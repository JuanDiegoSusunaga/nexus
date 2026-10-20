//! Finality Gadget for Anchor Layer
//!
//! Provides finality guarantees for blocks, ensuring they cannot be reverted.

use nexus_core::{Block, BlockHeight, Hash256, NexusError, Timestamp, Address};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::validator::ValidatorSet;
use crate::consensus::{strict_quorum_threshold, verify_validator_signature};

/// A finalized block with finality proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedBlock {
    /// The block that was finalized
    pub block: Block,
    /// Finalization height (may differ from block height)
    pub finalized_at: BlockHeight,
    /// Finalization timestamp
    pub finalized_time: Timestamp,
    /// Justification (aggregated signatures)
    pub justification: FinalityJustification,
}

impl FinalizedBlock {
    /// Get block hash
    pub fn hash(&self) -> Hash256 {
        self.block.hash()
    }

    /// Get block height
    pub fn height(&self) -> BlockHeight {
        self.block.height()
    }
}

/// Local certificate with authenticated stake strictly greater than 2/3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityJustification {
    /// Target block hash
    pub target_hash: Hash256,
    /// Target block height
    pub target_height: BlockHeight,
    /// Validator signatures
    pub signatures: Vec<FinalityVote>,
    /// Total voting power that signed
    pub total_weight: u128,
    /// Threshold required
    pub threshold: u128,
}

/// Individual finality vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityVote {
    /// Validator address
    pub validator: Address,
    /// Signature on (target_hash, target_height)
    pub signature: Vec<u8>,
    /// Exact stake in smallest units; must match the trusted block snapshot.
    pub weight: u128,
}

/// Domain and target are authenticated; weights come from the local snapshot.
pub fn finality_signing_bytes(hash: Hash256, height: BlockHeight) -> Result<Vec<u8>, NexusError> {
    Ok(bincode::serialize(&(b"NEXUS-FINALITY-VOTE-v1".as_slice(), nexus_core::Layer::Anchor, hash, height))?)
}

/// Authenticated local certificates. Full BFT locking/liveness is outside this PoC.
#[derive(Serialize, Deserialize)]
pub struct FinalityGadget {
    last_finalized: Option<FinalizedBlock>,
    pending_votes: HashMap<Hash256, Vec<FinalityVote>>,
    pending_blocks: HashMap<Hash256, Block>,
    validators: ValidatorSet,
    snapshots: HashMap<Hash256, ValidatorSet>,
    ancestry: HashMap<Hash256, (BlockHeight, Hash256)>,
}

impl FinalityGadget {
    pub fn new() -> Self { Self::with_validator_set(ValidatorSet::new()) }
    pub fn with_validator_set(validators: ValidatorSet) -> Self {
        Self { last_finalized: None, pending_votes: HashMap::new(), pending_blocks: HashMap::new(),
            validators, snapshots: HashMap::new(), ancestry: HashMap::new() }
    }
    /// Trusted caller policy for subsequently added blocks; earlier snapshots stay fixed.
    pub fn set_validator_set(&mut self, validators: ValidatorSet) { self.validators = validators; }
    pub fn last_finalized(&self) -> Option<&FinalizedBlock> { self.last_finalized.as_ref() }
    pub fn last_finalized_height(&self) -> BlockHeight {
        self.last_finalized.as_ref().map(|b| b.height()).unwrap_or(BlockHeight::GENESIS)
    }
    pub fn add_block(&mut self, block: Block) {
        let hash = block.hash();
        if block.header.layer != nexus_core::Layer::Anchor || block.validate_structure().is_err()
            || block.header.transactions_root != nexus_core::MerkleTree::from_leaves(block.transaction_hashes()).root() {
            return;
        }
        self.ancestry.entry(hash).or_insert((block.height(), block.parent_hash()));
        // Re-adding a block cannot replace its authority snapshot or existing votes.
        self.snapshots.entry(hash).or_insert_with(|| self.validators.clone());
        self.pending_blocks.entry(hash).or_insert(block);
        self.pending_votes.entry(hash).or_default();
    }
    pub fn add_vote(&mut self, vote: FinalityVote, hash: Hash256) -> Result<bool, NexusError> {
        let block = self.pending_blocks.get(&hash).ok_or(NexusError::BlockNotFound(hash))?;
        let set = self.snapshots.get(&hash).ok_or(NexusError::NotValidator)?;
        verify_validator_signature(set, vote.validator,
            &finality_signing_bytes(hash, block.height())?, &vote.signature)?;
        let trusted = set.get_validator(&vote.validator).ok_or(NexusError::NotValidator)?.stake.0;
        if vote.weight != trusted { return Err(NexusError::InvalidValidatorSignature); }
        let votes = self.pending_votes.entry(hash).or_default();
        if votes.iter().any(|previous| previous.validator == vote.validator) { return Ok(false); }
        votes.push(vote);
        Ok(true)
    }
    fn descends_from_anchor(&self, hash: Hash256, height: BlockHeight) -> bool {
        let genesis = Block::genesis(nexus_core::Layer::Anchor);
        let target = self.last_finalized.as_ref().map(|b| (b.hash(), b.height()))
            .unwrap_or((genesis.hash(), BlockHeight::GENESIS));
        let (mut current, mut current_height) = (hash, height);
        while current_height > target.1 {
            let Some((stored_height, parent)) = self.ancestry.get(&current) else { return false; };
            if *stored_height != current_height { return false; }
            let parent_height = if *parent == genesis.hash() { BlockHeight::GENESIS }
                else if let Some((parent_height, _)) = self.ancestry.get(parent) { *parent_height }
                else { return false; };
            if parent_height.0.checked_add(1) != Some(current_height.0) { return false; }
            current = *parent;
            current_height = parent_height;
        }
        current == target.0 && current_height == target.1
    }
    pub fn check_finalization(&self, hash: &Hash256, claimed_total: u128) -> Option<FinalityJustification> {
        let votes = self.pending_votes.get(hash)?;
        let block = self.pending_blocks.get(hash)?;
        if !self.descends_from_anchor(*hash, block.height()) { return None; }
        let total = self.snapshots.get(hash)?.active_validators().iter()
            .try_fold(0u128, |sum, validator| sum.checked_add(validator.stake.0))?;
        if claimed_total != total { return None; }
        let threshold = strict_quorum_threshold(total)?;
        let total_weight = votes.iter().try_fold(0u128, |sum, vote| sum.checked_add(vote.weight))?;
        if total_weight < threshold { return None; }
        Some(FinalityJustification { target_hash: *hash, target_height: block.height(),
            signatures: votes.clone(), total_weight, threshold })
    }
    pub fn try_finalize(&mut self, hash: Hash256, total: u128) -> Result<Option<FinalizedBlock>, NexusError> {
        let Some(block) = self.pending_blocks.get(&hash) else { return Ok(None); };
        if self.last_finalized.as_ref().is_some_and(|last| block.height() <= last.height()) { return Ok(None); }
        let Some(justification) = self.check_finalization(&hash, total) else { return Ok(None); };
        let block = self.pending_blocks.remove(&hash).ok_or(NexusError::BlockNotFound(hash))?;
        let finalized = FinalizedBlock { finalized_at: block.height(), block,
            finalized_time: Timestamp::now(), justification };
        let height = finalized.height();
        let old: Vec<_> = self.pending_blocks.iter().filter(|(_, b)| b.height() <= height)
            .map(|(hash, _)| *hash).chain(std::iter::once(hash)).collect();
        for hash in old {
            self.pending_blocks.remove(&hash);
            self.pending_votes.remove(&hash);
            self.snapshots.remove(&hash);
        }
        self.last_finalized = Some(finalized.clone());
        Ok(Some(finalized))
    }
    pub fn is_finalized(&self, hash: &Hash256) -> bool {
        self.last_finalized.as_ref().is_some_and(|f| f.hash() == *hash)
    }
    pub fn is_height_finalized(&self, height: BlockHeight) -> bool {
        self.last_finalized.as_ref().is_some_and(|f| f.height() >= height)
    }
    pub fn pending_count(&self) -> usize { self.pending_blocks.len() }
    pub fn vote_count(&self, hash: &Hash256) -> usize { self.pending_votes.get(hash).map(Vec::len).unwrap_or(0) }
}
impl Default for FinalityGadget { fn default() -> Self { Self::new() } }

/// Fork choice rule for selecting the best chain
pub struct ForkChoice {
    /// Finalized block (anchor)
    finalized: Option<Hash256>,
    /// Best block by weight
    best_block: Option<Hash256>,
    /// Block weights (accumulated votes)
    weights: HashMap<Hash256, u64>,
    /// Parent links
    parents: HashMap<Hash256, Hash256>,
}

impl ForkChoice {
    pub fn new() -> Self {
        Self {
            finalized: None,
            best_block: None,
            weights: HashMap::new(),
            parents: HashMap::new(),
        }
    }

    /// Add a block to the fork choice
    pub fn add_block(&mut self, block_hash: Hash256, parent_hash: Hash256, weight: u64) {
        self.parents.insert(block_hash, parent_hash);

        // Accumulate weight from parent
        let parent_weight = self.weights.get(&parent_hash).copied().unwrap_or(0);
        let total_weight = parent_weight + weight;
        self.weights.insert(block_hash, total_weight);

        // Update best block
        let current_best_weight = self
            .best_block
            .and_then(|b| self.weights.get(&b))
            .copied()
            .unwrap_or(0);

        if total_weight > current_best_weight {
            self.best_block = Some(block_hash);
        }
    }

    /// Set finalized block
    pub fn set_finalized(&mut self, block_hash: Hash256) {
        self.finalized = Some(block_hash);

        // Prune blocks not descending from finalized
        // (simplified - full implementation would check ancestry)
    }

    /// Get best block
    pub fn best_block(&self) -> Option<Hash256> {
        self.best_block
    }

    /// Check if a block is ancestor of another
    pub fn is_ancestor(&self, ancestor: &Hash256, descendant: &Hash256) -> bool {
        let mut current = *descendant;

        while let Some(parent) = self.parents.get(&current) {
            if parent == ancestor {
                return true;
            }
            current = *parent;
        }

        false
    }
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::Layer;

    #[test]
    fn test_finality_gadget_creation() {
        let gadget = FinalityGadget::new();
        assert!(gadget.last_finalized().is_none());
        assert_eq!(gadget.pending_count(), 0);
    }

    #[test]
    fn test_add_block() {
        let mut gadget = FinalityGadget::new();
        let block = Block::genesis(Layer::Anchor);

        gadget.add_block(block.clone());
        assert_eq!(gadget.pending_count(), 1);
    }

    #[test]
    fn test_finalization() {
        use nexus_crypto::DilithiumKeypair;
        use nexus_core::{Amount, SignatureScheme};
        use crate::validator::Validator;
        let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let mut set = ValidatorSet::new();
        set.add_validator(Validator::new(signer.address(), signer.public_key().as_bytes().to_vec(), Amount(100))).unwrap();
        set.activate_validator(&signer.address()).unwrap();
        let mut gadget = FinalityGadget::with_validator_set(set);
        let block = Block::genesis(Layer::Anchor);
        let hash = block.hash();
        let signature = signer.sign(&finality_signing_bytes(hash, block.height()).unwrap()).unwrap();
        gadget.add_block(block);
        gadget.add_vote(FinalityVote { validator: signer.address(), signature: signature.as_bytes().to_vec(), weight: 100 }, hash).unwrap();
        let result = gadget.try_finalize(hash, 100).unwrap();
        assert!(result.is_some());
        assert!(gadget.is_finalized(&hash));
    }

    #[test]
    fn test_fork_choice() {
        let mut fc = ForkChoice::new();

        let genesis = Hash256::hash(b"genesis");
        let block_a = Hash256::hash(b"block_a");
        let block_b = Hash256::hash(b"block_b");

        fc.add_block(block_a, genesis, 10);
        fc.add_block(block_b, genesis, 15);

        // Block B should be best (higher weight)
        assert_eq!(fc.best_block(), Some(block_b));
    }
}
