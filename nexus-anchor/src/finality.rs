//! Finality Gadget for Anchor Layer
//!
//! Provides finality guarantees for blocks, ensuring they cannot be reverted.

use nexus_core::{Block, BlockHeight, Hash256, NexusError, Timestamp, Address};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

/// Justification for finality (proof that 2/3+ validators agreed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityJustification {
    /// Target block hash
    pub target_hash: Hash256,
    /// Target block height
    pub target_height: BlockHeight,
    /// Validator signatures
    pub signatures: Vec<FinalityVote>,
    /// Total voting power that signed
    pub total_weight: u64,
    /// Threshold required
    pub threshold: u64,
}

/// Individual finality vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityVote {
    /// Validator address
    pub validator: Address,
    /// Signature on (target_hash, target_height)
    pub signature: Vec<u8>,
    /// Validator's voting weight
    pub weight: u64,
}

/// Finality gadget inspired by GRANDPA
pub struct FinalityGadget {
    /// Last finalized block
    last_finalized: Option<FinalizedBlock>,
    /// Pending finality votes
    pending_votes: HashMap<Hash256, Vec<FinalityVote>>,
    /// Blocks pending finalization
    pending_blocks: HashMap<Hash256, Block>,
    /// Finalization threshold (2/3 of total voting power)
    threshold_ratio: f64,
    /// Minimum blocks before finalization
    min_blocks_to_finality: u64,
}

impl FinalityGadget {
    /// Create a new finality gadget
    pub fn new() -> Self {
        Self {
            last_finalized: None,
            pending_votes: HashMap::new(),
            pending_blocks: HashMap::new(),
            threshold_ratio: 0.667, // 2/3
            min_blocks_to_finality: 2,
        }
    }

    /// Get last finalized block
    pub fn last_finalized(&self) -> Option<&FinalizedBlock> {
        self.last_finalized.as_ref()
    }

    /// Get last finalized height
    pub fn last_finalized_height(&self) -> BlockHeight {
        self.last_finalized
            .as_ref()
            .map(|b| b.height())
            .unwrap_or(BlockHeight::GENESIS)
    }

    /// Add a block to pending finalization
    pub fn add_block(&mut self, block: Block) {
        let hash = block.hash();
        self.pending_blocks.insert(hash, block);
        self.pending_votes.entry(hash).or_default();
    }

    /// Add a finality vote
    pub fn add_vote(&mut self, vote: FinalityVote, block_hash: Hash256) -> Result<bool, NexusError> {
        // Check if block exists
        if !self.pending_blocks.contains_key(&block_hash) {
            return Err(NexusError::BlockNotFound(block_hash));
        }

        // Add vote
        let votes = self.pending_votes.entry(block_hash).or_default();

        // Check for duplicate
        if votes.iter().any(|v| v.validator == vote.validator) {
            return Ok(false); // Already voted
        }

        votes.push(vote);

        Ok(true)
    }

    /// Check if a block has enough votes for finalization
    pub fn check_finalization(
        &self,
        block_hash: &Hash256,
        total_voting_power: u64,
    ) -> Option<FinalityJustification> {
        let votes = self.pending_votes.get(block_hash)?;
        let block = self.pending_blocks.get(block_hash)?;

        let total_weight: u64 = votes.iter().map(|v| v.weight).sum();
        let threshold = (total_voting_power as f64 * self.threshold_ratio) as u64;

        if total_weight >= threshold {
            Some(FinalityJustification {
                target_hash: *block_hash,
                target_height: block.height(),
                signatures: votes.clone(),
                total_weight,
                threshold,
            })
        } else {
            None
        }
    }

    /// Try to finalize a block
    pub fn try_finalize(
        &mut self,
        block_hash: Hash256,
        total_voting_power: u64,
    ) -> Result<Option<FinalizedBlock>, NexusError> {
        // Check if already finalized
        if let Some(ref last) = self.last_finalized {
            let block = self.pending_blocks.get(&block_hash);
            if let Some(b) = block {
                if b.height().0 <= last.height().0 {
                    return Ok(None); // Already past this height
                }
            }
        }

        // Check for justification
        if let Some(justification) = self.check_finalization(&block_hash, total_voting_power) {
            let block = self
                .pending_blocks
                .remove(&block_hash)
                .ok_or(NexusError::BlockNotFound(block_hash))?;

            let finalized = FinalizedBlock {
                block: block.clone(),
                finalized_at: block.height(),
                finalized_time: Timestamp::now(),
                justification,
            };

            // Clean up older pending blocks
            self.cleanup_finalized(block.height());

            self.last_finalized = Some(finalized.clone());
            self.pending_votes.remove(&block_hash);

            Ok(Some(finalized))
        } else {
            Ok(None)
        }
    }

    /// Clean up blocks that are now finalized
    fn cleanup_finalized(&mut self, finalized_height: BlockHeight) {
        let to_remove: Vec<Hash256> = self
            .pending_blocks
            .iter()
            .filter(|(_, b)| b.height().0 <= finalized_height.0)
            .map(|(h, _)| *h)
            .collect();

        for hash in to_remove {
            self.pending_blocks.remove(&hash);
            self.pending_votes.remove(&hash);
        }
    }

    /// Check if a block is finalized
    pub fn is_finalized(&self, block_hash: &Hash256) -> bool {
        self.last_finalized
            .as_ref()
            .map(|f| f.hash() == *block_hash)
            .unwrap_or(false)
    }

    /// Check if a height is finalized
    pub fn is_height_finalized(&self, height: BlockHeight) -> bool {
        self.last_finalized
            .as_ref()
            .map(|f| f.height().0 >= height.0)
            .unwrap_or(false)
    }

    /// Get pending block count
    pub fn pending_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Get vote count for a block
    pub fn vote_count(&self, block_hash: &Hash256) -> usize {
        self.pending_votes
            .get(block_hash)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

impl Default for FinalityGadget {
    fn default() -> Self {
        Self::new()
    }
}

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
        let mut gadget = FinalityGadget::new();
        let block = Block::genesis(Layer::Anchor);
        let block_hash = block.hash();

        gadget.add_block(block);

        // Add enough votes
        for i in 0..10 {
            let vote = FinalityVote {
                validator: Address::new([i as u8; 32]),
                signature: vec![],
                weight: 10,
            };
            gadget.add_vote(vote, block_hash).unwrap();
        }

        // Total power 100, threshold 67, we have 100
        let result = gadget.try_finalize(block_hash, 100).unwrap();
        assert!(result.is_some());
        assert!(gadget.is_finalized(&block_hash));
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
