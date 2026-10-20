//! Authenticated, serialized reference consensus state machine.
//! Quorum is exact stake > 2/3 (Nexus.Modelos.Quorum); this is not a proof
//! of full BFT safety/liveness, locking across rounds, or network integration.

use crate::validator::ValidatorSet;
use async_trait::async_trait;
use nexus_core::{Address, Amount, Block, BlockBody, BlockHeader, BlockHeight,
    Hash256, Layer, MerkleTree, NexusError, SignedTransaction};
use nexus_core::block::ValidatorSignature;
use nexus_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Target block time in milliseconds
    pub block_time_ms: u64,
    /// Minimum stake to become a validator
    pub min_stake: Amount,
    /// Number of validators to select for each round
    pub committee_size: usize,
    /// Timeout for proposal phase (ms)
    pub proposal_timeout_ms: u64,
    /// Timeout for prevote phase (ms)
    pub prevote_timeout_ms: u64,
    /// Timeout for precommit phase (ms)
    pub precommit_timeout_ms: u64,
    /// Compatibility value (0.667 or 2/3); runtime uses exact stake > 2/3.
    pub bft_threshold: f64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 12_000, // 12 seconds
            min_stake: Amount::from_units(32), // 32 tokens minimum
            committee_size: 21,
            proposal_timeout_ms: 3_000,
            prevote_timeout_ms: 2_000,
            precommit_timeout_ms: 2_000,
            bft_threshold: 0.667, // 2/3
        }
    }
}

/// Consensus round state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundState {
    /// Waiting for proposal
    Proposal,
    /// Collecting prevotes
    Prevote,
    /// Collecting precommits
    Precommit,
    /// Round completed
    Commit,
}

/// Consensus message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Block proposal
    Proposal {
        height: BlockHeight,
        round: u32,
        block: Block,
        proposer: Address,
    },
    /// Prevote for a block
    Prevote {
        height: BlockHeight,
        round: u32,
        block_hash: Option<Hash256>, // None = nil vote
        validator: Address,
        signature: Vec<u8>,
    },
    /// Precommit for a block
    Precommit {
        height: BlockHeight,
        round: u32,
        block_hash: Option<Hash256>,
        validator: Address,
        signature: Vec<u8>,
    },
}

/// Consensus engine trait
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Start the consensus engine
    async fn start(&self) -> Result<(), NexusError>;

    /// Stop the consensus engine
    async fn stop(&self) -> Result<(), NexusError>;

    /// Propose a new block
    async fn propose_block(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block, NexusError>;

    /// Validate a proposed block
    async fn validate_block(&self, block: &Block) -> Result<bool, NexusError>;

    /// Process a consensus message
    async fn process_message(&self, message: ConsensusMessage) -> Result<(), NexusError>;

    /// Get current height
    fn current_height(&self) -> BlockHeight;

    /// Get current round
    fn current_round(&self) -> u32;

    /// Check if this node is the current proposer
    fn is_proposer(&self) -> bool;
}


/// Domain separation prevents replaying a prevote as a precommit.
#[derive(Clone, Copy)]
pub enum VotePhase { Prevote = 1, Precommit = 2 }

pub fn vote_signing_bytes(phase: VotePhase, height: BlockHeight, round: u32,
    hash: Option<Hash256>) -> Result<Vec<u8>, NexusError> {
    Ok(bincode::serialize(&(b"NEXUS-CONSENSUS-VOTE-v1".as_slice(),
        phase as u8, Layer::Anchor, height, round, hash))?)
}

fn proposal_signing_bytes(block: &Block) -> Vec<u8> {
    [b"NEXUS-CONSENSUS-PROPOSAL-v1".as_slice(), block.hash().as_bytes()].concat()
}

/// Integer form of weight > 2/3, avoiding multiplication overflow and floats.
pub(crate) fn strict_quorum_threshold(total: u128) -> Option<u128> {
    if total == 0 { None } else { Some(total - (total - 1) / 3) }
}

pub(crate) fn verify_validator_signature(set: &ValidatorSet, address: Address,
    message: &[u8], signature: &[u8]) -> Result<(), NexusError> {
    use nexus_core::SignatureScheme;
    let validators = set.active_validators();
    let validator = validators.into_iter().find(|v| v.address == address && v.stake.0 > 0)
        .ok_or(NexusError::NotValidator)?;
    if Address::from_public_key(&validator.public_key) != address {
        return Err(NexusError::InvalidValidatorSignature);
    }
    let scheme = match validator.public_key.len() {
        1312 => SignatureScheme::Dilithium2,
        1952 => SignatureScheme::Dilithium3,
        2592 => SignatureScheme::Dilithium5,
        _ => return Err(NexusError::InvalidValidatorSignature),
    };
    let key = DilithiumPublicKey::from_bytes(validator.public_key.clone(), scheme)?;
    let sig = DilithiumSignature::from_bytes(signature.to_vec(), scheme)?;
    if !key.verify(message, &sig)? { return Err(NexusError::InvalidValidatorSignature); }
    Ok(())
}

struct ConsensusState {
    /// Last committed height; a proposal extends it by one.
    height: BlockHeight,
    round: u32,
    phase: RoundState,
    prevotes: HashMap<Address, Option<Hash256>>,
    precommits: HashMap<Address, Option<Hash256>>,
    proposal: Option<Block>,
    last_finalized: Option<Block>,
}

pub struct ProofOfStake {
    config: ConsensusConfig,
    validator_set: ValidatorSet,
    keypair: DilithiumKeypair,
    state: Mutex<ConsensusState>,
}

impl ProofOfStake {
    pub fn new(config: ConsensusConfig, validator_set: ValidatorSet, keypair: DilithiumKeypair) -> Self {
        Self { config, validator_set, keypair, state: Mutex::new(ConsensusState {
            height: BlockHeight::GENESIS, round: 0, phase: RoundState::Proposal,
            prevotes: HashMap::new(), precommits: HashMap::new(), proposal: None, last_finalized: None }) }
    }

    fn check_config(&self) -> Result<(), NexusError> {
        // The legacy float is not used for arithmetic and cannot weaken/change
        // the strict two-thirds policy specified by the thesis and Lean model.
        if self.config.bft_threshold != 0.667 && self.config.bft_threshold != 2.0 / 3.0 {
            return Err(NexusError::ConfigError("Consensus requires exact stake > 2/3".into()));
        }
        Ok(())
    }

    pub fn get_proposer(&self, height: BlockHeight, round: u32) -> Option<Address> {
        let validators = self.validator_set.active_validators();
        if validators.is_empty() { return None; }
        let index = ((height.0 as u128 + round as u128) % validators.len() as u128) as usize;
        Some(validators[index].address)
    }

    fn has_quorum(&self, votes: &HashMap<Address, Option<Hash256>>, hash: Hash256) -> Result<bool, NexusError> {
        let mut total = 0u128;
        let mut signed = 0u128;
        for validator in self.validator_set.active_validators() {
            total = total.checked_add(validator.stake.0)
                .ok_or_else(|| NexusError::ConfigError("Active stake overflow".into()))?;
            if votes.get(&validator.address) == Some(&Some(hash)) {
                signed = signed.checked_add(validator.stake.0)
                    .ok_or_else(|| NexusError::ConfigError("Signed stake overflow".into()))?;
            }
        }
        Ok(strict_quorum_threshold(total).is_some_and(|threshold| signed >= threshold))
    }

    fn validate_proposal(&self, block: &Block, state: &ConsensusState) -> Result<bool, NexusError> {
        self.check_config()?;
        block.validate_structure()?;
        let next = state.height.0.checked_add(1)
            .ok_or_else(|| NexusError::ConsensusFailure("Height exhausted".into()))?;
        let parent = state.last_finalized.as_ref().map(Block::hash)
            .unwrap_or_else(|| Block::genesis(Layer::Anchor).hash());
        if block.height().0 != next || block.parent_hash() != parent || block.header.layer != Layer::Anchor
            || self.get_proposer(block.height(), state.round) != Some(block.header.proposer)
            || block.header.transactions_root != MerkleTree::from_leaves(block.transaction_hashes()).root() {
            return Ok(false);
        }
        let Some(signature) = block.body.signatures.iter().find(|sig| sig.validator == block.header.proposer)
            else { return Ok(false); };
        verify_validator_signature(&self.validator_set, block.header.proposer,
            &proposal_signing_bytes(block), &signature.signature.bytes)?;
        for tx in &block.body.transactions {
            if !nexus_crypto::verify_signed_transaction(tx)? { return Ok(false); }
        }
        Ok(true)
    }

    fn record_vote(votes: &mut HashMap<Address, Option<Hash256>>, validator: Address,
        hash: Option<Hash256>) -> Result<(), NexusError> {
        if let Some(previous) = votes.get(&validator) {
            if *previous != hash {
                return Err(NexusError::ConsensusFailure("Conflicting vote in the same round".into()));
            }
        } else { votes.insert(validator, hash); }
        Ok(())
    }
}

#[async_trait]
impl ConsensusEngine for ProofOfStake {
    async fn start(&self) -> Result<(), NexusError> { self.check_config() }
    async fn stop(&self) -> Result<(), NexusError> { Ok(()) }

    async fn propose_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block, NexusError> {
        self.check_config()?;
        let mut state = self.state.lock();
        if state.proposal.is_some() {
            return Err(NexusError::ConsensusFailure("Proposal already present".into()));
        }
        let height = BlockHeight(state.height.0.checked_add(1)
            .ok_or_else(|| NexusError::ConsensusFailure("Height exhausted".into()))?);
        if self.get_proposer(height, state.round) != Some(self.keypair.address()) {
            return Err(NexusError::NotValidator);
        }
        let parent = state.last_finalized.as_ref().map(Block::hash)
            .unwrap_or_else(|| Block::genesis(Layer::Anchor).hash());
        let mut header = BlockHeader::new(height, parent, self.keypair.address(), Layer::Anchor);
        header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
        let mut block = Block::new(header, BlockBody::new(transactions));
        let signature = self.keypair.sign(&proposal_signing_bytes(&block))?.to_pq_signature();
        block.body.signatures.push(ValidatorSignature { validator: self.keypair.address(), signature });
        if !self.validate_proposal(&block, &state)? {
            return Err(NexusError::InvalidBlock("Invalid proposal".into()));
        }
        state.proposal = Some(block.clone());
        state.phase = RoundState::Prevote;
        Ok(block)
    }

    async fn validate_block(&self, block: &Block) -> Result<bool, NexusError> {
        self.validate_proposal(block, &self.state.lock())
    }

    async fn process_message(&self, message: ConsensusMessage) -> Result<(), NexusError> {
        self.check_config()?;
        let mut state = self.state.lock();
        let is_prevote = matches!(&message, ConsensusMessage::Prevote { .. });
        match message {
            ConsensusMessage::Proposal { height, round, block, proposer } => {
                if height != block.height() || proposer != block.header.proposer || round != state.round
                    || !self.validate_proposal(&block, &state)? {
                    return Err(NexusError::InvalidBlock("Invalid proposal context".into()));
                }
                if state.proposal.as_ref().is_some_and(|p| p.hash() != block.hash()) {
                    return Err(NexusError::ConsensusFailure("Conflicting proposal".into()));
                }
                if state.proposal.is_none() {
                    state.proposal = Some(block);
                    state.phase = RoundState::Prevote;
                }
            }
            ConsensusMessage::Prevote { height, round, block_hash, validator, signature }
            | ConsensusMessage::Precommit { height, round, block_hash, validator, signature } => {
                let phase = if is_prevote {
                    VotePhase::Prevote
                } else { VotePhase::Precommit };
                let proposal = state.proposal.clone()
                    .ok_or_else(|| NexusError::ConsensusFailure("No proposal".into()))?;
                if height != proposal.height() || round != state.round
                    || block_hash.is_some_and(|hash| hash != proposal.hash()) {
                    return Err(NexusError::ConsensusFailure("Unexpected vote context".into()));
                }
                verify_validator_signature(&self.validator_set, validator,
                    &vote_signing_bytes(phase, height, round, block_hash)?, &signature)?;
                match phase {
                    VotePhase::Prevote => {
                        Self::record_vote(&mut state.prevotes, validator, block_hash)?;
                        if self.has_quorum(&state.prevotes, proposal.hash())? {
                            state.phase = RoundState::Precommit;
                        }
                    }
                    VotePhase::Precommit => {
                        if state.phase != RoundState::Precommit {
                            return Err(NexusError::ConsensusFailure("Prevote quorum required".into()));
                        }
                        Self::record_vote(&mut state.precommits, validator, block_hash)?;
                        if self.has_quorum(&state.precommits, proposal.hash())? {
                            state.height = proposal.height();
                            state.last_finalized = Some(proposal);
                            state.round = 0;
                            state.phase = RoundState::Proposal;
                            state.proposal = None;
                            state.prevotes.clear();
                            state.precommits.clear();
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn current_height(&self) -> BlockHeight { self.state.lock().height }
    fn current_round(&self) -> u32 { self.state.lock().round }
    fn is_proposer(&self) -> bool {
        let state = self.state.lock();
        state.height.0.checked_add(1).is_some_and(|height|
            self.get_proposer(BlockHeight(height), state.round) == Some(self.keypair.address()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::SignatureScheme;

    #[test]
    fn test_consensus_config_default() {
        let config = ConsensusConfig::default();
        assert_eq!(config.block_time_ms, 12_000);
        assert!(config.bft_threshold > 0.66);
    }

    #[tokio::test]
    async fn test_pos_creation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let validator_set = ValidatorSet::new();
        let pos = ProofOfStake::new(ConsensusConfig::default(), validator_set, keypair);

        assert_eq!(pos.current_height(), BlockHeight::GENESIS);
        assert_eq!(pos.current_round(), 0);
    }
}
