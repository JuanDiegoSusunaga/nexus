//! Consensus Engine for Anchor Layer
//!
//! Implements Proof-of-Stake consensus with post-quantum signatures.
//! Based on Tendermint-style BFT consensus adapted for PQC.

use crate::validator::{Validator, ValidatorSet};
use async_trait::async_trait;
use nexus_core::{
    Address, Amount, Block, BlockHeader, BlockHeight, Hash256, Layer,
    NexusError, SignedTransaction, Timestamp,
};
use nexus_crypto::{DilithiumKeypair, Signer};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

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
    /// Threshold for Byzantine fault tolerance (2/3 + 1)
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

/// Proof-of-Stake consensus implementation
pub struct ProofOfStake {
    /// Configuration
    config: ConsensusConfig,
    /// Validator set
    validator_set: Arc<RwLock<ValidatorSet>>,
    /// Current height
    height: Arc<RwLock<BlockHeight>>,
    /// Current round
    round: Arc<RwLock<u32>>,
    /// Current state
    state: Arc<RwLock<RoundState>>,
    /// This node's keypair
    keypair: Arc<DilithiumKeypair>,
    /// Collected prevotes
    prevotes: Arc<RwLock<HashMap<(BlockHeight, u32), Vec<ConsensusMessage>>>>,
    /// Collected precommits
    precommits: Arc<RwLock<HashMap<(BlockHeight, u32), Vec<ConsensusMessage>>>>,
    /// Current proposal
    current_proposal: Arc<RwLock<Option<Block>>>,
    /// Last finalized block
    last_finalized: Arc<RwLock<Option<Block>>>,
}

impl ProofOfStake {
    /// Create a new PoS consensus engine
    pub fn new(
        config: ConsensusConfig,
        validator_set: ValidatorSet,
        keypair: DilithiumKeypair,
    ) -> Self {
        Self {
            config,
            validator_set: Arc::new(RwLock::new(validator_set)),
            height: Arc::new(RwLock::new(BlockHeight::GENESIS)),
            round: Arc::new(RwLock::new(0)),
            state: Arc::new(RwLock::new(RoundState::Proposal)),
            keypair: Arc::new(keypair),
            prevotes: Arc::new(RwLock::new(HashMap::new())),
            precommits: Arc::new(RwLock::new(HashMap::new())),
            current_proposal: Arc::new(RwLock::new(None)),
            last_finalized: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the proposer for a given height and round
    pub fn get_proposer(&self, height: BlockHeight, round: u32) -> Option<Address> {
        let validator_set = self.validator_set.read();
        let validators = validator_set.active_validators();

        if validators.is_empty() {
            return None;
        }

        // Simple round-robin selection weighted by stake
        let index = ((height.0 as usize) + (round as usize)) % validators.len();
        Some(validators[index].address)
    }

    /// Check if we have enough prevotes
    fn has_prevote_quorum(&self, height: BlockHeight, round: u32, block_hash: &Hash256) -> bool {
        let prevotes = self.prevotes.read();
        let key = (height, round);

        let count = prevotes
            .get(&key)
            .map(|votes| {
                votes
                    .iter()
                    .filter(|v| match v {
                        ConsensusMessage::Prevote { block_hash: h, .. } => {
                            h.as_ref() == Some(block_hash)
                        }
                        _ => false,
                    })
                    .count()
            })
            .unwrap_or(0);

        let total = self.validator_set.read().active_count();
        (count as f64 / total as f64) >= self.config.bft_threshold
    }

    /// Check if we have enough precommits
    fn has_precommit_quorum(&self, height: BlockHeight, round: u32, block_hash: &Hash256) -> bool {
        let precommits = self.precommits.read();
        let key = (height, round);

        let count = precommits
            .get(&key)
            .map(|votes| {
                votes
                    .iter()
                    .filter(|v| match v {
                        ConsensusMessage::Precommit { block_hash: h, .. } => {
                            h.as_ref() == Some(block_hash)
                        }
                        _ => false,
                    })
                    .count()
            })
            .unwrap_or(0);

        let total = self.validator_set.read().active_count();
        (count as f64 / total as f64) >= self.config.bft_threshold
    }

    /// Create a prevote message
    fn create_prevote(&self, block_hash: Option<Hash256>) -> Result<ConsensusMessage, NexusError> {
        let height = *self.height.read();
        let round = *self.round.read();

        let msg_bytes = bincode::serialize(&(height, round, &block_hash))
            .map_err(|e| NexusError::SerializationError(e.to_string()))?;

        let signature = self.keypair.sign(&msg_bytes)?;

        Ok(ConsensusMessage::Prevote {
            height,
            round,
            block_hash,
            validator: self.keypair.address(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Create a precommit message
    fn create_precommit(&self, block_hash: Option<Hash256>) -> Result<ConsensusMessage, NexusError> {
        let height = *self.height.read();
        let round = *self.round.read();

        let msg_bytes = bincode::serialize(&(height, round, &block_hash))
            .map_err(|e| NexusError::SerializationError(e.to_string()))?;

        let signature = self.keypair.sign(&msg_bytes)?;

        Ok(ConsensusMessage::Precommit {
            height,
            round,
            block_hash,
            validator: self.keypair.address(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Advance to next height
    fn advance_height(&self) {
        let mut height = self.height.write();
        *height = height.next();
        *self.round.write() = 0;
        *self.state.write() = RoundState::Proposal;
        self.current_proposal.write().take();
    }

    /// Advance to next round
    fn advance_round(&self) {
        *self.round.write() += 1;
        *self.state.write() = RoundState::Proposal;
        self.current_proposal.write().take();
    }
}

#[async_trait]
impl ConsensusEngine for ProofOfStake {
    async fn start(&self) -> Result<(), NexusError> {
        tracing::info!("Starting PoS consensus engine");
        Ok(())
    }

    async fn stop(&self) -> Result<(), NexusError> {
        tracing::info!("Stopping PoS consensus engine");
        Ok(())
    }

    async fn propose_block(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block, NexusError> {
        let height = *self.height.read();
        let round = *self.round.read();

        // Verify we are the proposer
        let proposer = self
            .get_proposer(height, round)
            .ok_or(NexusError::ConsensusFailure("No validators".into()))?;

        if proposer != self.keypair.address() {
            return Err(NexusError::NotValidator);
        }

        // Get parent hash
        let parent_hash = self
            .last_finalized
            .read()
            .as_ref()
            .map(|b| b.hash())
            .unwrap_or(Hash256::ZERO);

        // Create block header
        let header = BlockHeader::new(height, parent_hash, self.keypair.address(), Layer::Anchor);

        // Create block body
        let body = nexus_core::BlockBody::new(transactions);

        let block = Block::new(header, body);

        // Store as current proposal
        *self.current_proposal.write() = Some(block.clone());
        *self.state.write() = RoundState::Prevote;

        Ok(block)
    }

    async fn validate_block(&self, block: &Block) -> Result<bool, NexusError> {
        // Basic structure validation
        block.validate_structure()?;

        // Verify proposer
        let expected_proposer = self
            .get_proposer(block.height(), 0)
            .ok_or(NexusError::ConsensusFailure("No validators".into()))?;

        if block.header.proposer != expected_proposer {
            return Ok(false);
        }

        // Verify parent hash
        let expected_parent = self
            .last_finalized
            .read()
            .as_ref()
            .map(|b| b.hash())
            .unwrap_or(Hash256::ZERO);

        if block.parent_hash() != expected_parent {
            return Ok(false);
        }

        // Verify height
        let expected_height = self.last_finalized
            .read()
            .as_ref()
            .map(|b| b.height().next())
            .unwrap_or(BlockHeight::GENESIS);

        if block.height() != expected_height {
            return Ok(false);
        }

        Ok(true)
    }

    async fn process_message(&self, message: ConsensusMessage) -> Result<(), NexusError> {
        match message {
            ConsensusMessage::Proposal { height, round, block, .. } => {
                // Verify block
                if self.validate_block(&block).await? {
                    *self.current_proposal.write() = Some(block.clone());
                    *self.state.write() = RoundState::Prevote;

                    // Send prevote
                    let _prevote = self.create_prevote(Some(block.hash()))?;
                    // In production: broadcast prevote
                }
            }
            ConsensusMessage::Prevote { height, round, block_hash, validator, signature } => {
                let key = (height, round);
                self.prevotes.write().entry(key).or_default().push(
                    ConsensusMessage::Prevote { height, round, block_hash, validator, signature }
                );

                // Check for quorum
                if let Some(hash) = block_hash {
                    if self.has_prevote_quorum(height, round, &hash) {
                        *self.state.write() = RoundState::Precommit;
                        let _precommit = self.create_precommit(Some(hash))?;
                        // In production: broadcast precommit
                    }
                }
            }
            ConsensusMessage::Precommit { height, round, block_hash, validator, signature } => {
                let key = (height, round);
                self.precommits.write().entry(key).or_default().push(
                    ConsensusMessage::Precommit { height, round, block_hash, validator, signature }
                );

                // Check for quorum
                if let Some(hash) = block_hash {
                    if self.has_precommit_quorum(height, round, &hash) {
                        // Commit block
                        if let Some(block) = self.current_proposal.read().clone() {
                            if block.hash() == hash {
                                *self.last_finalized.write() = Some(block);
                                self.advance_height();
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn current_height(&self) -> BlockHeight {
        *self.height.read()
    }

    fn current_round(&self) -> u32 {
        *self.round.read()
    }

    fn is_proposer(&self) -> bool {
        let height = *self.height.read();
        let round = *self.round.read();

        self.get_proposer(height, round)
            .map(|p| p == self.keypair.address())
            .unwrap_or(false)
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
