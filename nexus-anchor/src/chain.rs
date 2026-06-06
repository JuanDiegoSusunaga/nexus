//! Anchor Chain - Complete L1 Implementation
//!
//! Integrates consensus, validators, DA, and finality into a cohesive chain.

use crate::{
    consensus::{ConsensusConfig, ConsensusEngine, ProofOfStake},
    data_availability::DataAvailabilityLayer,
    finality::{FinalityGadget, FinalizedBlock},
    validator::{ValidatorRegistry, ValidatorSet},
};
use nexus_core::{
    Block, BlockHeight, Hash256, Layer, NexusError, SignedTransaction,
    StateRoot, InMemoryState, AccountState, Address, Amount,
};
use nexus_crypto::{DilithiumKeypair, Signer, verify_signed_transaction};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Anchor Chain configuration
#[derive(Debug, Clone)]
pub struct AnchorChainConfig {
    /// Consensus configuration
    pub consensus: ConsensusConfig,
    /// Minimum validator stake
    pub min_stake: Amount,
    /// Block reward
    pub block_reward: Amount,
    /// Transaction fee percentage
    pub fee_percentage: u8,
}

impl Default for AnchorChainConfig {
    fn default() -> Self {
        Self {
            consensus: ConsensusConfig::default(),
            min_stake: Amount::from_units(32),
            block_reward: Amount::from_units(2),
            fee_percentage: 1,
        }
    }
}

/// The Anchor Chain (L1)
pub struct AnchorChain {
    /// Configuration
    config: AnchorChainConfig,
    /// Consensus engine
    consensus: Arc<ProofOfStake>,
    /// Validator registry
    validators: Arc<RwLock<ValidatorRegistry>>,
    /// Data availability layer
    da_layer: Arc<RwLock<DataAvailabilityLayer>>,
    /// Finality gadget
    finality: Arc<RwLock<FinalityGadget>>,
    /// Block storage (hash -> block)
    blocks: Arc<RwLock<HashMap<Hash256, Block>>>,
    /// Block by height
    blocks_by_height: Arc<RwLock<HashMap<BlockHeight, Hash256>>>,
    /// Current state
    state: Arc<RwLock<InMemoryState>>,
    /// Genesis block
    genesis: Block,
    /// L2 batch roots stored on L1
    l2_batches: Arc<RwLock<Vec<L2BatchRecord>>>,
}

/// Record of an L2 batch stored on L1
#[derive(Debug, Clone)]
pub struct L2BatchRecord {
    /// Batch index
    pub index: u64,
    /// State root before
    pub pre_state_root: StateRoot,
    /// State root after
    pub post_state_root: StateRoot,
    /// Batch data hash
    pub data_hash: Hash256,
    /// L1 block height where stored
    pub l1_height: BlockHeight,
    /// Timestamp
    pub timestamp: nexus_core::Timestamp,
}

impl AnchorChain {
    /// Create a new Anchor Chain
    pub fn new(config: AnchorChainConfig, keypair: DilithiumKeypair) -> Self {
        let validator_set = ValidatorSet::new();
        let consensus = Arc::new(ProofOfStake::new(
            config.consensus.clone(),
            validator_set.clone(),
            keypair,
        ));

        let genesis = Block::genesis(Layer::Anchor);
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis.clone());

        let mut blocks_by_height = HashMap::new();
        blocks_by_height.insert(BlockHeight::GENESIS, genesis_hash);

        Self {
            config: config.clone(),
            consensus,
            validators: Arc::new(RwLock::new(ValidatorRegistry::new(config.min_stake))),
            da_layer: Arc::new(RwLock::new(DataAvailabilityLayer::new())),
            finality: Arc::new(RwLock::new(FinalityGadget::new())),
            blocks: Arc::new(RwLock::new(blocks)),
            blocks_by_height: Arc::new(RwLock::new(blocks_by_height)),
            state: Arc::new(RwLock::new(InMemoryState::new())),
            genesis,
            l2_batches: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get genesis block
    pub fn genesis(&self) -> &Block {
        &self.genesis
    }

    /// Get current height
    pub fn height(&self) -> BlockHeight {
        self.consensus.current_height()
    }

    /// Get block by hash
    pub fn get_block(&self, hash: &Hash256) -> Option<Block> {
        self.blocks.read().get(hash).cloned()
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        let hash = self.blocks_by_height.read().get(&height).cloned()?;
        self.get_block(&hash)
    }

    /// Get latest block
    pub fn latest_block(&self) -> Option<Block> {
        let height = self.height();
        self.get_block_by_height(height)
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Option<AccountState> {
        self.state.read().get_account(address).cloned()
    }

    /// Process a new block
    pub async fn process_block(&self, block: Block) -> Result<(), NexusError> {
        // Validate block
        self.validate_block(&block).await?;

        // Execute transactions
        self.execute_block(&block)?;

        // Store block
        let hash = block.hash();
        let height = block.height();

        self.blocks.write().insert(hash, block.clone());
        self.blocks_by_height.write().insert(height, hash);

        // Add to finality gadget
        self.finality.write().add_block(block);

        Ok(())
    }

    /// Validate a block
    async fn validate_block(&self, block: &Block) -> Result<(), NexusError> {
        // Structure validation
        block.validate_structure()?;

        // Verify it builds on current chain
        let expected_height = self.height().next();
        if block.height() != expected_height {
            return Err(NexusError::InvalidBlock(format!(
                "Expected height {}, got {}",
                expected_height.0, block.height().0
            )));
        }

        // Verify parent
        let expected_parent = self
            .blocks_by_height
            .read()
            .get(&self.height())
            .cloned()
            .unwrap_or(Hash256::ZERO);

        if block.parent_hash() != expected_parent {
            return Err(NexusError::InvalidParentBlock {
                expected: expected_parent,
                got: block.parent_hash(),
            });
        }

        // Validate all transactions
        for tx in &block.body.transactions {
            verify_signed_transaction(tx)?;
        }

        Ok(())
    }

    /// Execute block transactions
    fn execute_block(&self, block: &Block) -> Result<(), NexusError> {
        let mut state = self.state.write();

        for tx in &block.body.transactions {
            self.execute_transaction(&mut state, tx)?;
        }

        // Reward block proposer
        let proposer = state.get_or_create_account(&block.header.proposer);
        proposer.credit(self.config.block_reward)?;

        Ok(())
    }

    /// Execute a single transaction
    fn execute_transaction(
        &self,
        state: &mut InMemoryState,
        tx: &SignedTransaction,
    ) -> Result<(), NexusError> {
        use nexus_core::TransactionType;

        // Verify nonce
        let sender_state = state.get_or_create_account(&tx.sender);
        if tx.transaction.nonce.0 != sender_state.nonce.0 {
            return Err(NexusError::InvalidNonce {
                expected: sender_state.nonce.0,
                got: tx.transaction.nonce.0,
            });
        }

        // Check balance for max cost
        let max_cost = tx.transaction.max_cost();
        if sender_state.balance.0 < max_cost.0 {
            return Err(NexusError::InsufficientBalance {
                required: max_cost.0,
                available: sender_state.balance.0,
            });
        }

        // Execute based on type
        match &tx.transaction.tx_type {
            TransactionType::Transfer { to, amount } => {
                state.transfer(&tx.sender, to, *amount)?;
            }
            TransactionType::ValidatorRegister { public_key, stake } => {
                // Deduct stake from sender
                let sender = state.get_or_create_account(&tx.sender);
                sender.debit(*stake)?;

                // Register validator
                self.validators.write().register(
                    tx.sender,
                    public_key.clone(),
                    *stake,
                )?;
            }
            TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } => {
                // Store L2 batch
                let record = L2BatchRecord {
                    index: self.l2_batches.read().len() as u64,
                    pre_state_root: StateRoot::EMPTY, // Would come from batch
                    post_state_root: StateRoot::new(*batch_root),
                    data_hash: Hash256::hash(compressed_data),
                    l1_height: self.height(),
                    timestamp: nexus_core::Timestamp::now(),
                };
                self.l2_batches.write().push(record);

                // Store in DA layer
                self.da_layer.write().submit_data(
                    self.height(),
                    compressed_data.clone(),
                )?;
            }
            _ => {
                // Other transaction types not yet implemented
            }
        }

        // Increment nonce
        let sender = state.get_or_create_account(&tx.sender);
        sender.increment_nonce();

        Ok(())
    }

    /// Submit L2 batch data
    pub fn submit_l2_batch(
        &self,
        batch_root: StateRoot,
        data: Vec<u8>,
    ) -> Result<Hash256, NexusError> {
        let commitment = self.da_layer.write().submit_data(self.height(), data)?;

        let record = L2BatchRecord {
            index: self.l2_batches.read().len() as u64,
            pre_state_root: StateRoot::EMPTY,
            post_state_root: batch_root,
            data_hash: commitment.commitment,
            l1_height: self.height(),
            timestamp: nexus_core::Timestamp::now(),
        };

        self.l2_batches.write().push(record);

        Ok(commitment.commitment)
    }

    /// Get L2 batch by index
    pub fn get_l2_batch(&self, index: u64) -> Option<L2BatchRecord> {
        self.l2_batches.read().get(index as usize).cloned()
    }

    /// Get finalized height
    pub fn finalized_height(&self) -> BlockHeight {
        self.finality.read().last_finalized_height()
    }

    /// Check if block is finalized
    pub fn is_finalized(&self, hash: &Hash256) -> bool {
        self.finality.read().is_finalized(hash)
    }

    /// Get validator set
    pub fn validator_set(&self) -> ValidatorSet {
        self.validators.read().validator_set().clone()
    }

    /// Get state root
    pub fn state_root(&self) -> StateRoot {
        self.state.read().compute_root()
    }

    /// Get statistics
    pub fn stats(&self) -> ChainStats {
        ChainStats {
            height: self.height(),
            finalized_height: self.finalized_height(),
            block_count: self.blocks.read().len(),
            account_count: self.state.read().account_count(),
            validator_count: self.validators.read().validator_set().active_count(),
            l2_batch_count: self.l2_batches.read().len(),
        }
    }
}

/// Chain statistics
#[derive(Debug, Clone)]
pub struct ChainStats {
    pub height: BlockHeight,
    pub finalized_height: BlockHeight,
    pub block_count: usize,
    pub account_count: usize,
    pub validator_count: usize,
    pub l2_batch_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::SignatureScheme;

    #[test]
    fn test_chain_creation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = AnchorChain::new(AnchorChainConfig::default(), keypair);

        assert_eq!(chain.genesis().height(), BlockHeight::GENESIS);
        assert!(chain.get_block(&chain.genesis().hash()).is_some());
    }

    #[test]
    fn test_chain_stats() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = AnchorChain::new(AnchorChainConfig::default(), keypair);

        let stats = chain.stats();
        assert_eq!(stats.block_count, 1); // Genesis
        assert_eq!(stats.height, BlockHeight::GENESIS);
    }

    #[test]
    fn test_l2_batch_submission() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = AnchorChain::new(AnchorChainConfig::default(), keypair);

        let batch_data = vec![1u8; 1024];
        let result = chain.submit_l2_batch(StateRoot::EMPTY, batch_data);

        assert!(result.is_ok());
        assert_eq!(chain.stats().l2_batch_count, 1);
    }
}
