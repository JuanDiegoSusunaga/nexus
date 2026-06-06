//! Active Chain - Complete L2 Implementation
//!
//! Integrates sequencer, execution, verifier, and batching.

use crate::{
    batch::{BatchBuilder, BatchSubmitter, L2Batch},
    execution::{ExecutionEngine, ExecutionResult},
    sequencer::{NexusSequencer, SequencerConfig},
    verifier::{NitroVerifier, VerificationMode, StateProof, ProofType},
};
use nexus_core::{
    Block, BlockHeader, BlockBody, BlockHeight, Hash256, Layer, NexusError,
    SignedTransaction, StateRoot, Timestamp, Address, InMemoryState,
};
use nexus_crypto::DilithiumKeypair;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Active Chain configuration
#[derive(Debug, Clone)]
pub struct ActiveChainConfig {
    /// Sequencer configuration
    pub sequencer: SequencerConfig,
    /// Verification mode
    pub verification_mode: VerificationMode,
    /// Block time (ms)
    pub block_time_ms: u64,
    /// Batch submission interval (blocks)
    pub batch_interval_blocks: u64,
}

impl Default for ActiveChainConfig {
    fn default() -> Self {
        Self {
            sequencer: SequencerConfig::default(),
            verification_mode: VerificationMode::Optimistic,
            block_time_ms: 2000, // 2 seconds
            batch_interval_blocks: 100,
        }
    }
}

/// The Active Chain (L2)
pub struct ActiveChain {
    /// Configuration
    config: ActiveChainConfig,
    /// Sequencer
    sequencer: Arc<NexusSequencer>,
    /// Execution engine
    execution: Arc<RwLock<ExecutionEngine>>,
    /// Verifier
    verifier: Arc<RwLock<NitroVerifier>>,
    /// Batch builder
    batch_builder: Arc<RwLock<BatchBuilder>>,
    /// Batch submitter
    batch_submitter: Arc<RwLock<BatchSubmitter>>,
    /// Blocks by hash
    blocks: Arc<RwLock<HashMap<Hash256, Block>>>,
    /// Blocks by height
    blocks_by_height: Arc<RwLock<HashMap<BlockHeight, Hash256>>>,
    /// Current height
    height: Arc<RwLock<BlockHeight>>,
    /// L1 reference height (last L1 block we know about)
    l1_reference: Arc<RwLock<BlockHeight>>,
    /// Genesis block
    genesis: Block,
}

impl ActiveChain {
    /// Create a new Active Chain
    pub fn new(config: ActiveChainConfig, keypair: DilithiumKeypair) -> Self {
        let sequencer = Arc::new(NexusSequencer::new(config.sequencer.clone(), keypair));
        let verifier = Arc::new(RwLock::new(NitroVerifier::new(config.verification_mode)));

        let genesis = Block::genesis(Layer::Active);
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis.clone());

        let mut blocks_by_height = HashMap::new();
        blocks_by_height.insert(BlockHeight::GENESIS, genesis_hash);

        Self {
            config,
            sequencer,
            execution: Arc::new(RwLock::new(ExecutionEngine::new())),
            verifier,
            batch_builder: Arc::new(RwLock::new(BatchBuilder::new())),
            batch_submitter: Arc::new(RwLock::new(BatchSubmitter::new())),
            blocks: Arc::new(RwLock::new(blocks)),
            blocks_by_height: Arc::new(RwLock::new(blocks_by_height)),
            height: Arc::new(RwLock::new(BlockHeight::GENESIS)),
            l1_reference: Arc::new(RwLock::new(BlockHeight::GENESIS)),
            genesis,
        }
    }

    /// Get sequencer
    pub fn sequencer(&self) -> Arc<NexusSequencer> {
        self.sequencer.clone()
    }

    /// Get current height
    pub fn height(&self) -> BlockHeight {
        *self.height.read()
    }

    /// Get genesis block
    pub fn genesis(&self) -> &Block {
        &self.genesis
    }

    /// Submit transaction
    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        self.sequencer.submit_transaction(tx)
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

    /// Produce a new block
    pub fn produce_block(&self) -> Result<Block, NexusError> {
        // Build batch from sequencer
        let batch = self.sequencer.build_batch()?;

        let transactions = batch.map(|b| b.transactions).unwrap_or_default();

        if transactions.is_empty() {
            // Return empty block
            return self.create_empty_block();
        }

        // Execute transactions
        let results = self.execution.write().execute_batch(&transactions);

        // Create block
        let height = self.height.read().next();
        let parent_hash = self
            .blocks_by_height
            .read()
            .get(&*self.height.read())
            .cloned()
            .unwrap_or(Hash256::ZERO);

        let header = BlockHeader {
            version: nexus_core::PROTOCOL_VERSION,
            height,
            timestamp: Timestamp::now(),
            parent_hash,
            transactions_root: self.compute_tx_root(&transactions),
            state_root: self.execution.read().state_root().0,
            receipts_root: self.compute_receipts_root(&results),
            layer: Layer::Active,
            proposer: self.sequencer.address(),
            l1_reference: None, // Would be set from L1
            extra_data: Vec::new(),
        };

        let body = BlockBody::new(transactions);
        let block = Block::new(header, body);

        // Store block
        self.store_block(block.clone())?;

        // Add to batch builder
        self.add_to_batch(&block)?;

        Ok(block)
    }

    /// Create empty block
    fn create_empty_block(&self) -> Result<Block, NexusError> {
        let height = self.height.read().next();
        let parent_hash = self
            .blocks_by_height
            .read()
            .get(&*self.height.read())
            .cloned()
            .unwrap_or(Hash256::ZERO);

        let header = BlockHeader::new(height, parent_hash, self.sequencer.address(), Layer::Active);
        let body = BlockBody::new(Vec::new());
        let block = Block::new(header, body);

        self.store_block(block.clone())?;
        Ok(block)
    }

    /// Store a block
    fn store_block(&self, block: Block) -> Result<(), NexusError> {
        let hash = block.hash();
        let height = block.height();

        self.blocks.write().insert(hash, block);
        self.blocks_by_height.write().insert(height, hash);
        *self.height.write() = height;

        Ok(())
    }

    /// Add block to current batch
    fn add_to_batch(&self, block: &Block) -> Result<(), NexusError> {
        let mut builder = self.batch_builder.write();

        // Start new batch if needed
        if builder.pending_count() == 0 {
            builder.start_batch(
                self.execution.read().state_root(),
                block.height(),
            );
        }

        // Add transactions
        for tx in &block.body.transactions {
            if let Err(NexusError::BatchTooLarge) = builder.add_transaction(tx.clone()) {
                // Finalize current batch and start new one
                let batch = builder.finalize_batch(
                    self.execution.read().state_root(),
                    block.height(),
                )?;
                self.batch_submitter.write().queue(batch);

                builder.start_batch(self.execution.read().state_root(), block.height());
                builder.add_transaction(tx.clone())?;
            }
        }

        // Check if should submit batch
        if block.height().0 % self.config.batch_interval_blocks == 0 {
            if builder.pending_count() > 0 {
                let batch = builder.finalize_batch(
                    self.execution.read().state_root(),
                    block.height(),
                )?;
                self.batch_submitter.write().queue(batch);
            }
        }

        Ok(())
    }

    /// Get next batch to submit to L1
    pub fn get_next_batch(&self) -> Option<L2Batch> {
        self.batch_submitter.write().next_to_submit()
    }

    /// Mark batch as submitted
    pub fn mark_batch_submitted(&self, batch: L2Batch, l1_tx_hash: Hash256) {
        self.batch_submitter.write().mark_submitted(batch, l1_tx_hash);
    }

    /// Mark batch as confirmed
    pub fn mark_batch_confirmed(&self, batch_index: u64) -> Option<L2Batch> {
        self.batch_submitter.write().mark_confirmed(batch_index)
    }

    /// Create state proof for batch
    pub fn create_state_proof(&self, batch: &L2Batch) -> StateProof {
        StateProof {
            proof_type: match self.config.verification_mode {
                VerificationMode::ZKValidity => ProofType::ZKValidity,
                VerificationMode::Optimistic => ProofType::Optimistic,
                VerificationMode::Hybrid { .. } => ProofType::ZKValidity,
            },
            pre_state_root: batch.pre_state_root,
            post_state_root: batch.post_state_root,
            height: batch.block_range.1,
            proof_data: batch.validity_proof.clone().unwrap_or_default(),
            public_inputs: Vec::new(),
        }
    }

    /// Compute transaction root
    fn compute_tx_root(&self, transactions: &[SignedTransaction]) -> Hash256 {
        if transactions.is_empty() {
            return Hash256::ZERO;
        }

        let hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.hash()).collect();
        let tree = nexus_core::MerkleTree::from_leaves(hashes);
        tree.root()
    }

    /// Compute receipts root
    fn compute_receipts_root(&self, results: &[ExecutionResult]) -> Hash256 {
        if results.is_empty() {
            return Hash256::ZERO;
        }

        let hashes: Vec<Hash256> = results
            .iter()
            .map(|r| Hash256::hash(&bincode::serialize(r).unwrap_or_default()))
            .collect();
        let tree = nexus_core::MerkleTree::from_leaves(hashes);
        tree.root()
    }

    /// Get state root
    pub fn state_root(&self) -> StateRoot {
        self.execution.read().state_root()
    }

    /// Get execution results for a block
    pub fn get_execution_results(&self, _block_hash: &Hash256) -> Vec<ExecutionResult> {
        // Would be stored with block in production
        Vec::new()
    }

    /// Get chain statistics
    pub fn stats(&self) -> L2ChainStats {
        L2ChainStats {
            height: self.height(),
            pending_txs: self.sequencer.pending_count(),
            pending_batches: self.batch_submitter.read().pending_count(),
            submitted_batches: self.batch_submitter.read().submitted_count(),
            confirmed_batches: self.batch_submitter.read().confirmed_count(),
            total_blocks: self.blocks.read().len(),
        }
    }
}

/// L2 Chain statistics
#[derive(Debug, Clone)]
pub struct L2ChainStats {
    pub height: BlockHeight,
    pub pending_txs: usize,
    pub pending_batches: usize,
    pub submitted_batches: usize,
    pub confirmed_batches: usize,
    pub total_blocks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::SignatureScheme;

    #[test]
    fn test_active_chain_creation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig::default(), keypair);

        assert_eq!(chain.height(), BlockHeight::GENESIS);
        assert!(chain.get_block(&chain.genesis().hash()).is_some());
    }

    #[test]
    fn test_produce_block() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig::default(), keypair);

        let block = chain.produce_block().unwrap();
        assert_eq!(block.height(), BlockHeight::new(1));
        assert_eq!(chain.height(), BlockHeight::new(1));
    }

    #[test]
    fn test_chain_stats() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig::default(), keypair);

        let stats = chain.stats();
        assert_eq!(stats.height, BlockHeight::GENESIS);
        assert_eq!(stats.total_blocks, 1);
    }
}
