//! Batch Building and Management for L2
//!
//! Handles batch creation, compression, and submission to L1.

use nexus_core::{Hash256, NexusError, PQSignature, SignedTransaction, StateRoot, BlockHeight, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// L2 Batch ready for L1 submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Batch {
    /// Batch index
    pub index: u64,
    /// Block range covered (start, end)
    pub block_range: (BlockHeight, BlockHeight),
    /// Number of transactions
    pub tx_count: usize,
    /// Compressed transaction data
    pub compressed_data: Vec<u8>,
    /// Pre-state root
    pub pre_state_root: StateRoot,
    /// Post-state root
    pub post_state_root: StateRoot,
    /// Batch hash
    pub batch_hash: Hash256,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Sequencer signature
    pub signature: Option<Vec<u8>>,
    /// ZK validity proof (if using validity rollup)
    pub validity_proof: Option<Vec<u8>>,
}

impl L2Batch {
    /// Calculate batch hash
    pub fn compute_hash(&self) -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.index.to_le_bytes());
        data.extend_from_slice(&self.block_range.0.0.to_le_bytes());
        data.extend_from_slice(&self.block_range.1.0.to_le_bytes());
        data.extend_from_slice(self.pre_state_root.0.as_bytes());
        data.extend_from_slice(self.post_state_root.0.as_bytes());
        data.extend_from_slice(&self.compressed_data);
        Hash256::hash(&data)
    }

    /// Get data size
    pub fn data_size(&self) -> usize {
        self.compressed_data.len()
    }

    /// Check if batch has validity proof
    pub fn has_validity_proof(&self) -> bool {
        self.validity_proof.is_some()
    }
}

/// Batch status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStatus {
    /// Being built
    Building,
    /// Ready for submission
    Ready,
    /// Submitted to L1
    Submitted,
    /// Confirmed on L1
    Confirmed,
    /// Finalized (past challenge period)
    Finalized,
    /// Challenged/Invalid
    Challenged,
}

/// Batch builder for creating L2 batches
pub struct BatchBuilder {
    /// Current batch index
    current_index: u64,
    /// Pending transactions
    pending_txs: Vec<SignedTransaction>,
    /// Current block range
    block_range: Option<(BlockHeight, BlockHeight)>,
    /// Pre-state root (set when starting batch)
    pre_state_root: Option<StateRoot>,
    /// Maximum batch size (transactions)
    max_tx_count: usize,
    /// Maximum batch data size (bytes)
    max_data_size: usize,
    /// Compression enabled
    compression_enabled: bool,
    /// Pending batches queue
    pending_batches: VecDeque<L2Batch>,
}

impl BatchBuilder {
    /// Create a new batch builder
    pub fn new() -> Self {
        Self {
            current_index: 0,
            pending_txs: Vec::new(),
            block_range: None,
            pre_state_root: None,
            max_tx_count: 10_000,
            max_data_size: 128 * 1024, // 128 KB
            compression_enabled: true,
            pending_batches: VecDeque::new(),
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_tx_count: usize, max_data_size: usize) -> Self {
        Self {
            max_tx_count,
            max_data_size,
            ..Self::new()
        }
    }

    /// Start a new batch
    pub fn start_batch(&mut self, pre_state_root: StateRoot, start_height: BlockHeight) {
        self.pending_txs.clear();
        self.pre_state_root = Some(pre_state_root);
        self.block_range = Some((start_height, start_height));
    }

    /// Add transaction to current batch
    pub fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), NexusError> {
        if self.pending_txs.len() >= self.max_tx_count {
            return Err(NexusError::BatchTooLarge);
        }

        // Check data size
        let tx_size = bincode::serialize(&tx).map(|b| b.len()).unwrap_or(0);
        let current_size: usize = self
            .pending_txs
            .iter()
            .map(|t| bincode::serialize(t).map(|b| b.len()).unwrap_or(0))
            .sum();

        if current_size + tx_size > self.max_data_size {
            return Err(NexusError::BatchTooLarge);
        }

        self.pending_txs.push(tx);
        Ok(())
    }

    /// Finalize current batch
    pub fn finalize_batch(&mut self, post_state_root: StateRoot, end_height: BlockHeight) -> Result<L2Batch, NexusError> {
        let pre_state_root = self
            .pre_state_root
            .take()
            .ok_or(NexusError::StateError("No batch started".into()))?;

        let block_range = self
            .block_range
            .take()
            .map(|(start, _)| (start, end_height))
            .ok_or(NexusError::StateError("No batch started".into()))?;

        // Compress transactions
        let compressed_data = self.compress_transactions()?;

        let batch = L2Batch {
            index: self.current_index,
            block_range,
            tx_count: self.pending_txs.len(),
            compressed_data,
            pre_state_root,
            post_state_root,
            batch_hash: Hash256::ZERO, // Will be computed
            created_at: Timestamp::now(),
            signature: None,
            validity_proof: None,
        };

        // Compute hash
        let mut batch = batch;
        batch.batch_hash = batch.compute_hash();

        self.current_index += 1;
        self.pending_txs.clear();

        Ok(batch)
    }

    /// Compress transactions for batch
    fn compress_transactions(&self) -> Result<Vec<u8>, NexusError> {
        let serialized = bincode::serialize(&self.pending_txs)
            .map_err(|e| NexusError::SerializationError(e.to_string()))?;

        if self.compression_enabled {
            // Simplified compression (in production use zstd or similar)
            // For now, just return serialized data
            Ok(serialized)
        } else {
            Ok(serialized)
        }
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending_txs.len()
    }

    /// Check if batch is ready (meets minimum size)
    pub fn is_ready(&self, min_tx_count: usize) -> bool {
        self.pending_txs.len() >= min_tx_count
    }

    /// Get current batch index
    pub fn current_index(&self) -> u64 {
        self.current_index
    }

    /// Queue a batch for submission
    pub fn queue_batch(&mut self, batch: L2Batch) {
        self.pending_batches.push_back(batch);
    }

    /// Get next batch to submit
    pub fn next_batch(&mut self) -> Option<L2Batch> {
        self.pending_batches.pop_front()
    }

    /// Get pending batch count
    pub fn pending_batch_count(&self) -> usize {
        self.pending_batches.len()
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch submission manager
pub struct BatchSubmitter {
    /// Pending batches to submit
    pending: VecDeque<L2Batch>,
    /// Submitted batches awaiting confirmation
    submitted: Vec<SubmittedBatch>,
    /// Confirmed batches
    confirmed: Vec<L2Batch>,
    /// Submission retry count
    max_retries: u32,
}

/// A submitted batch with metadata
#[derive(Debug, Clone)]
pub struct SubmittedBatch {
    pub batch: L2Batch,
    pub l1_tx_hash: Hash256,
    pub submitted_at: Timestamp,
    pub retries: u32,
}

impl BatchSubmitter {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            submitted: Vec::new(),
            confirmed: Vec::new(),
            max_retries: 3,
        }
    }

    /// Queue a batch for submission
    pub fn queue(&mut self, batch: L2Batch) {
        self.pending.push_back(batch);
    }

    /// Get next batch to submit
    pub fn next_to_submit(&mut self) -> Option<L2Batch> {
        self.pending.pop_front()
    }

    /// Mark batch as submitted
    pub fn mark_submitted(&mut self, batch: L2Batch, l1_tx_hash: Hash256) {
        self.submitted.push(SubmittedBatch {
            batch,
            l1_tx_hash,
            submitted_at: Timestamp::now(),
            retries: 0,
        });
    }

    /// Mark batch as confirmed
    pub fn mark_confirmed(&mut self, batch_index: u64) -> Option<L2Batch> {
        if let Some(pos) = self.submitted.iter().position(|b| b.batch.index == batch_index) {
            let submitted = self.submitted.remove(pos);
            self.confirmed.push(submitted.batch.clone());
            return Some(submitted.batch);
        }
        None
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get submitted count
    pub fn submitted_count(&self) -> usize {
        self.submitted.len()
    }

    /// Get confirmed count
    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }
}

impl Default for BatchSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{ChainId, Nonce, SignatureScheme, Transaction, Address, Amount};
    use nexus_crypto::{DilithiumKeypair, Signer};

    fn create_test_tx() -> SignedTransaction {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(0),
            Address::ZERO,
            Amount::from_units(1),
            21000,
            Amount(1_000_000_000),
        );
        keypair.sign_transaction(tx).unwrap()
    }

    #[test]
    fn test_batch_builder() {
        let mut builder = BatchBuilder::new();

        builder.start_batch(StateRoot::EMPTY, BlockHeight::new(1));

        for _ in 0..5 {
            builder.add_transaction(create_test_tx()).unwrap();
        }

        assert_eq!(builder.pending_count(), 5);

        let batch = builder
            .finalize_batch(StateRoot::new(Hash256::hash(b"post")), BlockHeight::new(10))
            .unwrap();

        assert_eq!(batch.tx_count, 5);
        assert_eq!(batch.block_range, (BlockHeight::new(1), BlockHeight::new(10)));
    }

    #[test]
    fn test_batch_submitter() {
        let mut submitter = BatchSubmitter::new();

        let batch = L2Batch {
            index: 0,
            block_range: (BlockHeight::new(1), BlockHeight::new(10)),
            tx_count: 5,
            compressed_data: vec![],
            pre_state_root: StateRoot::EMPTY,
            post_state_root: StateRoot::EMPTY,
            batch_hash: Hash256::ZERO,
            created_at: Timestamp::now(),
            signature: None,
            validity_proof: None,
        };

        submitter.queue(batch.clone());
        assert_eq!(submitter.pending_count(), 1);

        let to_submit = submitter.next_to_submit().unwrap();
        submitter.mark_submitted(to_submit, Hash256::hash(b"l1_tx"));
        assert_eq!(submitter.submitted_count(), 1);

        submitter.mark_confirmed(0);
        assert_eq!(submitter.confirmed_count(), 1);
    }
}
