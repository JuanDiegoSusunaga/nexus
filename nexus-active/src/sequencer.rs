//! Nexus Sequencer - Transaction Ordering and Batching
//!
//! The sequencer is responsible for:
//! - Receiving transactions from users
//! - Ordering transactions fairly
//! - Building batches for L1 submission
//! - Maintaining liveness guarantees

use nexus_core::{
    Address, Amount, BlockHeight, Hash256, NexusError, SignedTransaction,
    Timestamp, TransactionType,
};
use nexus_crypto::{DilithiumKeypair, Signer};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Arc;
use std::cmp::Ordering;

/// Sequencer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Maximum transactions per batch
    pub max_batch_size: usize,
    /// Maximum batch data size (bytes)
    pub max_batch_bytes: usize,
    /// Batch submission interval (ms)
    pub batch_interval_ms: u64,
    /// Minimum transactions before batch
    pub min_batch_size: usize,
    /// Transaction timeout (ms)
    pub tx_timeout_ms: u64,
    /// Required stake amount
    pub required_stake: Amount,
    /// Sequencer mode
    pub mode: SequencerMode,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 10_000,
            max_batch_bytes: 1_048_576, // 1 MB
            batch_interval_ms: 2_000,   // 2 seconds
            min_batch_size: 1,
            tx_timeout_ms: 60_000, // 1 minute
            required_stake: Amount::from_units(100),
            mode: SequencerMode::Centralized,
        }
    }
}

/// Sequencer operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequencerMode {
    /// Single centralized sequencer
    Centralized,
    /// Decentralized sequencer rotation
    Decentralized,
    /// Based on consensus (shared sequencing)
    SharedSequencing,
}

/// Pending transaction with priority
#[derive(Clone)]
struct PendingTx {
    /// The transaction
    tx: SignedTransaction,
    /// Received timestamp
    received_at: Timestamp,
    /// Gas price (for priority)
    gas_price: Amount,
}

impl PartialEq for PendingTx {
    fn eq(&self, other: &Self) -> bool {
        self.tx.hash() == other.tx.hash()
    }
}

impl Eq for PendingTx {}

impl PartialOrd for PendingTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher gas price = higher priority
        self.gas_price.0.cmp(&other.gas_price.0)
    }
}

/// The Nexus Sequencer
pub struct NexusSequencer {
    /// Configuration
    config: SequencerConfig,
    /// Sequencer keypair
    keypair: Arc<DilithiumKeypair>,
    /// Pending transactions (priority queue)
    pending: Arc<RwLock<BinaryHeap<PendingTx>>>,
    /// Transaction lookup (hash -> pending)
    tx_lookup: Arc<RwLock<HashMap<Hash256, SignedTransaction>>>,
    /// Current batch being built
    current_batch: Arc<RwLock<Vec<SignedTransaction>>>,
    /// Last batch submission time
    last_batch_time: Arc<RwLock<Timestamp>>,
    /// Batch counter
    batch_counter: Arc<RwLock<u64>>,
    /// Sequencer address
    address: Address,
    /// Whether sequencer is active
    is_active: Arc<RwLock<bool>>,
    /// Nonce tracker per sender
    nonces: Arc<RwLock<HashMap<Address, u64>>>,
}

impl NexusSequencer {
    /// Create a new sequencer
    pub fn new(config: SequencerConfig, keypair: DilithiumKeypair) -> Self {
        let address = keypair.address();

        Self {
            config,
            keypair: Arc::new(keypair),
            pending: Arc::new(RwLock::new(BinaryHeap::new())),
            tx_lookup: Arc::new(RwLock::new(HashMap::new())),
            current_batch: Arc::new(RwLock::new(Vec::new())),
            last_batch_time: Arc::new(RwLock::new(Timestamp::now())),
            batch_counter: Arc::new(RwLock::new(0)),
            address,
            is_active: Arc::new(RwLock::new(true)),
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get sequencer address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Check if sequencer is active
    pub fn is_active(&self) -> bool {
        *self.is_active.read()
    }

    /// Submit a transaction to the sequencer
    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        if !self.is_active() {
            return Err(NexusError::NotActiveSequencer);
        }

        // Validate transaction
        tx.validate_structure()?;

        let hash = tx.hash();

        // Check for duplicate
        if self.tx_lookup.read().contains_key(&hash) {
            return Err(NexusError::DuplicateTransaction(hash));
        }

        // Check nonce
        let expected_nonce = self.nonces.read().get(&tx.sender).copied().unwrap_or(0);
        if tx.transaction.nonce.0 < expected_nonce {
            return Err(NexusError::InvalidNonce {
                expected: expected_nonce,
                got: tx.transaction.nonce.0,
            });
        }

        // Add to pending
        let pending_tx = PendingTx {
            gas_price: tx.transaction.gas_price,
            received_at: Timestamp::now(),
            tx: tx.clone(),
        };

        self.pending.write().push(pending_tx);
        self.tx_lookup.write().insert(hash, tx);

        tracing::debug!("Transaction submitted: {}", hash);

        Ok(hash)
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Build the next batch
    pub fn build_batch(&self) -> Result<Option<SequencerBatch>, NexusError> {
        if !self.is_active() {
            return Err(NexusError::NotActiveSequencer);
        }

        let mut pending = self.pending.write();
        let mut batch_txs = Vec::new();
        let mut batch_size = 0usize;

        // Collect transactions for batch
        while let Some(pending_tx) = pending.pop() {
            // Check timeout
            let age = Timestamp::now().elapsed_since(pending_tx.received_at);
            if age > self.config.tx_timeout_ms {
                // Transaction expired, remove from lookup
                self.tx_lookup.write().remove(&pending_tx.tx.hash());
                continue;
            }

            // Check batch limits
            let tx_size = bincode::serialize(&pending_tx.tx)
                .map(|b| b.len())
                .unwrap_or(0);

            if batch_txs.len() >= self.config.max_batch_size {
                // Put back and break
                pending.push(pending_tx);
                break;
            }

            if batch_size + tx_size > self.config.max_batch_bytes {
                pending.push(pending_tx);
                break;
            }

            batch_txs.push(pending_tx.tx.clone());
            batch_size += tx_size;

            // Update nonce tracker
            self.nonces.write().insert(
                pending_tx.tx.sender,
                pending_tx.tx.transaction.nonce.0 + 1,
            );
        }

        // Check minimum batch size
        if batch_txs.len() < self.config.min_batch_size {
            // Put transactions back
            for tx in batch_txs {
                pending.push(PendingTx {
                    gas_price: tx.transaction.gas_price,
                    received_at: Timestamp::now(),
                    tx,
                });
            }
            return Ok(None);
        }

        // Create batch
        let batch_index = {
            let mut counter = self.batch_counter.write();
            let idx = *counter;
            *counter += 1;
            idx
        };

        let batch = SequencerBatch {
            index: batch_index,
            transactions: batch_txs,
            sequencer: self.address,
            timestamp: Timestamp::now(),
            signature: vec![], // Would be signed
        };

        *self.last_batch_time.write() = Timestamp::now();

        // Remove from lookup
        for tx in &batch.transactions {
            self.tx_lookup.write().remove(&tx.hash());
        }

        Ok(Some(batch))
    }

    /// Check if batch should be submitted (time-based)
    pub fn should_submit_batch(&self) -> bool {
        let elapsed = Timestamp::now().elapsed_since(*self.last_batch_time.read());
        elapsed >= self.config.batch_interval_ms && self.pending_count() >= self.config.min_batch_size
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &Hash256) -> Option<SignedTransaction> {
        self.tx_lookup.read().get(hash).cloned()
    }

    /// Remove transaction (e.g., after inclusion)
    pub fn remove_transaction(&self, hash: &Hash256) -> Option<SignedTransaction> {
        self.tx_lookup.write().remove(hash)
    }

    /// Activate/deactivate sequencer
    pub fn set_active(&self, active: bool) {
        *self.is_active.write() = active;
    }

    /// Get batch counter
    pub fn batch_count(&self) -> u64 {
        *self.batch_counter.read()
    }
}

/// A batch produced by the sequencer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerBatch {
    /// Batch index
    pub index: u64,
    /// Ordered transactions
    pub transactions: Vec<SignedTransaction>,
    /// Sequencer address
    pub sequencer: Address,
    /// Creation timestamp
    pub timestamp: Timestamp,
    /// Sequencer signature
    pub signature: Vec<u8>,
}

impl SequencerBatch {
    /// Calculate batch hash
    pub fn hash(&self) -> Hash256 {
        let data = bincode::serialize(self).expect("Batch serialization failed");
        Hash256::hash(&data)
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get all transaction hashes
    pub fn tx_hashes(&self) -> Vec<Hash256> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{ChainId, Nonce, SignatureScheme, Transaction};

    fn create_test_tx(nonce: u64) -> SignedTransaction {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(nonce),
            Address::ZERO,
            Amount::from_units(1),
            21000,
            Amount(1000000000),
        );
        keypair.sign_transaction(tx).unwrap()
    }

    #[test]
    fn test_sequencer_creation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let sequencer = NexusSequencer::new(SequencerConfig::default(), keypair);

        assert!(sequencer.is_active());
        assert_eq!(sequencer.pending_count(), 0);
    }

    #[test]
    fn test_submit_transaction() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let sequencer = NexusSequencer::new(SequencerConfig::default(), keypair);

        let tx = create_test_tx(0);
        let hash = sequencer.submit_transaction(tx).unwrap();

        assert_eq!(sequencer.pending_count(), 1);
        assert!(sequencer.get_transaction(&hash).is_some());
    }

    #[test]
    fn test_build_batch() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let config = SequencerConfig {
            min_batch_size: 1,
            ..Default::default()
        };
        let sequencer = NexusSequencer::new(config, keypair);

        // Submit transactions
        for i in 0..5 {
            let tx = create_test_tx(i);
            sequencer.submit_transaction(tx).unwrap();
        }

        let batch = sequencer.build_batch().unwrap().unwrap();
        assert_eq!(batch.tx_count(), 5);
        assert_eq!(sequencer.pending_count(), 0);
    }

    #[test]
    fn test_duplicate_transaction() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let sequencer = NexusSequencer::new(SequencerConfig::default(), keypair);

        let tx = create_test_tx(0);
        sequencer.submit_transaction(tx.clone()).unwrap();

        let result = sequencer.submit_transaction(tx);
        assert!(matches!(result, Err(NexusError::DuplicateTransaction(_))));
    }
}
