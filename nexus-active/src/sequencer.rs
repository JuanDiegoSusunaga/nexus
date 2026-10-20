//! Authenticated transaction pool with per-sender nonce dependencies.
//! Building reserves work; confirmed nonces advance only from local execution.

use crate::execution::ExecutionResult;
use nexus_core::{Address, Amount, Hash256, NexusError, SignedTransaction, Timestamp};
use nexus_crypto::{verify_signed_transaction, DilithiumKeypair};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
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


#[derive(Clone)]
struct PendingTx {
    tx: SignedTransaction,
    received_at: Timestamp,
    size: usize,
}
impl PartialEq for PendingTx {
    fn eq(&self, other: &Self) -> bool { self.tx.hash() == other.tx.hash() }
}
impl Eq for PendingTx {}
impl PartialOrd for PendingTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for PendingTx {
    fn cmp(&self, other: &Self) -> Ordering {
        self.tx.transaction.gas_price.cmp(&other.tx.transaction.gas_price)
            .then_with(|| other.received_at.cmp(&self.received_at))
            .then_with(|| other.tx.hash().0.cmp(&self.tx.hash().0))
    }
}

struct Pool {
    pending: HashMap<Address, BTreeMap<u64, PendingTx>>,
    lookup: HashMap<Hash256, SignedTransaction>,
    in_flight: HashMap<Hash256, PendingTx>,
    confirmed_nonces: HashMap<Address, u64>,
    last_batch_time: Timestamp,
    batch_counter: u64,
}

pub struct NexusSequencer {
    config: SequencerConfig,
    address: Address,
    is_active: RwLock<bool>,
    pool: Mutex<Pool>,
}

impl NexusSequencer {
    pub fn new(config: SequencerConfig, keypair: DilithiumKeypair) -> Self {
        Self { config, address: keypair.address(), is_active: RwLock::new(true),
            pool: Mutex::new(Pool { pending: HashMap::new(), lookup: HashMap::new(),
                in_flight: HashMap::new(), confirmed_nonces: HashMap::new(),
                last_batch_time: Timestamp::now(), batch_counter: 0 }) }
    }

    fn check_config(&self) -> Result<(), NexusError> {
        if self.config.max_batch_size == 0 || self.config.min_batch_size == 0
            || self.config.min_batch_size > self.config.max_batch_size || self.config.max_batch_bytes == 0 {
            return Err(NexusError::ConfigError("Invalid sequencer batch limits".into()));
        }
        Ok(())
    }
    pub fn address(&self) -> Address { self.address }
    pub fn is_active(&self) -> bool { *self.is_active.read() }

    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        self.check_config()?;
        if !self.is_active() { return Err(NexusError::NotActiveSequencer); }
        let size = usize::try_from(bincode::serialized_size(&tx)?)
            .map_err(|_| NexusError::BatchTooLarge)?;
        if size > self.config.max_batch_bytes { return Err(NexusError::BatchTooLarge); }
        if !verify_signed_transaction(&tx)? {
            return Err(NexusError::SignatureVerificationFailed(tx.sender));
        }
        let hash = tx.hash();
        let mut pool = self.pool.lock();
        if pool.lookup.contains_key(&hash) { return Err(NexusError::DuplicateTransaction(hash)); }
        let expected = pool.confirmed_nonces.get(&tx.sender).copied().unwrap_or(0);
        if tx.transaction.nonce.0 < expected {
            return Err(NexusError::InvalidNonce { expected, got: tx.transaction.nonce.0 });
        }
        if pool.pending.get(&tx.sender).is_some_and(|txs| txs.contains_key(&tx.transaction.nonce.0))
            || pool.in_flight.values().any(|p| p.tx.sender == tx.sender && p.tx.transaction.nonce == tx.transaction.nonce) {
            return Err(NexusError::InvalidTransaction("Sender nonce already reserved".into()));
        }
        pool.pending.entry(tx.sender).or_default().insert(tx.transaction.nonce.0,
            PendingTx { tx: tx.clone(), received_at: Timestamp::now(), size });
        pool.lookup.insert(hash, tx);
        Ok(hash)
    }

    pub fn pending_count(&self) -> usize {
        self.pool.lock().pending.values().map(BTreeMap::len).sum()
    }

    pub fn build_batch(&self) -> Result<Option<SequencerBatch>, NexusError> {
        self.check_config()?;
        if !self.is_active() { return Err(NexusError::NotActiveSequencer); }
        let mut pool = self.pool.lock();
        let now = Timestamp::now();
        let mut expired = Vec::new();
        for transactions in pool.pending.values_mut() {
            transactions.retain(|_, p| {
                let keep = now.elapsed_since(p.received_at) <= self.config.tx_timeout_ms
                    && !p.tx.transaction.is_expired();
                if !keep { expired.push(p.tx.hash()); }
                keep
            });
        }
        for hash in expired { pool.lookup.remove(&hash); }
        pool.pending.retain(|_, transactions| !transactions.is_empty());

        // Only the next executable nonce of each available sender competes on gas.
        let busy: HashSet<_> = pool.in_flight.values().map(|p| p.tx.sender).collect();
        let mut heads = BinaryHeap::new();
        for (sender, transactions) in &pool.pending {
            if busy.contains(sender) { continue; }
            let nonce = pool.confirmed_nonces.get(sender).copied().unwrap_or(0);
            if let Some(head) = transactions.get(&nonce) { heads.push(head.clone()); }
        }
        let mut selected = Vec::new();
        let mut bytes = 0usize;
        while selected.len() < self.config.max_batch_size {
            let Some(head) = heads.pop() else { break; };
            if head.size > self.config.max_batch_bytes.saturating_sub(bytes) {
                // Other sender heads can still fit; do not block the entire pool.
                continue;
            }
            bytes += head.size;
            if let Some(next) = head.tx.transaction.nonce.0.checked_add(1)
                .and_then(|nonce| pool.pending.get(&head.tx.sender)?.get(&nonce)) {
                heads.push(next.clone());
            }
            selected.push(head);
        }
        if selected.len() < self.config.min_batch_size { return Ok(None); }
        let next_index = pool.batch_counter.checked_add(1)
            .ok_or_else(|| NexusError::SequencerError("Batch counter exhausted".into()))?;
        let batch = SequencerBatch { index: pool.batch_counter,
            transactions: selected.iter().map(|p| p.tx.clone()).collect(),
            sequencer: self.address, timestamp: now, signature: vec![] };
        for pending in selected {
            if let Some(txs) = pool.pending.get_mut(&pending.tx.sender) {
                txs.remove(&pending.tx.transaction.nonce.0);
            }
            pool.in_flight.insert(pending.tx.hash(), pending);
        }
        pool.pending.retain(|_, transactions| !transactions.is_empty());
        pool.batch_counter = next_index;
        pool.last_batch_time = now;
        Ok(Some(batch))
    }

    /// Called only by local ActiveChain execution, never from a received envelope.
    pub(crate) fn complete_execution(&self, transactions: &[SignedTransaction], results: &[ExecutionResult])
        -> Result<(), NexusError> {
        let mut pool = self.pool.lock();
        if transactions.len() != results.len() || transactions.iter().zip(results).any(|(tx, res)|
            tx.hash() != res.tx_hash || !pool.in_flight.contains_key(&tx.hash())) {
            return Err(NexusError::StateError("Execution does not match reserved transactions".into()));
        }
        let mut confirmed = pool.confirmed_nonces.clone();
        for (tx, result) in transactions.iter().zip(results) {
            let expected = confirmed.get(&tx.sender).copied().unwrap_or(0);
            if result.success {
                if tx.transaction.nonce.0 != expected {
                    return Err(NexusError::StateError("Successful execution has unexpected nonce".into()));
                }
                confirmed.insert(tx.sender, expected.checked_add(1)
                    .ok_or_else(|| NexusError::StateError("Nonce exhausted".into()))?);
            }
        }
        pool.confirmed_nonces = confirmed;
        for (tx, result) in transactions.iter().zip(results) {
            let pending = pool.in_flight.remove(&tx.hash()).expect("reservation checked under lock");
            let expected = pool.confirmed_nonces.get(&tx.sender).copied().unwrap_or(0);
            if !result.success && tx.transaction.nonce.0 > expected {
                pool.pending.entry(tx.sender).or_default().insert(tx.transaction.nonce.0, pending);
            } else {
                pool.lookup.remove(&tx.hash());
            }
        }
        Ok(())
    }

    pub(crate) fn release_transactions(&self, transactions: &[SignedTransaction]) {
        let mut pool = self.pool.lock();
        for tx in transactions {
            if let Some(pending) = pool.in_flight.remove(&tx.hash()) {
                pool.pending.entry(tx.sender).or_default().insert(tx.transaction.nonce.0, pending);
            }
        }
    }

    pub fn should_submit_batch(&self) -> bool {
        let pool = self.pool.lock();
        Timestamp::now().elapsed_since(pool.last_batch_time) >= self.config.batch_interval_ms
            && pool.pending.values().map(BTreeMap::len).sum::<usize>() >= self.config.min_batch_size
    }
    pub fn get_transaction(&self, hash: &Hash256) -> Option<SignedTransaction> { self.pool.lock().lookup.get(hash).cloned() }
    pub fn remove_transaction(&self, hash: &Hash256) -> Option<SignedTransaction> {
        let mut pool = self.pool.lock();
        if pool.in_flight.contains_key(hash) { return None; }
        let tx = pool.lookup.remove(hash)?;
        if let Some(txs) = pool.pending.get_mut(&tx.sender) { txs.remove(&tx.transaction.nonce.0); }
        Some(tx)
    }
    pub fn set_active(&self, active: bool) { *self.is_active.write() = active; }
    pub fn batch_count(&self) -> u64 { self.pool.lock().batch_counter }
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
    use nexus_crypto::Signer;
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
        for _ in 0..5 {
            let tx = create_test_tx(0);
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

    #[test]
    fn failed_execution_releases_current_nonce_and_preserves_future_dependencies() {
        use crate::execution::ExecutionEngine;
        use nexus_core::AccountState;
        let sequencer = NexusSequencer::new(SequencerConfig::default(),
            DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let tx = |nonce| signer.sign_transaction(Transaction::transfer(ChainId::LOCAL,
            Nonce(nonce), Address::ZERO, Amount(1), 21000, Amount(1_000_000_000))).unwrap();
        let first = tx(0);
        sequencer.submit_transaction(first.clone()).unwrap();
        sequencer.submit_transaction(tx(1)).unwrap();
        let mut engine = ExecutionEngine::new();
        let batch = sequencer.build_batch().unwrap().unwrap();
        let results = engine.execute_batch(&batch.transactions);
        assert!(results.iter().all(|result| !result.success));
        sequencer.complete_execution(&batch.transactions, &results).unwrap();
        assert_eq!(sequencer.pending_count(), 1);
        assert!(sequencer.build_batch().unwrap().is_none());
        engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(1)));
        sequencer.submit_transaction(first.clone()).unwrap();
        let retry = sequencer.build_batch().unwrap().unwrap();
        assert_eq!(retry.transactions.iter().map(|tx| tx.transaction.nonce.0).collect::<Vec<_>>(), vec![0, 1]);
        let results = engine.execute_batch(&retry.transactions);
        assert!(results.iter().all(|result| result.success));
        sequencer.complete_execution(&retry.transactions, &results).unwrap();
        assert!(matches!(sequencer.submit_transaction(first), Err(NexusError::InvalidNonce { expected: 2, .. })));
        sequencer.submit_transaction(tx(2)).unwrap();
        assert_eq!(sequencer.build_batch().unwrap().unwrap().transactions[0].transaction.nonce, Nonce(2));
    }

    #[test]
    fn incomplete_batches_and_cancelled_reservations_do_not_advance_nonces() {
        let config = SequencerConfig { min_batch_size: 2, ..Default::default() };
        let sequencer = NexusSequencer::new(config,
            DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let first = create_test_tx(0);
        sequencer.submit_transaction(first.clone()).unwrap();
        assert!(sequencer.build_batch().unwrap().is_none());
        assert_eq!(sequencer.pending_count(), 1);
        sequencer.submit_transaction(create_test_tx(0)).unwrap();
        let batch = sequencer.build_batch().unwrap().unwrap();
        assert_eq!(sequencer.pending_count(), 0);
        assert!(sequencer.remove_transaction(&first.hash()).is_none());
        sequencer.release_transactions(&batch.transactions);
        assert_eq!(sequencer.pending_count(), 2);
        assert_eq!(sequencer.build_batch().unwrap().unwrap().tx_count(), 2);
    }

    #[test]
    fn concurrent_duplicate_admission_has_a_single_winner() {
        let sequencer = std::sync::Arc::new(NexusSequencer::new(SequencerConfig::default(),
            DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()));
        let transaction = create_test_tx(0);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4).map(|_| {
            let sequencer = sequencer.clone();
            let barrier = barrier.clone();
            let transaction = transaction.clone();
            std::thread::spawn(move || { barrier.wait(); sequencer.submit_transaction(transaction).is_ok() })
        }).collect();
        assert_eq!(workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum::<usize>(), 1);
        assert_eq!(sequencer.pending_count(), 1);
    }
}
