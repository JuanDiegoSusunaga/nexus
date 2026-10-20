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
    /// Included in a trusted local L1 processor; distinct from BFT finality
    Confirmed,
    /// Finalized (past challenge period)
    Finalized,
    /// Challenged/Invalid
    Challenged,
}

/// Batch builder for creating L2 batches
#[derive(Serialize, Deserialize)]
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
        self.add_transactions(std::slice::from_ref(&tx))
    }

    /// Comprueba un bloque completo antes de alterar el lote o ejecutar su estado.
    pub fn check_block_capacity(&self, transactions: &[SignedTransaction]) -> Result<(), NexusError> {
        self.check_capacity(transactions, false)
    }

    fn check_capacity(&self, transactions: &[SignedTransaction], include_pending: bool) -> Result<(), NexusError> {
        let mut candidates: Vec<&SignedTransaction> = Vec::new();
        if include_pending { candidates.extend(self.pending_txs.iter()); }
        candidates.extend(transactions.iter());
        if candidates.len() > self.max_tx_count { return Err(NexusError::BatchTooLarge); }
        let size = bincode::serialized_size(&candidates)
            .map_err(|e| NexusError::SerializationError(e.to_string()))?;
        if size > self.max_data_size as u64 { return Err(NexusError::BatchTooLarge); }
        Ok(())
    }

    /// Añade todo el bloque o nada; nunca divide una transición a mitad de bloque.
    pub fn add_transactions(&mut self, transactions: &[SignedTransaction]) -> Result<(), NexusError> {
        self.check_capacity(transactions, true)?;
        self.pending_txs.extend_from_slice(transactions);
        Ok(())
    }

    /// Finalize current batch
    pub fn finalize_batch(&mut self, post_state_root: StateRoot, end_height: BlockHeight) -> Result<L2Batch, NexusError> {
        // Todos los pasos falibles preceden al consumo del contexto del lote.
        let compressed_data = self.compress_transactions()?;
        let next_index = self.current_index.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Se agotaron los índices de lote".into()))?;
        if self.pre_state_root.is_none() || self.block_range.is_none() {
            return Err(NexusError::StateError("No hay un lote iniciado".into()));
        }
        if self.block_range.as_ref().is_some_and(|(start, _)| *start > end_height) {
            return Err(NexusError::StateError("Rango de lote invertido".into()));
        }
        let pre_state_root = self
            .pre_state_root
            .take()
            .ok_or(NexusError::StateError("No batch started".into()))?;

        let block_range = self
            .block_range
            .take()
            .map(|(start, _)| (start, end_height))
            .ok_or(NexusError::StateError("No batch started".into()))?;

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

        self.current_index = next_index;
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
#[derive(Serialize, Deserialize)]
pub struct BatchSubmitter {
    /// Pending batches to submit
    pending: VecDeque<L2Batch>,
    /// Submitted batches awaiting confirmation
    submitted: Vec<SubmittedBatch>,
    /// Confirmed batches
    confirmed: Vec<ConfirmedBatch>,
    /// Submission retry count
    max_retries: u32,
}

/// A submitted batch with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmittedBatch {
    pub batch: L2Batch,
    /// Current attempt; earlier hashes remain reserved and eligible for inclusion.
    pub l1_tx_hash: Hash256,
    pub submitted_at: Timestamp,
    pub retries: u32,
    pub attempts: Vec<SubmissionAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionAttempt {
    pub l1_tx_hash: Hash256,
    pub recorded_at: Timestamp,
    /// Exact serialized signed packet for validated registrations; hash-only intents keep None.
    pub transaction_bytes: Option<Vec<u8>>,
}

/// Local inclusion observation, without promoting an L2 root or claiming BFT finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedBatch {
    pub batch: L2Batch,
    pub l1_tx_hash: Hash256,
    pub l1_block_hash: Hash256,
    pub l1_height: BlockHeight,
    pub attempts: Vec<SubmissionAttempt>,
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
        self.record_submitted(batch, l1_tx_hash, None);
    }

    pub(crate) fn record_submitted(&mut self, batch: L2Batch, l1_tx_hash: Hash256,
        transaction_bytes: Option<Vec<u8>>) {
        // También puede enviarse desde una instantánea recuperada, sin extraer la cola.
        self.pending.retain(|pending| pending.index != batch.index);
        let now = Timestamp::now();
        self.submitted.push(SubmittedBatch {
            batch,
            l1_tx_hash,
            submitted_at: now,
            retries: 0,
            attempts: vec![SubmissionAttempt { l1_tx_hash, recorded_at: now, transaction_bytes }],
        });
    }

    /// ActiveChain has checked initial registration, exact canonical inclusion and the L2 proof.
    pub(crate) fn record_recovered(&mut self, batch: L2Batch, l1_tx_hash: Hash256,
        transaction_bytes: Vec<u8>, l1_block_hash: Hash256, l1_height: BlockHeight) -> ConfirmedBatch {
        self.pending.retain(|pending| pending.index != batch.index);
        let confirmed = ConfirmedBatch { batch, l1_tx_hash, l1_block_hash, l1_height,
            attempts: vec![SubmissionAttempt { l1_tx_hash, recorded_at: Timestamp::now(),
                transaction_bytes: Some(transaction_bytes) }] };
        self.confirmed.push(confirmed.clone());
        confirmed
    }

    /// ActiveChain checks global hash reservations while holding its context write lock.
    pub(crate) fn retry_submission(&mut self, batch_index: u64, expected_hash: Hash256,
        next_hash: Hash256, transaction_bytes: Option<Vec<u8>>) -> Result<(), NexusError> {
        let (pos, retries) = self.checked_retry_position(batch_index, expected_hash)?;
        let entry = &mut self.submitted[pos];
        let now = Timestamp::now();
        entry.attempts.push(SubmissionAttempt { l1_tx_hash: next_hash, recorded_at: now, transaction_bytes });
        entry.l1_tx_hash = next_hash;
        entry.submitted_at = now;
        entry.retries = retries;
        Ok(())
    }

    /// Validate before removing the pending record; append and confirm under the same write lock.
    pub(crate) fn recover_retry(&mut self, batch_index: u64, expected_hash: Hash256,
        next_hash: Hash256, transaction_bytes: Vec<u8>, l1_block_hash: Hash256,
        l1_height: BlockHeight) -> Result<ConfirmedBatch, NexusError> {
        let (pos, _) = self.checked_retry_position(batch_index, expected_hash)?;
        let mut submitted = self.submitted.remove(pos);
        submitted.attempts.push(SubmissionAttempt { l1_tx_hash: next_hash, recorded_at: Timestamp::now(),
            transaction_bytes: Some(transaction_bytes) });
        let confirmed = ConfirmedBatch { batch: submitted.batch, l1_tx_hash: next_hash,
            l1_block_hash, l1_height, attempts: submitted.attempts };
        self.confirmed.push(confirmed.clone());
        Ok(confirmed)
    }

    fn checked_retry_position(&self, batch_index: u64, expected_hash: Hash256) -> Result<(usize, u32), NexusError> {
        let pos = self.submitted.iter().position(|entry| entry.batch.index == batch_index)
            .ok_or_else(|| NexusError::BatchSubmissionFailed("No pending submission to retry".into()))?;
        let entry = &self.submitted[pos];
        if entry.l1_tx_hash != expected_hash {
            return Err(NexusError::BatchSubmissionFailed("Stale submission attempt".into()));
        }
        if entry.retries >= self.max_retries {
            return Err(NexusError::BatchSubmissionFailed("Submission retry limit reached".into()));
        }
        let retries = entry.retries.checked_add(1)
            .ok_or_else(|| NexusError::BatchSubmissionFailed("Submission retry count exhausted".into()))?;
        Ok((pos, retries))
    }

    pub(crate) fn get_submission(&self, batch_index: u64) -> Option<SubmittedBatch> {
        self.submitted.iter().find(|entry| entry.batch.index == batch_index).cloned()
    }

    pub(crate) fn get_transaction_bytes(&self, batch_index: u64, hash: Hash256) -> Option<Vec<u8>> {
        let attempts = self.submitted.iter().find(|entry| entry.batch.index == batch_index)
            .map(|entry| &entry.attempts).or_else(|| self.confirmed.iter()
                .find(|entry| entry.batch.index == batch_index).map(|entry| &entry.attempts))?;
        attempts.iter().find(|attempt| attempt.l1_tx_hash == hash)?.transaction_bytes.clone()
    }

    /// Internal bookkeeping after ActiveChain checks the trusted L1 instance.
    pub(crate) fn mark_confirmed(&mut self, batch_index: u64, l1_tx_hash: Hash256,
        l1_block_hash: Hash256, l1_height: BlockHeight) -> Option<ConfirmedBatch> {
        if let Some(pos) = self.submitted.iter().position(|b| b.batch.index == batch_index
            && b.attempts.iter().any(|attempt| attempt.l1_tx_hash == l1_tx_hash)) {
            let submitted = self.submitted.remove(pos);
            let confirmed = ConfirmedBatch { batch: submitted.batch, l1_tx_hash, l1_block_hash, l1_height,
                attempts: submitted.attempts };
            self.confirmed.push(confirmed.clone());
            return Some(confirmed);
        }
        None
    }

    pub(crate) fn get_confirmation(&self, batch_index: u64) -> Option<ConfirmedBatch> {
        self.confirmed.iter().find(|entry| entry.batch.index == batch_index).cloned()
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

        submitter.mark_confirmed(0, Hash256::hash(b"l1_tx"), Hash256::hash(b"local L1 block"), BlockHeight(1));
        assert_eq!(submitter.confirmed_count(), 1);
    }

    #[test]
    fn bloque_completo_se_agrega_atomicamente_y_cuenta_el_tamano_serializado() {
        let tx = create_test_tx();
        let mut builder = BatchBuilder::with_limits(2, usize::MAX);
        builder.start_batch(StateRoot::EMPTY, BlockHeight(1));
        builder.add_transaction(tx.clone()).unwrap();
        assert!(matches!(builder.add_transactions(&[tx.clone(), tx.clone()]), Err(NexusError::BatchTooLarge)));
        assert_eq!(builder.pending_count(), 1);
        assert!(builder.check_block_capacity(&[tx.clone(), tx.clone()]).is_ok());
        let size = bincode::serialized_size(&vec![tx.clone()]).unwrap() as usize;
        let mut exact = BatchBuilder::with_limits(2, size);
        exact.start_batch(StateRoot::EMPTY, BlockHeight(1));
        exact.add_transaction(tx.clone()).unwrap();
        assert!(exact.add_transaction(tx).is_err());
        assert_eq!(exact.pending_count(), 1);
        let batch = exact.finalize_batch(StateRoot::EMPTY, BlockHeight(1)).unwrap();
        assert_eq!(batch.compressed_data.len(), size);
    }

    #[test]
    fn finalizar_rango_invertido_no_consume_el_contexto_del_lote() {
        let mut builder = BatchBuilder::new();
        builder.start_batch(StateRoot::EMPTY, BlockHeight(2));
        builder.add_transaction(create_test_tx()).unwrap();
        assert!(builder.finalize_batch(StateRoot::EMPTY, BlockHeight(1)).is_err());
        assert_eq!(builder.pending_count(), 1);
        let batch = builder.finalize_batch(StateRoot::EMPTY, BlockHeight(3)).unwrap();
        assert_eq!(batch.index, 0);
        assert_eq!(batch.block_range, (BlockHeight(2), BlockHeight(3)));
    }
}
