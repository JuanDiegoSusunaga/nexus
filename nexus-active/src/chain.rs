//! Prototipo ActiveChain: ejecución, lotes y verificación con contexto local.
//! El contrato Lean escalar no acredita transacciones ni raíces SHA3 generales.

use crate::{
    batch::{BatchBuilder, BatchSubmitter, ConfirmedBatch, L2Batch, SubmittedBatch},
    execution::{ExecutionEngine, ExecutionResult},
    linked_verifier::{ExpectedTransition, public_inputs},
    sequencer::{NexusSequencer, SequencerConfig},
    verifier::{NitroVerifier, VerificationMode, StateProof, ProofType, VerificationResult},
};
use nexus_core::{
    Block, BlockHeader, BlockBody, BlockHeight, Hash256, Layer, NexusError,
    SignedTransaction, StateRoot, Timestamp, Address, InMemoryState,
};
use nexus_crypto::DilithiumKeypair;
use nexus_anchor::{AnchorChain, L1SubmissionOptions};
use nexus_zk::stark::{linked::{MIN_ROWS, MAX_ROWS, MAX_CERTIFICATE_BYTES}, params::POW_BITS_RUNTIME};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

/// Política local; jamás se extrae del certificado recibido.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LinkedValidityProfile {
    steps: usize,
    pow_bits: u32,
}

impl LinkedValidityProfile {
    pub fn new(steps: usize, pow_bits: u32) -> Result<Self, NexusError> {
        if !(MIN_ROWS..=MAX_ROWS).contains(&steps) || !steps.is_power_of_two()
            || (pow_bits != 12 && pow_bits != 20) {
            return Err(NexusError::ConfigError("Perfil fuera del contrato Lean".into()));
        }
        Ok(Self { steps, pow_bits })
    }
}

impl Default for LinkedValidityProfile {
    fn default() -> Self { Self { steps: MIN_ROWS, pow_bits: POW_BITS_RUNTIME } }
}

/// Instantánea de un lote construido localmente; solo la prueba se aporta después.
#[derive(Clone, Serialize, Deserialize)]
struct KnownBatch {
    batch: L2Batch,
    /// Every attempt stays reserved for this immutable local batch.
    l1_tx_hashes: Vec<Hash256>,
}

/// Active Chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveChainConfig {
    /// Sequencer configuration; its chain_id also fixes the execution domain.
    pub sequencer: SequencerConfig,
    /// Verification mode
    pub verification_mode: VerificationMode,
    /// Block time (ms)
    pub block_time_ms: u64,
    /// Batch submission interval (blocks)
    pub batch_interval_blocks: u64,
    /// Perfil del AIR ilustrativo, independiente de los mensajes entrantes.
    pub validity_profile: LinkedValidityProfile,
}

impl Default for ActiveChainConfig {
    fn default() -> Self {
        Self {
            sequencer: SequencerConfig::default(),
            verification_mode: VerificationMode::Optimistic,
            block_time_ms: 2000, // 2 seconds
            batch_interval_blocks: 100,
            validity_profile: LinkedValidityProfile::default(),
        }
    }
}

/// The Active Chain (L2)
pub struct ActiveChain {
    /// Serializa ejecución, alturas y captura de raíces por bloque.
    production: Mutex<()>,
    /// Contextos locales inmutables y control de envío único por índice.
    known_batches: RwLock<HashMap<u64, KnownBatch>>,
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

#[derive(Serialize, Deserialize)]
struct ActiveCheckpoint {
    version: u32,
    publisher: Address,
    config: ActiveChainConfig,
    execution: Vec<u8>,
    sequencer: Vec<u8>,
    verifier: Vec<u8>,
    builder: Vec<u8>,
    submitter: Vec<u8>,
    known: HashMap<u64, KnownBatch>,
    blocks: HashMap<Hash256, Block>,
    heights: HashMap<BlockHeight, Hash256>,
    height: BlockHeight,
    l1_reference: BlockHeight,
    genesis: Block,
}

impl ActiveChain {
    /// Local genesis allocation for reproducible experiments; commits its account root in genesis.
    pub fn with_genesis_balances(config: ActiveChainConfig, keypair: DilithiumKeypair,
        balances: &[(Address, nexus_core::Amount)]) -> Result<Self, NexusError> {
        let mut chain = Self::new(config, keypair);
        for (address, balance) in balances {
            let mut execution = chain.execution.write();
            if execution.state().account_exists(address) {
                return Err(NexusError::ConfigError("Duplicate genesis allocation".into()));
            }
            execution.state_mut().set_account(*address, nexus_core::AccountState::with_balance(*balance));
        }
        chain.genesis.header.state_root = chain.state_root().0;
        *chain.blocks.write() = HashMap::from([(chain.genesis.hash(), chain.genesis.clone())]);
        *chain.blocks_by_height.write() = HashMap::from([(BlockHeight::GENESIS, chain.genesis.hash())]);
        Ok(chain)
    }

    /// Trusted local checkpoint only. No secret key or new proof/finality claim is serialized.
    pub fn export_checkpoint(&self) -> Result<Vec<u8>, NexusError> {
        use nexus_core::checkpoint::encode;
        let _production = self.production.lock();
        let known = self.known_batches.write();
        let execution = self.execution.read();
        let verifier = self.verifier.read();
        let builder = self.batch_builder.read();
        let submitter = self.batch_submitter.read();
        let snapshot = ActiveCheckpoint { version: 1, publisher: self.sequencer.address(), config: self.config.clone(),
            execution: encode(&*execution)?, sequencer: self.sequencer.checkpoint()?, verifier: encode(&*verifier)?,
            builder: encode(&*builder)?, submitter: encode(&*submitter)?, known: known.clone(),
            blocks: self.blocks.read().clone(), heights: self.blocks_by_height.read().clone(),
            height: self.height(), l1_reference: *self.l1_reference.read(), genesis: self.genesis.clone() };
        encode(&snapshot)
    }

    pub fn restore_checkpoint(bytes: &[u8], keypair: DilithiumKeypair,
        expected: &ActiveChainConfig) -> Result<Self, NexusError> {
        use nexus_core::checkpoint::{decode, encode};
        let snapshot: ActiveCheckpoint = decode(bytes)?;
        if snapshot.version != 1 || snapshot.publisher != keypair.address() || encode(&snapshot.config)? != encode(expected)? {
            return Err(NexusError::ConfigError("Checkpoint identity, version or L2 policy differs".into()));
        }
        LinkedValidityProfile::new(expected.validity_profile.steps, expected.validity_profile.pow_bits)?;
        if expected.batch_interval_blocks == 0 { return Err(NexusError::ConfigError("Invalid checkpoint batch interval".into())); }
        let execution = ExecutionEngine::restore_checkpoint(&snapshot.execution, expected.sequencer.chain_id)?;
        let sequencer = NexusSequencer::restore_checkpoint(&snapshot.sequencer, expected.sequencer.clone(), keypair, execution.state())?;
        nexus_core::checkpoint::validate_blocks(&snapshot.blocks, &snapshot.heights, snapshot.height,
            &snapshot.genesis, Layer::Active, execution.state_root())?;
        Ok(Self { production: Mutex::new(()), known_batches: RwLock::new(snapshot.known), config: snapshot.config,
            sequencer: Arc::new(sequencer), execution: Arc::new(RwLock::new(execution)),
            verifier: Arc::new(RwLock::new(decode(&snapshot.verifier)?)),
            batch_builder: Arc::new(RwLock::new(decode(&snapshot.builder)?)),
            batch_submitter: Arc::new(RwLock::new(decode(&snapshot.submitter)?)),
            blocks: Arc::new(RwLock::new(snapshot.blocks)), blocks_by_height: Arc::new(RwLock::new(snapshot.heights)),
            height: Arc::new(RwLock::new(snapshot.height)), l1_reference: Arc::new(RwLock::new(snapshot.l1_reference)),
            genesis: snapshot.genesis })
    }

    /// Create a new Active Chain
    pub fn new(config: ActiveChainConfig, keypair: DilithiumKeypair) -> Self {
        let sequencer = Arc::new(NexusSequencer::new(config.sequencer.clone(), keypair));
        let execution = Arc::new(RwLock::new(ExecutionEngine::for_chain(config.sequencer.chain_id)));
        let verifier = Arc::new(RwLock::new(NitroVerifier::new(config.verification_mode)));

        let genesis = Block::genesis(Layer::Active);
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis.clone());

        let mut blocks_by_height = HashMap::new();
        blocks_by_height.insert(BlockHeight::GENESIS, genesis_hash);

        Self {
            production: Mutex::new(()),
            known_batches: RwLock::new(HashMap::new()),
            // El prefijo LE de longitud ocupa ocho bytes en el formato fijado.
            batch_builder: Arc::new(RwLock::new(BatchBuilder::with_limits(
                config.sequencer.max_batch_size, config.sequencer.max_batch_bytes.saturating_add(8)))),
            config,
            sequencer,
            execution,
            verifier,
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
        let _production = self.production.lock();
        if self.config.batch_interval_blocks == 0 {
            return Err(NexusError::ConfigError("El intervalo de lotes debe ser positivo".into()));
        }
        let current = self.height();
        let height = BlockHeight(current.0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Se agotaron las alturas".into()))?);
        let parent_hash = self.blocks_by_height.read().get(&current).copied()
            .ok_or(NexusError::BlockHeightNotFound(current))?;
        // Build batch from sequencer
        let batch = self.sequencer.build_batch()?;

        let transactions = batch.map(|b| b.transactions).unwrap_or_default();

        if transactions.is_empty() {
            // Return empty block
            return self.create_empty_block(height, parent_hash);
        }

        // Se captura la raíz anterior antes de ejecutar; el bloque entra entero al lote.
        let pre_state = self.execution.read().state_root();
        if let Err(error) = self.prepare_batch(&transactions, pre_state, height) {
            self.sequencer.release_transactions(&transactions);
            return Err(error);
        }
        let (results, post_state) = {
            let mut execution = self.execution.write();
            let results = execution.execute_batch(&transactions);
            (results, execution.state_root())
        };
        self.sequencer.complete_execution(&transactions, &results)?;

        let header = BlockHeader {
            version: nexus_core::PROTOCOL_VERSION,
            height,
            timestamp: Timestamp::now(),
            parent_hash,
            transactions_root: self.compute_tx_root(&transactions),
            state_root: post_state.0,
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

        self.finish_batch_if_due(height, post_state)?;

        Ok(block)
    }

    /// Create empty block
    fn create_empty_block(&self, height: BlockHeight, parent_hash: Hash256) -> Result<Block, NexusError> {
        let state = self.execution.read().state_root();
        let mut header = BlockHeader::new(height, parent_hash, self.sequencer.address(), Layer::Active);
        header.state_root = state.0;
        let body = BlockBody::new(Vec::new());
        let block = Block::new(header, body);

        self.store_block(block.clone())?;
        self.finish_batch_if_due(height, state)?;
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

    /// Reserva el bloque antes de ejecutarlo y rota únicamente entre bloques completos.
    fn prepare_batch(&self, transactions: &[SignedTransaction], pre: StateRoot, height: BlockHeight)
        -> Result<(), NexusError> {
        let mut builder = self.batch_builder.write();
        builder.check_block_capacity(transactions)?;
        if builder.pending_count() == 0 {
            builder.start_batch(pre, height);
        }
        match builder.add_transactions(transactions) {
            Ok(()) => Ok(()),
            Err(NexusError::BatchTooLarge) => {
                let batch = builder.finalize_batch(pre, BlockHeight(height.0 - 1))?;
                self.queue_local_batch(batch)?;
                builder.start_batch(pre, height);
                builder.add_transactions(transactions)
            }
            Err(error) => Err(error),
        }
    }

    fn finish_batch_if_due(&self, height: BlockHeight, post: StateRoot) -> Result<(), NexusError> {
        let mut builder = self.batch_builder.write();
        if height.0 % self.config.batch_interval_blocks == 0 && builder.pending_count() > 0 {
            let batch = builder.finalize_batch(post, height)?;
            self.queue_local_batch(batch)?;
        }
        Ok(())
    }

    /// Solo se registran aquí lotes construidos por la cadena, nunca mensajes externos.
    fn queue_local_batch(&self, batch: L2Batch) -> Result<(), NexusError> {
        let mut known = self.known_batches.write();
        if known.contains_key(&batch.index) {
            return Err(NexusError::StateError("Índice local de lote repetido".into()));
        }
        known.insert(batch.index, KnownBatch { batch: batch.clone(), l1_tx_hashes: Vec::new() });
        self.batch_submitter.write().queue(batch);
        Ok(())
    }

    /// Obtiene trabajo para el probador; no autoriza envío ni acredita validez.
    pub fn get_next_batch(&self) -> Option<L2Batch> {
        self.batch_submitter.write().next_to_submit()
    }

    /// Recupera la instantánea local incluso después de un intento rechazado.
    pub fn get_known_batch(&self, index: u64) -> Option<L2Batch> {
        self.known_batches.read().get(&index).map(|known| known.batch.clone())
    }

    fn check_known_batch<'a>(batch: &L2Batch, known: &'a HashMap<u64, KnownBatch>)
        -> Result<&'a KnownBatch, NexusError> {
        let entry = known.get(&batch.index)
            .ok_or_else(|| NexusError::SecurityViolation("Lote desconocido para esta cadena".into()))?;
        let local = &entry.batch;
        if batch.block_range != local.block_range || batch.tx_count != local.tx_count
            || batch.pre_state_root != local.pre_state_root || batch.post_state_root != local.post_state_root
            || batch.compressed_data != local.compressed_data || batch.batch_hash != local.batch_hash
            || batch.created_at != local.created_at || batch.signature != local.signature {
            return Err(NexusError::SecurityViolation("El lote difiere de la instantánea local".into()));
        }
        Ok(entry)
    }

    fn expected_for_local_batch(&self, batch: &L2Batch) -> ExpectedTransition {
        ExpectedTransition { pre: batch.pre_state_root, post: batch.post_state_root,
            height: batch.block_range.1, steps: self.config.validity_profile.steps,
            pow_bits: self.config.validity_profile.pow_bits }
    }

    fn state_proof_with_context(&self, batch: &L2Batch, expected: &ExpectedTransition)
        -> Result<StateProof, NexusError> {
        let optimistic = self.config.verification_mode == VerificationMode::Optimistic;
        let data = match &batch.validity_proof {
            Some(bytes) if optimistic || bytes.len() <= MAX_CERTIFICATE_BYTES => bytes.clone(),
            Some(_) => return Err(NexusError::InvalidProofFormat),
            None if optimistic => Vec::new(),
            None => return Err(NexusError::InvalidProofFormat),
        };
        Ok(StateProof { proof_type: if optimistic { ProofType::Optimistic } else { ProofType::ZKValidity },
            pre_state_root: expected.pre, post_state_root: expected.post, height: expected.height,
            proof_data: data, public_inputs: public_inputs(expected) })
    }

    /// Prepare a signed L1 transaction from immutable local batch context.
    /// A scratch verifier checks admissibility without registering proof or submission effects.
    pub fn prepare_l1_submission(&self, batch: &L2Batch, l1: &AnchorChain,
        signer: &DilithiumKeypair, options: L1SubmissionOptions) -> Result<SignedTransaction, NexusError> {
        let known = self.known_batches.read();
        let entry = Self::check_known_batch(batch, &known)?;
        if self.batch_submitter.read().get_confirmation(batch.index).is_some() {
            return Err(NexusError::SecurityViolation("Local batch is already confirmed".into()));
        }
        if signer.address() != self.sequencer.address() {
            return Err(NexusError::SecurityViolation("L1 publisher differs from the local sequencer".into()));
        }
        let expected = self.expected_for_local_batch(&entry.batch);
        if self.verifier.read().get_verified_root(expected.height).is_some_and(|root| root != expected.post) {
            return Err(NexusError::SecurityViolation("Conflicting verified root at the local batch height".into()));
        }
        let proof = self.state_proof_with_context(batch, &expected)?;
        let mut checker = NitroVerifier::new(self.config.verification_mode);
        let result = if self.config.verification_mode == VerificationMode::Optimistic {
            checker.verify(&proof)?
        } else { checker.verify_expected(&proof, &expected)? };
        if !result.valid { return Err(NexusError::ProofVerificationFailed); }
        let count = u32::try_from(entry.batch.tx_count)
            .map_err(|_| NexusError::BatchTooLarge)?;
        l1.prepare_batch_submission(signer, entry.batch.post_state_root, count,
            entry.batch.compressed_data.clone(), options)
    }

    /// Hash-only local intent after L2 proof checks; this does not validate an L1 packet.
    /// Prefer register_l1_submission for L1 preflight and exact signed packet retention.
    pub fn mark_batch_submitted(&self, batch: L2Batch, l1_tx_hash: Hash256) -> Result<(), NexusError> {
        let mut known = self.known_batches.write();
        self.record_batch_submission(batch, l1_tx_hash, None, &mut known)
    }

    /// Register the actual signed packet after L1 admission and local batch checks.
    pub fn register_l1_submission(&self, batch: L2Batch, transaction: &SignedTransaction,
        l1: &AnchorChain) -> Result<Hash256, NexusError> {
        let mut known = self.known_batches.write();
        let entry = Self::check_known_batch(&batch, &known)?;
        self.check_l1_packet(&entry.batch, transaction)?;
        l1.validate_batch_submission(transaction)?;
        let bytes = bincode::serialize(transaction)?;
        let hash = transaction.hash();
        self.record_batch_submission(batch, hash, Some(bytes), &mut known)?;
        Ok(hash)
    }

    /// Recover an omitted initial registration after the exact packet was processed by trusted L1.
    /// Requires an existing local batch with no attempts; this is local inclusion, not BFT finality.
    pub fn recover_l1_submission(&self, batch: L2Batch, transaction: &SignedTransaction,
        l1: &AnchorChain) -> Result<ConfirmedBatch, NexusError> {
        let mut known = self.known_batches.write();
        let entry = Self::check_known_batch(&batch, &known)?;
        self.check_l1_packet(&entry.batch, transaction)?;
        let inclusion = l1.validate_processed_batch_submission(transaction)?;
        let bytes = bincode::serialize(transaction)?;
        let hash = transaction.hash();
        self.verify_initial_submission(&batch, hash, &known)?;
        // All fallible checks precede publishing the single confirmed record.
        let index = batch.index;
        let confirmed = self.batch_submitter.write().record_recovered(batch, hash, bytes,
            inclusion.block_hash, inclusion.block_height);
        known.get_mut(&index).expect("context held under write lock").l1_tx_hashes.push(hash);
        Ok(confirmed)
    }

    fn check_l1_packet(&self, batch: &L2Batch, transaction: &SignedTransaction) -> Result<(), NexusError> {
        let matches = match &transaction.transaction.tx_type {
            nexus_core::TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } =>
                *batch_root == batch.post_state_root.0 && usize::try_from(*batch_size).ok() == Some(batch.tx_count)
                    && compressed_data == &batch.compressed_data,
            _ => false,
        };
        if transaction.sender != self.sequencer.address() || !matches {
            return Err(NexusError::SecurityViolation("Signed L1 packet differs from the local batch or publisher".into()));
        }
        Ok(())
    }

    fn record_batch_submission(&self, batch: L2Batch, l1_tx_hash: Hash256,
        bytes: Option<Vec<u8>>, known: &mut HashMap<u64, KnownBatch>) -> Result<(), NexusError> {
        self.verify_initial_submission(&batch, l1_tx_hash, known)?;
        let entry = known.get_mut(&batch.index).expect("context held under write lock");
        self.batch_submitter.write().record_submitted(batch, l1_tx_hash, bytes);
        entry.l1_tx_hashes.push(l1_tx_hash);
        Ok(())
    }

    fn verify_initial_submission(&self, batch: &L2Batch, l1_tx_hash: Hash256,
        known: &HashMap<u64, KnownBatch>) -> Result<(), NexusError> {
        let entry = Self::check_known_batch(batch, known)?;
        if l1_tx_hash == Hash256::ZERO || known.values().any(|entry| entry.l1_tx_hashes.contains(&l1_tx_hash)) {
            return Err(NexusError::SecurityViolation("Empty or already assigned L1 transaction hash".into()));
        }
        if !entry.l1_tx_hashes.is_empty() {
            return Err(NexusError::SecurityViolation("El lote ya fue enviado".into()));
        }
        let expected = self.expected_for_local_batch(&entry.batch);
        let proof = self.state_proof_with_context(batch, &expected)?;
        let result = if self.config.verification_mode == VerificationMode::Optimistic {
            self.verifier.write().verify(&proof)?
        } else {
            self.verifier.write().verify_expected(&proof, &expected)?
        };
        if !result.valid { return Err(NexusError::ProofVerificationFailed); }
        Ok(())
    }

    /// Hash-only replacement intent; retry_l1_submission also validates and retains a signed packet.
    pub fn retry_batch_submission(&self, batch_index: u64, expected_hash: Hash256,
        next_hash: Hash256) -> Result<(), NexusError> {
        let mut known = self.known_batches.write();
        self.record_retry(batch_index, expected_hash, next_hash, None, &mut known)
    }

    pub fn retry_l1_submission(&self, batch_index: u64, expected_hash: Hash256,
        transaction: &SignedTransaction, l1: &AnchorChain) -> Result<Hash256, NexusError> {
        let mut known = self.known_batches.write();
        let entry = known.get(&batch_index)
            .ok_or_else(|| NexusError::SecurityViolation("Unknown local batch".into()))?;
        self.check_l1_packet(&entry.batch, transaction)?;
        l1.validate_batch_submission(transaction)?;
        let bytes = bincode::serialize(transaction)?;
        let hash = transaction.hash();
        self.record_retry(batch_index, expected_hash, hash, Some(bytes), &mut known)?;
        Ok(hash)
    }

    /// Recover an omitted replacement registration and observe that exact packet's local inclusion.
    /// Preserves prior attempts and the accepted L2 certificate; requires a current pending attempt.
    pub fn recover_l1_retry(&self, batch_index: u64, expected_hash: Hash256,
        transaction: &SignedTransaction, l1: &AnchorChain) -> Result<ConfirmedBatch, NexusError> {
        let mut known = self.known_batches.write();
        let entry = known.get(&batch_index)
            .ok_or_else(|| NexusError::SecurityViolation("Unknown local batch".into()))?;
        self.check_l1_packet(&entry.batch, transaction)?;
        let inclusion = l1.validate_processed_batch_submission(transaction)?;
        let bytes = bincode::serialize(transaction)?;
        let hash = transaction.hash();
        Self::check_retry_hashes(batch_index, expected_hash, hash, &known)?;
        let confirmed = self.batch_submitter.write().recover_retry(batch_index, expected_hash, hash,
            bytes, inclusion.block_hash, inclusion.block_height)?;
        known.get_mut(&batch_index).expect("context held under write lock").l1_tx_hashes.push(hash);
        Ok(confirmed)
    }

    fn record_retry(&self, batch_index: u64, expected_hash: Hash256, next_hash: Hash256,
        bytes: Option<Vec<u8>>, known: &mut HashMap<u64, KnownBatch>) -> Result<(), NexusError> {
        Self::check_retry_hashes(batch_index, expected_hash, next_hash, known)?;
        self.batch_submitter.write().retry_submission(batch_index, expected_hash, next_hash, bytes)?;
        known.get_mut(&batch_index).expect("context held under write lock").l1_tx_hashes.push(next_hash);
        Ok(())
    }

    fn check_retry_hashes(batch_index: u64, expected_hash: Hash256, next_hash: Hash256,
        known: &HashMap<u64, KnownBatch>) -> Result<(), NexusError> {
        let entry = known.get(&batch_index)
            .ok_or_else(|| NexusError::SecurityViolation("Unknown local batch".into()))?;
        if entry.l1_tx_hashes.last().copied() != Some(expected_hash) {
            return Err(NexusError::BatchSubmissionFailed("Stale or absent submission attempt".into()));
        }
        if next_hash == Hash256::ZERO || known.values().any(|entry| entry.l1_tx_hashes.contains(&next_hash)) {
            return Err(NexusError::SecurityViolation("Empty or already assigned L1 transaction hash".into()));
        }
        Ok(())
    }

    pub fn get_batch_submission(&self, batch_index: u64) -> Option<SubmittedBatch> {
        self.batch_submitter.read().get_submission(batch_index)
    }

    /// Recover exact signed bytes without re-signing; current admissibility still requires validation.
    pub fn get_l1_submission_transaction(&self, batch_index: u64, hash: Hash256) -> Result<SignedTransaction, NexusError> {
        let bytes = self.batch_submitter.read().get_transaction_bytes(batch_index, hash)
            .ok_or_else(|| NexusError::BatchSubmissionFailed("No signed packet recorded for this attempt".into()))?;
        bincode::deserialize(&bytes).map_err(Into::into)
    }

    /// Confirm local inclusion using a trusted L1 instance supplied by the integration.
    /// This neither establishes BFT finality nor promotes an optimistic root to verified.
    pub fn mark_batch_confirmed(&self, batch_index: u64, l1: &AnchorChain) -> Result<ConfirmedBatch, NexusError> {
        let known = self.known_batches.read();
        let entry = known.get(&batch_index)
            .ok_or_else(|| NexusError::SecurityViolation("Unknown local batch".into()))?;
        let mut matched = None;
        // Prefer the earliest recorded matching inclusion, including delayed old attempts.
        for tx_hash in &entry.l1_tx_hashes {
            if let Some(inclusion) = l1.find_processed_batch_inclusion(tx_hash)? {
                if inclusion.transaction_hash == *tx_hash && inclusion.sender == self.sequencer.address()
                    && inclusion.batch_root == entry.batch.post_state_root
                    && usize::try_from(inclusion.batch_size).ok() == Some(entry.batch.tx_count)
                    && inclusion.data == entry.batch.compressed_data {
                    matched = Some(inclusion);
                    break;
                }
            }
        }
        let inclusion = matched.ok_or_else(|| NexusError::SecurityViolation("No recorded attempt has matching processed L1 inclusion".into()))?;
        self.batch_submitter.write().mark_confirmed(batch_index, inclusion.transaction_hash, inclusion.block_hash, inclusion.block_height)
            .ok_or_else(|| NexusError::SecurityViolation("Batch already confirmed or submission no longer pending".into()))
    }

    pub fn get_batch_confirmation(&self, batch_index: u64) -> Option<ConfirmedBatch> {
        self.batch_submitter.read().get_confirmation(batch_index)
    }

    /// Construye el sobre desde la instantánea local, sin deducir política de la prueba.
    pub fn create_state_proof(&self, batch: &L2Batch) -> Result<StateProof, NexusError> {
        let known = self.known_batches.read();
        let entry = Self::check_known_batch(batch, &known)?;
        self.state_proof_with_context(batch, &self.expected_for_local_batch(&entry.batch))
    }

    /// Ruta de validez/híbrido; el mensaje no proporciona el contexto confiable.
    pub fn verify_state_proof(&self, batch: &L2Batch, proof: &StateProof)
        -> Result<VerificationResult, NexusError> {
        let known = self.known_batches.read();
        let entry = Self::check_known_batch(batch, &known)?;
        let expected = self.expected_for_local_batch(&entry.batch);
        self.verifier.write().verify_expected(proof, &expected)
    }

    pub fn verified_state_root(&self, height: BlockHeight) -> Option<StateRoot> {
        self.verifier.read().get_verified_root(height)
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

    pub fn get_account(&self, address: &Address) -> Option<nexus_core::AccountState> {
        self.execution.read().get_account(address).cloned()
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
    fn configured_transaction_domain_is_shared_by_admission_and_block_execution() {
        use nexus_core::{AccountState, Amount, ChainId, Nonce, Transaction};
        use nexus_crypto::Signer;
        let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let config = ActiveChainConfig {
            sequencer: SequencerConfig { chain_id: ChainId::TESTNET, ..Default::default() },
            batch_interval_blocks: 1,
            ..Default::default()
        };
        let chain = ActiveChain::new(config, DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        chain.execution.write().state_mut().set_account(signer.address(),
            AccountState::with_balance(Amount::from_units(100)));
        let receiver = Address::new([42; 32]);
        let tx = |domain| signer.sign_transaction(Transaction::transfer(domain, Nonce(0), receiver,
            Amount(7), 21000, Amount(1_000_000_000))).unwrap();
        let before = chain.state_root();
        assert!(matches!(chain.submit_transaction(tx(ChainId::LOCAL)), Err(NexusError::InvalidChainId)));
        assert_eq!(chain.state_root(), before);
        let honest = tx(ChainId::TESTNET);
        chain.submit_transaction(honest.clone()).unwrap();
        let block = chain.produce_block().unwrap();
        let mut expected = InMemoryState::new();
        let mut sender = AccountState::with_balance(Amount(Amount::from_units(100).0 - 7));
        sender.nonce = Nonce(1);
        expected.set_account(signer.address(), sender);
        expected.set_account(receiver, AccountState::with_balance(Amount(7)));
        assert_eq!(block.header.state_root, expected.compute_root().0);
        assert_eq!(chain.state_root(), expected.compute_root());
        assert_eq!(block.transaction_hashes(), vec![honest.hash()]);
        assert_eq!(chain.height(), BlockHeight(1));
        assert_eq!(chain.sequencer().pending_count(), 0);
        assert!(matches!(chain.submit_transaction(honest), Err(NexusError::InvalidNonce { expected: 1, got: 0 })));
        let batch = chain.get_known_batch(0).unwrap();
        assert_eq!(batch.pre_state_root, before);
        assert_eq!(batch.post_state_root, chain.state_root());
        assert_eq!(batch.tx_count, 1);
    }

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

    fn scalar_fixture() -> L2Batch {
        use crate::linked_verifier::{LinkedValidityProof, scalar_root};
        use nexus_zk::stark::field::Felt;
        use std::sync::OnceLock;
        static CASE: OnceLock<L2Batch> = OnceLock::new();
        CASE.get_or_init(|| {
            let pre = scalar_root(Felt::new(3));
            let linked = LinkedValidityProof::prove(&pre, 5, 16).unwrap();
            let mut batch = L2Batch { index: 9, block_range: (BlockHeight(40), BlockHeight(42)),
                tx_count: 0, compressed_data: Vec::new(), pre_state_root: pre,
                post_state_root: linked.post_root(), batch_hash: Hash256::ZERO,
                created_at: Timestamp::from_millis(0), signature: None,
                validity_proof: Some(linked.to_bytes().unwrap()) };
            batch.batch_hash = batch.compute_hash();
            batch
        }).clone()
    }

    fn validity_chain(profile: LinkedValidityProfile) -> ActiveChain {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let mut config = ActiveChainConfig::default();
        config.verification_mode = VerificationMode::ZKValidity;
        config.validity_profile = profile;
        ActiveChain::new(config, keypair)
    }

    #[tokio::test]
    async fn local_checkpoint_preserves_an_accepted_scalar_certificate_and_verified_root() {
        // Synthetic scalar context only; not an AIR proof of account execution.
        let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let config = ActiveChainConfig { verification_mode: VerificationMode::ZKValidity, ..Default::default() };
        let chain = ActiveChain::new(config.clone(), publisher.clone());
        let local = scalar_fixture(); chain.queue_local_batch(local.clone()).unwrap();
        let hash = Hash256::hash(b"checkpoint scalar attempt");
        chain.mark_batch_submitted(local.clone(), hash).unwrap();
        let bytes = chain.export_checkpoint().unwrap();
        let restored = ActiveChain::restore_checkpoint(&bytes, publisher, &config).unwrap();
        assert_eq!(restored.verified_state_root(local.block_range.1), Some(local.post_state_root));
        assert_eq!(restored.get_batch_submission(local.index).unwrap().batch.validity_proof, local.validity_proof);
        restored.retry_batch_submission(local.index, hash, Hash256::hash(b"next scalar attempt")).unwrap();
        assert_eq!(restored.get_batch_submission(local.index).unwrap().attempts.len(), 2);
        assert_eq!(restored.verified_state_root(local.block_range.1), Some(local.post_state_root));
    }

    #[tokio::test]
    async fn recovering_a_processed_retry_preserves_the_accepted_scalar_certificate() {
        use nexus_core::{Amount, ChainId, Nonce, Transaction};
        use nexus_crypto::Signer;
        // Synthetic scalar context only; its opaque DA bytes are not L2 execution authenticated.
        let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig { verification_mode: VerificationMode::ZKValidity,
            ..Default::default() }, publisher.clone());
        let mut local = scalar_fixture();
        local.tx_count = 1; local.compressed_data = vec![1]; local.batch_hash = local.compute_hash();
        chain.queue_local_batch(local.clone()).unwrap();
        let l1 = AnchorChain::new(Default::default(), DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
        chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
        let before = chain.get_batch_submission(local.index).unwrap();
        assert_eq!(chain.verified_state_root(local.block_range.1), Some(local.post_state_root));
        let other = publisher.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
            Address::ZERO, Amount::ZERO, 21000, Amount::ZERO)).unwrap();
        l1.process_block(l1.prepare_block(vec![other], Address::ZERO).unwrap()).await.unwrap();
        let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        let mut forged = signed.clone(); forged.public_key[0] ^= 1;
        assert!(chain.recover_l1_retry(local.index, initial.hash(), &forged, &l1).is_err());
        assert!(chain.recover_l1_retry(local.index, Hash256::ZERO, &signed, &l1).is_err());
        assert_eq!(chain.get_batch_submission(local.index).unwrap().attempts, before.attempts);
        assert!(chain.get_batch_confirmation(local.index).is_none());
        let confirmed = chain.recover_l1_retry(local.index, initial.hash(), &signed, &l1).unwrap();
        assert_eq!(confirmed.batch.validity_proof, local.validity_proof);
        assert_eq!(confirmed.batch.batch_hash, local.batch_hash);
        assert_eq!(&confirmed.attempts[..1], &before.attempts);
        assert_eq!(chain.verified_state_root(local.block_range.1), Some(local.post_state_root));
        assert_eq!(chain.stats().confirmed_batches, 1);
    }

    #[tokio::test]
    async fn processed_recovery_checks_l1_before_registering_a_valid_scalar_root() {
        // Scalar fixture only: canonical inclusion does not authenticate DA as L2 execution.
        let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig { verification_mode: VerificationMode::ZKValidity,
            ..Default::default() }, publisher.clone());
        let mut local = scalar_fixture();
        local.tx_count = 1; local.compressed_data = vec![1]; local.batch_hash = local.compute_hash();
        chain.queue_local_batch(local.clone()).unwrap();
        let l1 = AnchorChain::new(Default::default(), DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
        assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        let mut forged = signed.clone(); forged.public_key[0] ^= 1;
        assert!(chain.recover_l1_submission(local.clone(), &forged, &l1).is_err());
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        let mut bad_certificate = local.clone(); bad_certificate.validity_proof = Some(vec![0; 4096]);
        assert!(chain.recover_l1_submission(bad_certificate, &signed, &l1).is_err());
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        assert!(chain.get_batch_confirmation(local.index).is_none());
        assert!(chain.get_batch_submission(local.index).is_none());
        let confirmed = chain.recover_l1_submission(local.clone(), &signed, &l1).unwrap();
        assert_eq!(chain.verified_state_root(local.block_range.1), Some(local.post_state_root));
        assert_eq!(confirmed.batch.validity_proof, local.validity_proof);
        assert_eq!(chain.stats().confirmed_batches, 1);
    }

    #[test]
    fn l1_registration_failure_does_not_register_a_valid_scalar_root() {
        // Synthetic scalar fixture only; opaque DA bytes are not execution authenticated by this AIR.
        let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig { verification_mode: VerificationMode::ZKValidity,
            ..Default::default() }, publisher.clone());
        let mut local = scalar_fixture();
        local.tx_count = 1; local.compressed_data = vec![1]; local.batch_hash = local.compute_hash();
        chain.queue_local_batch(local.clone()).unwrap();
        let l1 = AnchorChain::new(Default::default(), DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
        let restrictive = AnchorChain::new(nexus_anchor::AnchorChainConfig { block_gas_limit: 0, ..Default::default() },
            DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        assert!(chain.register_l1_submission(local.clone(), &signed, &restrictive).is_err());
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        assert!(chain.get_batch_submission(local.index).is_none());
        chain.register_l1_submission(local.clone(), &signed, &l1).unwrap();
        assert_eq!(chain.verified_state_root(local.block_range.1), Some(local.post_state_root));
        assert_eq!(bincode::serialize(&chain.get_l1_submission_transaction(local.index, signed.hash()).unwrap()).unwrap(),
            bincode::serialize(&signed).unwrap());
    }

    #[test]
    fn preparing_a_valid_scalar_fixture_does_not_register_its_root_or_submission() {
        // Synthetic caller context only: the scalar AIR does not authenticate these opaque bytes.
        let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = ActiveChain::new(ActiveChainConfig { verification_mode: VerificationMode::ZKValidity,
            ..Default::default() }, publisher.clone());
        let mut local = scalar_fixture();
        local.compressed_data = vec![1];
        local.tx_count = 1;
        local.batch_hash = local.compute_hash();
        chain.queue_local_batch(local.clone()).unwrap();
        let l1 = AnchorChain::new(Default::default(), DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        let prepared = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        assert!(chain.get_batch_submission(local.index).is_none());
        assert_eq!(chain.stats().pending_batches, 1);
        assert_eq!(l1.height(), BlockHeight::GENESIS);
        assert!(l1.get_account(&publisher.address()).is_none());
        chain.mark_batch_submitted(local.clone(), prepared.hash()).unwrap();
        assert_eq!(chain.verified_state_root(local.block_range.1), Some(local.post_state_root));
    }

    #[test]
    fn submission_retries_preserve_the_validity_certificate_and_local_context() {
        let proved = scalar_fixture();
        let mut local = proved.clone();
        local.validity_proof = None;
        let chain = validity_chain(LinkedValidityProfile::default());
        chain.queue_local_batch(local.clone()).unwrap();
        let initial = Hash256::hash(b"initial scalar intent");
        let replacement = Hash256::hash(b"replacement scalar intent");
        chain.mark_batch_submitted(proved.clone(), initial).unwrap();
        chain.retry_batch_submission(proved.index, initial, replacement).unwrap();
        let pending = chain.get_batch_submission(proved.index).unwrap();
        assert_eq!(bincode::serialize(&pending.batch).unwrap(), bincode::serialize(&proved).unwrap());
        assert_eq!(bincode::serialize(&chain.get_known_batch(proved.index).unwrap()).unwrap(),
            bincode::serialize(&local).unwrap());
        assert_eq!(chain.verified_state_root(proved.block_range.1), Some(proved.post_state_root));
        assert_eq!(pending.attempts.len(), 2);
        assert_eq!(pending.retries, 1);
        assert_eq!(pending.l1_tx_hash, replacement);
        assert_eq!(chain.stats().confirmed_batches, 0);
    }

    #[test]
    fn cableado_escalar_sintetico_verifica_antes_del_envio_y_no_confunde_indice_con_altura() {
        // Solo ejercita el cableado: esta instantánea sintética no representa transacciones L2.
        let batch = scalar_fixture();
        let chain = validity_chain(LinkedValidityProfile::default());
        chain.queue_local_batch(batch.clone()).unwrap();
        let proof = chain.create_state_proof(&batch).unwrap();
        assert_eq!(proof.public_inputs.len(), 72);
        assert!(chain.verify_state_proof(&batch, &proof).unwrap().valid);
        chain.mark_batch_submitted(batch.clone(), Hash256::hash(b"envio sintetico")).unwrap();
        assert_eq!(chain.verified_state_root(BlockHeight(42)), Some(batch.post_state_root));
        assert!(chain.mark_batch_submitted(batch, Hash256::hash(b"repeticion")).is_err());
        assert_eq!(chain.stats().submitted_batches, 1);
        assert_eq!(chain.stats().pending_batches, 0);
    }

    #[test]
    fn la_cadena_fija_filas_y_trabajo_antes_de_recibir_el_certificado() {
        let batch = scalar_fixture();
        let opposite_bits = if POW_BITS_RUNTIME == 12 { 20 } else { 12 };
        for profile in [LinkedValidityProfile::new(32, POW_BITS_RUNTIME).unwrap(),
            LinkedValidityProfile::new(16, opposite_bits).unwrap()] {
            let chain = validity_chain(profile);
            chain.queue_local_batch(batch.clone()).unwrap();
            let proof = chain.create_state_proof(&batch).unwrap();
            assert!(!chain.verify_state_proof(&batch, &proof).unwrap().valid);
            assert!(chain.mark_batch_submitted(batch.clone(), Hash256::ZERO).is_err());
            assert!(chain.verified_state_root(BlockHeight(42)).is_none());
            assert_eq!(chain.stats().submitted_batches, 0);
        }
        for (steps, bits) in [(0, 12), (15, 12), (17, 12), (8192, 12), (16, 0), (16, 11), (16, 21)] {
            assert!(LinkedValidityProfile::new(steps, bits).is_err());
        }
    }

    #[test]
    fn un_certificado_valido_no_autoriza_lotes_desconocidos_ni_sobres_alterados() {
        let batch = scalar_fixture();
        let chain = validity_chain(LinkedValidityProfile::default());
        assert!(chain.create_state_proof(&batch).is_err());
        chain.queue_local_batch(batch.clone()).unwrap();
        let proof = chain.create_state_proof(&batch).unwrap();
        for case in 0..5 {
            let mut changed = proof.clone();
            match case {
                0 => changed.height = BlockHeight(43),
                1 => changed.pre_state_root = StateRoot::EMPTY,
                2 => changed.post_state_root = StateRoot::EMPTY,
                3 => changed.public_inputs[71] ^= 1,
                _ => changed.proof_type = ProofType::Optimistic,
            }
            assert!(!chain.verify_state_proof(&batch, &changed).unwrap().valid);
            assert!(chain.verified_state_root(BlockHeight(42)).is_none());
        }
    }

    #[test]
    fn certificados_truncados_o_con_sufijos_no_registran_ni_envian_el_lote() {
        let original = scalar_fixture();
        let data = original.validity_proof.as_ref().unwrap();
        for bytes in [Vec::new(), vec![1, 2, 3], data[..40].to_vec(),
            [data.as_slice(), &[0]].concat(), vec![0; MAX_CERTIFICATE_BYTES + 1]] {
            let chain = validity_chain(LinkedValidityProfile::default());
            chain.queue_local_batch(original.clone()).unwrap();
            let mut batch = original.clone();
            batch.validity_proof = Some(bytes);
            assert!(chain.mark_batch_submitted(batch, Hash256::ZERO).is_err());
            assert!(chain.verified_state_root(BlockHeight(42)).is_none());
            assert_eq!(chain.stats().submitted_batches, 0);
            assert!(chain.get_known_batch(original.index).is_some());
        }
    }

    #[test]
    fn envios_simultaneos_del_mismo_lote_solo_registran_un_envio() {
        let chain = Arc::new(validity_chain(LinkedValidityProfile::default()));
        let batch = scalar_fixture();
        chain.queue_local_batch(batch.clone()).unwrap();
        let workers: Vec<_> = (0..4).map(|index| {
            let chain = Arc::clone(&chain);
            let batch = batch.clone();
            std::thread::spawn(move || chain.mark_batch_submitted(batch, Hash256::hash(&[index])).is_ok())
        }).collect();
        let accepted = workers.into_iter().map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted).count();
        assert_eq!(accepted, 1);
        assert_eq!(chain.stats().submitted_batches, 1);
        assert_eq!(chain.stats().pending_batches, 0);
        assert!(chain.verified_state_root(BlockHeight(42)).is_some());
    }
}
