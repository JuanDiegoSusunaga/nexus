//! Prototipo ActiveChain: ejecución, lotes y verificación con contexto local.
//! El contrato Lean escalar no acredita transacciones ni raíces SHA3 generales.

use crate::{
    batch::{BatchBuilder, BatchSubmitter, ConfirmedBatch, L2Batch},
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
use nexus_anchor::AnchorChain;
use nexus_zk::stark::{linked::{MIN_ROWS, MAX_ROWS, MAX_CERTIFICATE_BYTES}, params::POW_BITS_RUNTIME};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;

/// Política local; jamás se extrae del certificado recibido.
#[derive(Debug, Clone, Copy)]
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
struct KnownBatch {
    batch: L2Batch,
    l1_tx_hash: Option<Hash256>,
}

/// Active Chain configuration
#[derive(Debug, Clone)]
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

impl ActiveChain {
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
        known.insert(batch.index, KnownBatch { batch: batch.clone(), l1_tx_hash: None });
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

    /// Verifica antes de marcar el envío; rechazos y duplicados no alteran el registro.
    /// El modo optimista mantiene su aceptación provisional, sin acreditar el contrato Lean.
    pub fn mark_batch_submitted(&self, batch: L2Batch, l1_tx_hash: Hash256) -> Result<(), NexusError> {
        let mut known = self.known_batches.write();
        Self::check_known_batch(&batch, &known)?;
        if l1_tx_hash == Hash256::ZERO || known.values().any(|entry| entry.l1_tx_hash == Some(l1_tx_hash)) {
            return Err(NexusError::SecurityViolation("Empty or already assigned L1 transaction hash".into()));
        }
        let entry = known.get_mut(&batch.index)
            .ok_or_else(|| NexusError::StateError("Se perdió el contexto local del lote".into()))?;
        if entry.l1_tx_hash.is_some() {
            return Err(NexusError::SecurityViolation("El lote ya fue enviado".into()));
        }
        let expected = self.expected_for_local_batch(&entry.batch);
        let proof = self.state_proof_with_context(&batch, &expected)?;
        let result = if self.config.verification_mode == VerificationMode::Optimistic {
            self.verifier.write().verify(&proof)?
        } else {
            self.verifier.write().verify_expected(&proof, &expected)?
        };
        if !result.valid { return Err(NexusError::ProofVerificationFailed); }
        self.batch_submitter.write().mark_submitted(batch, l1_tx_hash);
        entry.l1_tx_hash = Some(l1_tx_hash);
        Ok(())
    }

    /// Confirm local inclusion using a trusted L1 instance supplied by the integration.
    /// This neither establishes BFT finality nor promotes an optimistic root to verified.
    pub fn mark_batch_confirmed(&self, batch_index: u64, l1: &AnchorChain) -> Result<ConfirmedBatch, NexusError> {
        let known = self.known_batches.read();
        let entry = known.get(&batch_index)
            .ok_or_else(|| NexusError::SecurityViolation("Unknown local batch".into()))?;
        let tx_hash = entry.l1_tx_hash
            .ok_or_else(|| NexusError::SecurityViolation("Batch has no recorded L1 submission".into()))?;
        let inclusion = l1.get_processed_batch_inclusion(&tx_hash)?;
        if inclusion.transaction_hash != tx_hash || inclusion.sender != self.sequencer.address()
            || inclusion.batch_root != entry.batch.post_state_root
            || usize::try_from(inclusion.batch_size).ok() != Some(entry.batch.tx_count)
            || inclusion.data != entry.batch.compressed_data {
            return Err(NexusError::SecurityViolation("L1 inclusion differs from the local batch or publisher".into()));
        }
        self.batch_submitter.write().mark_confirmed(batch_index, tx_hash, inclusion.block_hash, inclusion.block_height)
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
