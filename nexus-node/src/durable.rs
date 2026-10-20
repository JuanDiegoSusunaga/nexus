//! Exclusive local L1/L2 runtime. Successful mutations are checkpointed before return.
//! Checkpoints are trusted local state, not proofs against a malicious storage owner.
use nexus_active::{ActiveChain, ActiveChainConfig, ConfirmedBatch, L1SubmissionOptions, L2Batch, SubmittedBatch};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{checkpoint::{self, CheckpointStore}, AccountState, Address, Amount, Block,
    BlockHeight, Hash256, NexusError, SignedTransaction, StateRoot};
use nexus_crypto::DilithiumKeypair;
use serde::{Serialize, Deserialize};
use std::path::Path;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DurableNodeConfig {
    pub active: ActiveChainConfig,
    pub anchor: AnchorChainConfig,
    /// Explicit experimental L2 genesis allocation, not a public mint operation.
    pub genesis_balances: Vec<(Address, Amount)>,
}

#[derive(Serialize, Deserialize)]
struct NodeCheckpoint {
    version: u32,
    publisher: Address,
    config: DurableNodeConfig,
    anchor: Vec<u8>,
    active: Vec<u8>,
}

pub struct DurableNode {
    store: CheckpointStore,
    config: DurableNodeConfig,
    keypair: DilithiumKeypair,
    // Keep chains private: callers cannot acknowledge changes outside the durable boundary.
    anchor: AnchorChain,
    active: ActiveChain,
    poisoned: bool,
}

impl DurableNode {
    pub fn create(directory: &Path, config: DurableNodeConfig, keypair: DilithiumKeypair) -> Result<Self, NexusError> {
        let store = CheckpointStore::create(directory)?;
        let active = ActiveChain::with_genesis_balances(config.active.clone(), keypair.clone(), &config.genesis_balances)?;
        let anchor = AnchorChain::new(config.anchor.clone(), keypair.clone());
        let mut node = Self { store, config, keypair, anchor, active, poisoned: false };
        let bytes = node.snapshot()?;
        // Validate the initial policy and snapshot before publishing generation one.
        node.restore(&bytes)?;
        node.store.commit(&bytes)?;
        Ok(node)
    }

    pub fn open(directory: &Path, expected: DurableNodeConfig, keypair: DilithiumKeypair) -> Result<Self, NexusError> {
        let store = CheckpointStore::open(directory)?;
        let bytes = store.read_latest()?;
        let snapshot: NodeCheckpoint = checkpoint::decode(&bytes)?;
        Self::check_context(&snapshot, &expected, &keypair)?;
        let anchor = AnchorChain::restore_checkpoint(&snapshot.anchor, &expected.anchor)?;
        let active = ActiveChain::restore_checkpoint(&snapshot.active, keypair.clone(), &expected.active)?;
        Ok(Self { store, config: expected, keypair, anchor, active, poisoned: false })
    }

    fn check_context(snapshot: &NodeCheckpoint, config: &DurableNodeConfig, keypair: &DilithiumKeypair) -> Result<(), NexusError> {
        if snapshot.version != 1 || snapshot.publisher != keypair.address()
            || checkpoint::encode(&snapshot.config)? != checkpoint::encode(config)? {
            return Err(NexusError::ConfigError("Checkpoint identity, version or node policy differs".into()));
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<u8>, NexusError> {
        if self.poisoned { return Err(NexusError::StateError("Durable node must be reopened".into())); }
        checkpoint::encode(&NodeCheckpoint { version: 1, publisher: self.keypair.address(), config: self.config.clone(),
            anchor: self.anchor.export_checkpoint()?, active: self.active.export_checkpoint()? })
    }

    fn restore(&mut self, bytes: &[u8]) -> Result<(), NexusError> {
        let snapshot: NodeCheckpoint = checkpoint::decode(bytes)?;
        Self::check_context(&snapshot, &self.config, &self.keypair)?;
        let anchor = AnchorChain::restore_checkpoint(&snapshot.anchor, &self.config.anchor)?;
        let active = ActiveChain::restore_checkpoint(&snapshot.active, self.keypair.clone(), &self.config.active)?;
        self.anchor = anchor; self.active = active;
        Ok(())
    }

    fn finish<T>(&mut self, before: Vec<u8>, operation: Result<T, NexusError>) -> Result<T, NexusError> {
        let result = operation.and_then(|value| {
            let bytes = self.snapshot()?;
            self.store.commit(&bytes)?;
            Ok(value)
        });
        if result.is_err() {
            if let Err(error) = self.restore(&before) {
                self.poisoned = true;
                return Err(NexusError::StateError(format!("Checkpoint rollback failed; reopen node: {error}")));
            }
        }
        result
    }

    fn update<T>(&mut self, operation: impl FnOnce(&ActiveChain, &AnchorChain, &DilithiumKeypair) -> Result<T, NexusError>)
        -> Result<T, NexusError> {
        let before = self.snapshot()?;
        let result = operation(&self.active, &self.anchor, &self.keypair);
        self.finish(before, result)
    }

    pub fn submit_transaction(&mut self, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        self.update(|active, _, _| active.submit_transaction(tx))
    }

    pub fn produce_block(&mut self) -> Result<Block, NexusError> { self.update(|active, _, _| active.produce_block()) }

    /// Return a signed packet only after its exact bytes and initial intent are committed locally.
    pub fn prepare_l1_submission(&mut self, batch: L2Batch, options: L1SubmissionOptions) -> Result<SignedTransaction, NexusError> {
        self.update(|active, anchor, key| {
            let tx = active.prepare_l1_submission(&batch, anchor, key, options)?;
            active.register_l1_submission(batch, &tx, anchor)?;
            Ok(tx)
        })
    }

    pub fn prepare_l1_retry(&mut self, batch: L2Batch, expected_hash: Hash256,
        options: L1SubmissionOptions) -> Result<SignedTransaction, NexusError> {
        self.update(|active, anchor, key| {
            let tx = active.prepare_l1_submission(&batch, anchor, key, options)?;
            active.retry_l1_submission(batch.index, expected_hash, &tx, anchor)?;
            Ok(tx)
        })
    }

    pub async fn process_l1_block(&mut self, block: Block) -> Result<(), NexusError> {
        let before = self.snapshot()?;
        let result = self.anchor.process_block(block).await;
        self.finish(before, result)
    }

    pub async fn process_l1_transactions(&mut self, transactions: Vec<SignedTransaction>, proposer: Address) -> Result<(), NexusError> {
        let block = self.anchor.prepare_block(transactions, proposer)?;
        self.process_l1_block(block).await
    }

    pub fn confirm_batch(&mut self, index: u64) -> Result<ConfirmedBatch, NexusError> {
        self.update(|active, anchor, _| active.mark_batch_confirmed(index, anchor))
    }

    pub fn recover_l1_submission(&mut self, batch: L2Batch, tx: &SignedTransaction) -> Result<ConfirmedBatch, NexusError> {
        self.update(|active, anchor, _| active.recover_l1_submission(batch, tx, anchor))
    }

    pub fn recover_l1_retry(&mut self, index: u64, expected_hash: Hash256, tx: &SignedTransaction) -> Result<ConfirmedBatch, NexusError> {
        self.update(|active, anchor, _| active.recover_l1_retry(index, expected_hash, tx, anchor))
    }

    pub fn generation(&self) -> u64 { self.store.generation() }
    pub fn publisher(&self) -> Address { self.keypair.address() }
    pub fn l1_height(&self) -> BlockHeight { self.anchor.height() }
    pub fn l2_height(&self) -> BlockHeight { self.active.height() }
    pub fn l1_state_root(&self) -> StateRoot { self.anchor.state_root() }
    pub fn l2_state_root(&self) -> StateRoot { self.active.state_root() }
    pub fn l1_account(&self, address: &Address) -> Option<AccountState> { self.anchor.get_account(address) }
    pub fn l2_account(&self, address: &Address) -> Option<AccountState> { self.active.get_account(address) }
    pub fn batch(&self, index: u64) -> Option<L2Batch> { self.active.get_known_batch(index) }
    pub fn submission(&self, index: u64) -> Option<SubmittedBatch> { self.active.get_batch_submission(index) }
    pub fn confirmation(&self, index: u64) -> Option<ConfirmedBatch> { self.active.get_batch_confirmation(index) }
    pub fn signed_packet(&self, index: u64, hash: Hash256) -> Result<SignedTransaction, NexusError> {
        self.active.get_l1_submission_transaction(index, hash)
    }
    pub fn batch_data(&self, index: u64) -> Result<Vec<u8>, NexusError> { self.anchor.get_l2_batch_data(index) }
}
