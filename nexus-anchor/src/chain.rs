//! Local L1 reference processor; processing is distinct from BFT finalization.
//! State and auxiliary effects are committed together after successful execution.

use crate::{
    consensus::ConsensusConfig,
    data_availability::DataAvailabilityLayer,
    finality::FinalityGadget,
    validator::{ValidatorRegistry, ValidatorSet},
};
use nexus_core::{
    AccountState, Address, Amount, Block, BlockBody, BlockHeader, BlockHeight, ChainId, Hash256, InMemoryState,
    Layer, MerkleTree, NexusError, SignedTransaction, StateRoot, Timestamp,
};
use nexus_crypto::{signer::verify_signed_transaction_at, DilithiumKeypair, Signer};
use parking_lot::RwLock;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::monetary::{MonetaryCounters, MonetaryGenesis};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorChainConfig {
    /// Expected signed transaction domain; shared by all replicas of this L1.
    pub chain_id: ChainId,
    /// Sum of declared transaction gas limits, reserved before execution.
    /// Zero permits only empty blocks; gas is not charged by this profile.
    pub block_gas_limit: u64,
    pub consensus: ConsensusConfig,
    pub min_stake: Amount,
    pub block_reward: Amount,
    /// Reserved metadata; this reference profile does not charge transaction fees.
    pub fee_percentage: u8,
}

impl Default for AnchorChainConfig {
    fn default() -> Self {
        Self { chain_id: ChainId::LOCAL, block_gas_limit: 30_000_000,
            consensus: ConsensusConfig::default(), min_stake: Amount::from_units(32),
            block_reward: Amount::from_units(2), fee_percentage: 1 }
    }
}

/// Local transaction policy only; sender nonce, chain and time come from L1.
#[derive(Debug, Clone)]
pub struct L1SubmissionOptions {
    pub gas_limit: u64,
    pub gas_price: Amount,
    pub expires_at: Option<Timestamp>,
}

impl Default for L1SubmissionOptions {
    fn default() -> Self { Self { gas_limit: 21_000, gas_price: Amount::ZERO, expires_at: None } }
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecutionState {
    state: InMemoryState,
    money: Option<MonetaryCounters>,
    validators: ValidatorRegistry,
    da_layer: DataAvailabilityLayer,
    l2_batches: Vec<L2BatchRecord>,
}

#[derive(Serialize, Deserialize)]
struct ChainData {
    execution: ExecutionState,
    blocks: HashMap<Hash256, Block>,
    blocks_by_height: HashMap<BlockHeight, Hash256>,
    height: BlockHeight,
    finality: FinalityGadget,
}

/// One lock serializes validation, execution, and publication of a local block.
/// This processor does not turn local acceptance into a consensus certificate.
pub struct AnchorChain {
    config: AnchorChainConfig,
    monetary: Option<MonetaryGenesis>,
    network_domain: Option<Hash256>,
    data: RwLock<ChainData>,
    genesis: Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2BatchRecord {
    pub index: u64,
    /// Present only for a signed BatchSubmit in a successfully processed L1 block.
    pub l1_tx_hash: Option<Hash256>,
    /// Payload position within this local L1 height, independent of the global batch index.
    pub da_batch_index: usize,
    pub pre_state_root: StateRoot,
    pub post_state_root: StateRoot,
    pub data_hash: Hash256,
    pub l1_height: BlockHeight,
    pub timestamp: Timestamp,
}

/// Inclusion observed in this trusted local processor; not a BFT finality certificate.
#[derive(Debug, Clone)]
pub struct L1BatchInclusion {
    pub transaction_hash: Hash256,
    pub block_hash: Hash256,
    pub block_height: BlockHeight,
    pub sender: Address,
    pub batch_root: StateRoot,
    pub batch_size: u32,
    pub data_hash: Hash256,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct AnchorCheckpoint {
    version: u32,
    config: AnchorChainConfig,
    monetary: Option<MonetaryGenesis>,
    genesis: Block,
    data: Vec<u8>,
}

impl AnchorChain {
    /// Trusted local snapshot, including DA, validators and pending local finality metadata.
    pub fn export_checkpoint(&self) -> Result<Vec<u8>, NexusError> {
        use nexus_core::checkpoint::encode;
        let data = self.data.read();
        encode(&AnchorCheckpoint { version: 3, config: self.config.clone(), monetary: self.monetary.clone(),
            genesis: self.genesis.clone(), data: encode(&*data)? })
    }

    pub fn restore_checkpoint(bytes: &[u8], expected: &AnchorChainConfig) -> Result<Self, NexusError> {
        Self::restore_profile(bytes, expected, None)
    }

    /// Monetary checkpoints are accepted only with an independently supplied
    /// expected genesis/policy. The archive cannot choose its own money rules.
    pub fn restore_monetary_checkpoint(bytes: &[u8], expected: &AnchorChainConfig,
        genesis: &MonetaryGenesis) -> Result<Self, NexusError> {
        Self::restore_profile(bytes, expected, Some(genesis))
    }

    fn restore_profile(bytes: &[u8], expected: &AnchorChainConfig,
        monetary: Option<&MonetaryGenesis>) -> Result<Self, NexusError> {
        use nexus_core::checkpoint::{decode, encode, validate_blocks};
        let snapshot: AnchorCheckpoint = decode(bytes)?;
        let initial = if let Some(genesis) = monetary {
            Self::new_monetary(expected.clone(), genesis.clone())?
        } else { Self::empty(expected.clone()) };
        if snapshot.version != 3 || encode(&snapshot.config)? != encode(expected)?
            || snapshot.monetary != initial.monetary
            || encode(&snapshot.genesis)? != encode(&initial.genesis)? {
            return Err(NexusError::ConfigError("Checkpoint version, genesis or L1 policy differs".into()));
        }
        let data: ChainData = decode(&snapshot.data)?;
        if monetary.is_some() {
            // Replay signed operations and monetary rules instead of trusting
            // archived counters, balances or auxiliary DA/finality metadata.
            let count = data.height.0.checked_add(1).and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| NexusError::StateError("Invalid monetary checkpoint height".into()))?;
            if data.blocks.len() != count || data.blocks_by_height.len() != count
                || data.blocks_by_height.get(&BlockHeight::GENESIS) != Some(&initial.genesis.hash())
                || data.blocks.get(&initial.genesis.hash()).map(encode).transpose()? != Some(encode(&initial.genesis)?) {
                return Err(NexusError::StateError("Incomplete monetary checkpoint chain".into()));
            }
            for height in 1..=data.height.0 {
                let hash = data.blocks_by_height.get(&BlockHeight(height))
                    .ok_or(NexusError::BlockHeightNotFound(BlockHeight(height)))?;
                let block = data.blocks.get(hash).ok_or(NexusError::BlockNotFound(*hash))?;
                if block.hash() != *hash { return Err(NexusError::StateError("Monetary checkpoint hash mismatch".into())); }
                initial.process_block_now(block.clone())?;
            }
            let replayed = initial.data.read();
            if data.execution.money != replayed.execution.money
                || initial.execution_root(&data.execution) != initial.execution_root(&replayed.execution) {
                return Err(NexusError::StateError("Monetary checkpoint does not match replay".into()));
            }
            drop(replayed);
            return Ok(initial);
        }
        if data.execution.money.is_some() {
            return Err(NexusError::ConfigError("Unexpected monetary counters in legacy profile".into()));
        }
        validate_blocks(&data.blocks, &data.blocks_by_height, data.height, &snapshot.genesis,
            Layer::Anchor, data.execution.state.compute_root())?;
        for (index, record) in data.execution.l2_batches.iter().enumerate() {
            let payload = data.execution.da_layer.reconstruct_batch(record.l1_height, record.da_batch_index)?;
            if record.index != index as u64 || Hash256::hash(&payload) != record.data_hash {
                return Err(NexusError::StateError("Invalid checkpoint DA record".into()));
            }
            if let Some(hash) = record.l1_tx_hash { Self::processed_batch_inclusion(&data, &hash, None)?; }
        }
        Ok(Self { config: snapshot.config, monetary: None, network_domain: None,
            data: RwLock::new(data), genesis: snapshot.genesis })
    }

    pub fn new(config: AnchorChainConfig, _keypair: DilithiumKeypair) -> Self {
        Self::empty(config)
    }

    fn empty(config: AnchorChainConfig) -> Self {
        let genesis = Block::genesis(Layer::Anchor);
        let hash = genesis.hash();
        let execution = ExecutionState { state: InMemoryState::new(), money: None,
            validators: ValidatorRegistry::new(config.min_stake),
            da_layer: DataAvailabilityLayer::new(), l2_batches: Vec::new() };
        Self { config, monetary: None, network_domain: None, data: RwLock::new(ChainData { execution,
            blocks: HashMap::from([(hash, genesis.clone())]),
            blocks_by_height: HashMap::from([(BlockHeight::GENESIS, hash)]),
            height: BlockHeight::GENESIS, finality: FinalityGadget::new() }), genesis }
    }

    /// Explicit opt-in rules for the public testnet. No secret key or local clock
    /// is used to construct genesis; allocations and rules determine its hash.
    pub fn new_monetary(config: AnchorChainConfig, monetary: MonetaryGenesis) -> Result<Self, NexusError> {
        let monetary = monetary.canonical(&config)?;
        let network_domain = monetary.network_domain(&config)?;
        let mut chain = Self::empty(config);
        chain.monetary = Some(monetary.clone());
        chain.network_domain = Some(network_domain);
        {
            let mut data = chain.data.write();
            for (address, balance) in &monetary.allocations {
                data.execution.state.set_account(*address, AccountState::with_balance(*balance));
            }
            data.execution.money = Some(MonetaryCounters::genesis(&monetary)?);
            chain.genesis.header.state_root = chain.execution_root(&data.execution).0;
            chain.genesis.header.extra_data = network_domain.as_bytes().to_vec();
            data.blocks = HashMap::from([(chain.genesis.hash(), chain.genesis.clone())]);
            data.blocks_by_height = HashMap::from([(BlockHeight::GENESIS, chain.genesis.hash())]);
        }
        Ok(chain)
    }

    pub fn network_domain(&self) -> Option<Hash256> { self.network_domain }
    pub fn monetary_counters(&self) -> Option<MonetaryCounters> { self.data.read().execution.money }

    fn execution_root(&self, execution: &ExecutionState) -> StateRoot {
        match execution.money {
            None => execution.state.compute_root(),
            Some(counters) => {
                let bytes = bincode::serialize(&(b"NEXUS_MONETARY_STATE_V1".as_slice(),
                    self.network_domain, execution.state.compute_root(), counters))
                    .expect("Fixed-size monetary state commitment");
                StateRoot(Hash256::hash(&bytes))
            }
        }
    }

    pub fn genesis(&self) -> &Block { &self.genesis }
    pub fn height(&self) -> BlockHeight { self.data.read().height }
    pub fn get_block(&self, hash: &Hash256) -> Option<Block> {
        self.data.read().blocks.get(hash).cloned()
    }
    pub fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        let data = self.data.read();
        data.blocks.get(data.blocks_by_height.get(&height)?).cloned()
    }
    pub fn latest_block(&self) -> Option<Block> {
        let data = self.data.read();
        data.blocks.get(data.blocks_by_height.get(&data.height)?).cloned()
    }
    pub fn get_account(&self, address: &Address) -> Option<AccountState> {
        self.data.read().execution.state.get_account(address).cloned()
    }

    /// Sign and preflight a single batch transaction against one local L1 snapshot.
    /// Does not reserve nonce, publish DA, reward a proposer, or process a block.
    pub fn prepare_batch_submission(&self, signer: &DilithiumKeypair, batch_root: StateRoot,
        batch_size: u32, bytes: Vec<u8>, options: L1SubmissionOptions) -> Result<SignedTransaction, NexusError> {
        if bytes.is_empty() {
            return Err(NexusError::InvalidTransaction("Empty local DA payload".into()));
        }
        if bytes.len() > crate::data_availability::MAX_DA_DATA_SIZE { return Err(NexusError::BatchTooLarge); }
        let data = self.data.read();
        let parent_hash = *data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        let parent = data.blocks.get(&parent_hash).ok_or(NexusError::BlockNotFound(parent_hash))?;
        let timestamp = Timestamp::now().max(parent.header.timestamp);
        let nonce = data.execution.state.get_account(&signer.address()).map(|account| account.nonce).unwrap_or_default();
        let transaction = nexus_core::Transaction { chain_id: self.config.chain_id, network_domain: self.network_domain, nonce,
            gas_limit: options.gas_limit, gas_price: options.gas_price,
            tx_type: nexus_core::TransactionType::BatchSubmit { batch_root: batch_root.0, batch_size, compressed_data: bytes },
            timestamp, expires_at: options.expires_at };
        transaction.checked_max_cost()?;
        let signed = signer.sign_transaction(transaction)?;
        self.preflight_batch_submission(&signed, &data, timestamp)?;
        Ok(signed)
    }

    /// Validate a supplied signed transaction against current local admission state, without effects.
    pub fn validate_batch_submission(&self, signed: &SignedTransaction) -> Result<(), NexusError> {
        let data = self.data.read();
        let parent_hash = *data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        let parent = data.blocks.get(&parent_hash).ok_or(NexusError::BlockNotFound(parent_hash))?;
        self.preflight_batch_submission(signed, &data, Timestamp::now().max(parent.header.timestamp))
    }

    fn preflight_batch_submission(&self, signed: &SignedTransaction, data: &ChainData,
        timestamp: Timestamp) -> Result<(), NexusError> {
        if !matches!(&signed.transaction.tx_type, nexus_core::TransactionType::BatchSubmit { .. }) {
            return Err(NexusError::InvalidTransaction("Expected an L1 batch submission".into()));
        }
        let height = BlockHeight(data.height.0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Block heights exhausted".into()))?);
        let parent_hash = *data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        let mut header = BlockHeader::new(height, parent_hash, Address::ZERO, Layer::Anchor);
        header.timestamp = timestamp;
        header.transactions_root = MerkleTree::from_leaves(vec![signed.hash()]).root();
        let candidate = Block::new(header, BlockBody::new(vec![signed.clone()]));
        self.validate_block(&candidate, data)?;
        let mut staged = data.execution.clone();
        self.execute_transaction(&mut staged, signed, height, timestamp, Address::ZERO)?;
        Ok(())
    }

    /// Prepare a local candidate without publishing effects or certifying consensus.
    /// The root includes all successful transactions and the final block reward.
    pub fn prepare_block(&self, transactions: Vec<SignedTransaction>, proposer: Address) -> Result<Block, NexusError> {
        let data = self.data.read();
        let parent = data.blocks.get(data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        self.prepare_block_with_data(transactions, proposer, Timestamp::now().max(parent.header.timestamp), &data)
    }

    /// Deterministic construction for replicas and experiments. The consensus
    /// driver must separately enforce its live proposal clock/skew policy.
    pub fn prepare_block_at(&self, transactions: Vec<SignedTransaction>, proposer: Address,
        timestamp: Timestamp) -> Result<Block, NexusError> {
        self.prepare_block_with_data(transactions, proposer, timestamp, &self.data.read())
    }

    fn prepare_block_with_data(&self, transactions: Vec<SignedTransaction>, proposer: Address,
        timestamp: Timestamp, data: &ChainData) -> Result<Block, NexusError> {
        let height = BlockHeight(data.height.0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Block heights exhausted".into()))?);
        let parent = data.blocks.get(data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        let mut header = BlockHeader::new(height, parent.hash(), proposer, Layer::Anchor);
        header.timestamp = timestamp;
        header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
        let mut block = Block::new(header, BlockBody::new(transactions));
        block.header.state_root = self.execution_root(&self.stage_block(&block, data)?).0;
        Ok(block)
    }

    fn stage_block(&self, block: &Block, data: &ChainData) -> Result<ExecutionState, NexusError> {
        self.validate_block(block, data)?;
        // Stage every fallible effect, including registry, DA, and L2 records.
        let mut staged = data.execution.clone();
        for tx in &block.body.transactions {
            self.execute_transaction(&mut staged, tx, block.height(), block.header.timestamp, block.header.proposer)?;
        }
        if let Some(monetary) = &self.monetary {
            let counters = staged.money.as_mut()
                .ok_or_else(|| NexusError::StateError("Missing monetary counters".into()))?;
            let reward = monetary.policy.reward(block.height(), counters.issued)?;
            if reward != Amount::ZERO {
                staged.state.get_or_create_account(&block.header.proposer).credit(reward)?;
            }
            counters.issued = counters.issued.checked_add(reward)
                .ok_or_else(|| NexusError::StateError("Lifetime issuance overflow".into()))?;
            // This profile has no staking/escrow operations: all live supply is
            // accounted for by liquid balances. Check every accepted transition.
            if staged.state.total_balance()? != counters.supply()? {
                return Err(NexusError::StateError("Monetary supply conservation failed".into()));
            }
        } else {
            staged.state.get_or_create_account(&block.header.proposer).credit(self.config.block_reward)?;
        }
        Ok(staged)
    }

    pub async fn process_block(&self, block: Block) -> Result<(), NexusError> {
        self.process_block_now(block)
    }

    /// Aplica o reproduce un bloque de forma síncrona; no certifica finalidad BFT.
    pub fn process_block_now(&self, block: Block) -> Result<(), NexusError> {
        let mut data = self.data.write();
        let staged = self.stage_block(&block, &data)?;
        let expected = self.execution_root(&staged).0;
        if block.header.state_root != expected {
            return Err(NexusError::InvalidStateRoot { expected, got: block.header.state_root });
        }
        let validators_before_block = data.execution.validators.validator_set().clone();
        data.finality.set_validator_set(validators_before_block);
        data.execution = staged;
        data.height = block.height();
        data.blocks_by_height.insert(block.height(), block.hash());
        data.blocks.insert(block.hash(), block.clone());
        data.finality.add_block(block);
        Ok(())
    }

    /// Application validity only. Does not process the block or certify finality.
    pub fn validate_candidate(&self, block: &Block) -> Result<(), NexusError> {
        let staged = self.stage_block(block, &self.data.read())?;
        let expected = self.execution_root(&staged).0;
        if block.header.state_root != expected {
            return Err(NexusError::InvalidStateRoot { expected, got: block.header.state_root });
        }
        Ok(())
    }

    fn validate_block(&self, block: &Block, data: &ChainData) -> Result<(), NexusError> {
        block.validate_structure()?;
        if data.blocks.contains_key(&block.hash()) {
            return Err(NexusError::InvalidBlock("Block already processed".into()));
        }
        let expected = data.height.0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Block heights exhausted".into()))?;
        if block.height().0 != expected || block.header.layer != Layer::Anchor
            || block.header.version != nexus_core::PROTOCOL_VERSION {
            return Err(NexusError::InvalidBlock("Unexpected L1 height, layer or version".into()));
        }
        let parent = *data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        if block.parent_hash() != parent {
            return Err(NexusError::InvalidParentBlock { expected: parent, got: block.parent_hash() });
        }
        if block.header.timestamp < data.blocks.get(&parent)
            .ok_or(NexusError::BlockNotFound(parent))?.header.timestamp {
            return Err(NexusError::InvalidBlockTimestamp);
        }
        // No L1 receipt interpreter is implemented by this profile yet.
        if block.header.receipts_root != Hash256::ZERO {
            return Err(NexusError::InvalidBlock("L1 receipts root is not supported".into()));
        }
        let root = MerkleTree::from_leaves(block.transaction_hashes()).root();
        if block.header.transactions_root != root {
            return Err(NexusError::InvalidBlock("Transaction root mismatch".into()));
        }
        let mut remaining_gas = self.config.block_gas_limit;
        for tx in &block.body.transactions {
            if tx.transaction.chain_id != self.config.chain_id {
                return Err(NexusError::InvalidChainId);
            }
            if tx.transaction.gas_limit > remaining_gas {
                return Err(NexusError::InvalidBlock("L1 declared block gas limit exceeded".into()));
            }
            // Subtraction after comparison avoids summation overflow, including u64::MAX.
            remaining_gas -= tx.transaction.gas_limit;
            if tx.transaction.timestamp > block.header.timestamp {
                return Err(NexusError::InvalidTransaction("Transaction created after block timestamp".into()));
            }
            if !verify_signed_transaction_at(tx, block.header.timestamp)? {
                return Err(NexusError::SignatureVerificationFailed(tx.sender));
            }
            let required_gas = if let Some(monetary) = &self.monetary {
                if tx.transaction.network_domain != self.network_domain
                    || tx.signature.scheme != nexus_core::SignatureScheme::Dilithium3
                    || tx.transaction.gas_price < monetary.policy.min_gas_price {
                    return Err(NexusError::InvalidTransaction("Wrong deployment, signature profile or monetary gas price".into()));
                }
                monetary.policy.transaction_gas(tx)?
            } else { tx.transaction.intrinsic_gas()? };
            if required_gas > tx.transaction.gas_limit {
                return Err(NexusError::InvalidTransaction("Transaction gas limit exceeded".into()));
            }
        }
        Ok(())
    }

    fn execute_transaction(&self, execution: &mut ExecutionState, tx: &SignedTransaction,
        height: BlockHeight, timestamp: Timestamp, proposer: Address) -> Result<(), NexusError> {
        use nexus_core::TransactionType;
        let sender = execution.state.get_account(&tx.sender).cloned().unwrap_or_default();
        if tx.transaction.nonce != sender.nonce {
            return Err(NexusError::InvalidNonce { expected: sender.nonce.0, got: tx.transaction.nonce.0 });
        }
        let max_cost = tx.transaction.checked_max_cost()?;
        if sender.balance < max_cost {
            return Err(NexusError::InsufficientBalance { required: max_cost.0, available: sender.balance.0 });
        }
        match &tx.transaction.tx_type {
            TransactionType::Transfer { to, amount } => execution.state.transfer(&tx.sender, to, *amount)?,
            TransactionType::ValidatorRegister { public_key, stake } => {
                if public_key != &tx.public_key {
                    return Err(NexusError::InvalidPublicKey("Registration key differs from sender key".into()));
                }
                execution.state.get_or_create_account(&tx.sender).debit(*stake)?;
                execution.validators.register(tx.sender, public_key.clone(), *stake)?;
            }
            TransactionType::BatchSubmit { batch_root, compressed_data, .. } => {
                let da_batch_index = execution.da_layer.get_commitment(height).map_or(0, Vec::len);
                let commitment = execution.da_layer.submit_data(height, compressed_data.clone())?;
                execution.l2_batches.push(L2BatchRecord { index: execution.l2_batches.len() as u64,
                    l1_tx_hash: Some(tx.hash()), da_batch_index,
                    pre_state_root: StateRoot::EMPTY, post_state_root: StateRoot::new(*batch_root),
                    data_hash: commitment.commitment, l1_height: height, timestamp });
            }
            _ => return Err(NexusError::NotImplemented("L1 transaction type".into())),
        }
        if let Some(monetary) = &self.monetary {
            let fee = u128::from(monetary.policy.transaction_gas(tx)?)
                .checked_mul(tx.transaction.gas_price.0).map(Amount)
                .ok_or_else(|| NexusError::InvalidTransaction("Actual transaction fee overflow".into()))?;
            let (burned, paid) = monetary.policy.split_fee(fee)?;
            execution.state.get_or_create_account(&tx.sender).debit(fee)?;
            if paid != Amount::ZERO { execution.state.get_or_create_account(&proposer).credit(paid)?; }
            execution.money.as_mut().ok_or_else(|| NexusError::StateError("Missing monetary counters".into()))?
                .charge(fee, burned)?;
        }
        let next = sender.nonce.0.checked_add(1)
            .ok_or_else(|| NexusError::InvalidTransaction("Transaction nonce exhausted".into()))?;
        execution.state.get_or_create_account(&tx.sender).nonce = nexus_core::Nonce(next);
        Ok(())
    }

    /// Local DA registration, distinct from verifying an L2 validity certificate.
    pub fn submit_l2_batch(&self, batch_root: StateRoot, bytes: Vec<u8>) -> Result<Hash256, NexusError> {
        if self.monetary.is_some() {
            return Err(NexusError::InvalidTransaction("Monetary profile requires a signed BatchSubmit in a block".into()));
        }
        let mut data = self.data.write();
        let mut staged = data.execution.clone();
        let da_batch_index = staged.da_layer.get_commitment(data.height).map_or(0, Vec::len);
        let commitment = staged.da_layer.submit_data(data.height, bytes)?;
        staged.l2_batches.push(L2BatchRecord { index: staged.l2_batches.len() as u64,
            l1_tx_hash: None, da_batch_index,
            pre_state_root: StateRoot::EMPTY, post_state_root: batch_root,
            data_hash: commitment.commitment, l1_height: data.height, timestamp: Timestamp::now() });
        data.execution = staged;
        Ok(commitment.commitment)
    }
    pub fn get_l2_batch(&self, index: u64) -> Option<L2BatchRecord> {
        self.data.read().execution.l2_batches.get(usize::try_from(index).ok()?).cloned()
    }
    /// Reconstruct an exact local payload; this does not authenticate an L2 state transition.
    pub fn get_l2_batch_data(&self, index: u64) -> Result<Vec<u8>, NexusError> {
        let data = self.data.read();
        let record = usize::try_from(index).ok().and_then(|index| data.execution.l2_batches.get(index))
            .ok_or_else(|| NexusError::StateError("L2 batch not found".into()))?;
        let bytes = data.execution.da_layer.reconstruct_batch(record.l1_height, record.da_batch_index)?;
        if Hash256::hash(&bytes) != record.data_hash {
            return Err(NexusError::StateError("L2 payload hash mismatch".into()));
        }
        Ok(bytes)
    }

    /// Reads canonical processed storage under one lock, excluding helper-only registrations.
    pub fn get_processed_batch_inclusion(&self, tx_hash: &Hash256) -> Result<L1BatchInclusion, NexusError> {
        self.find_processed_batch_inclusion(tx_hash)?
            .ok_or_else(|| NexusError::SecurityViolation("No processed L1 batch transaction".into()))
    }

    /// Absence is distinct from inconsistent local storage; callers must propagate errors.
    pub fn find_processed_batch_inclusion(&self, tx_hash: &Hash256) -> Result<Option<L1BatchInclusion>, NexusError> {
        let data = self.data.read();
        Self::processed_batch_inclusion(&data, tx_hash, None)
    }

    /// Match the entire signed envelope against canonical processed storage, not current admission.
    /// Historical nonce and expiry were checked when the block was processed.
    pub fn validate_processed_batch_submission(&self, signed: &SignedTransaction) -> Result<L1BatchInclusion, NexusError> {
        let data = self.data.read();
        Self::processed_batch_inclusion(&data, &signed.hash(), Some(signed))?
            .ok_or_else(|| NexusError::SecurityViolation("No processed L1 batch transaction".into()))
    }

    fn processed_batch_inclusion(data: &ChainData, tx_hash: &Hash256,
        expected: Option<&SignedTransaction>) -> Result<Option<L1BatchInclusion>, NexusError> {
        let Some(record) = data.execution.l2_batches.iter().find(|record| record.l1_tx_hash == Some(*tx_hash)) else {
            return Ok(None);
        };
        let block_hash = *data.blocks_by_height.get(&record.l1_height)
            .ok_or(NexusError::BlockHeightNotFound(record.l1_height))?;
        let block = data.blocks.get(&block_hash).ok_or(NexusError::BlockNotFound(block_hash))?;
        let tx = block.body.transactions.iter().find(|tx| tx.hash() == *tx_hash)
            .ok_or_else(|| NexusError::SecurityViolation("Batch transaction absent from canonical L1 block".into()))?;
        // The transaction hash does not cover sender, public key or signature scheme.
        if let Some(expected) = expected {
            if bincode::serialize(expected)? != bincode::serialize(tx)? {
                return Err(NexusError::SecurityViolation("Signed packet differs from the processed L1 envelope".into()));
            }
        }
        let (batch_root, batch_size, payload) = match &tx.transaction.tx_type {
            nexus_core::TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } =>
                (*batch_root, *batch_size, compressed_data),
            _ => return Err(NexusError::SecurityViolation("L1 transaction is not a batch submission".into())),
        };
        let bytes = data.execution.da_layer.reconstruct_batch(record.l1_height, record.da_batch_index)?;
        if bytes != *payload || Hash256::hash(&bytes) != record.data_hash
            || record.post_state_root != StateRoot::new(batch_root) {
            return Err(NexusError::SecurityViolation("L1 batch record differs from its transaction or DA data".into()));
        }
        Ok(Some(L1BatchInclusion { transaction_hash: *tx_hash, block_hash, block_height: record.l1_height,
            sender: tx.sender, batch_root: StateRoot::new(batch_root), batch_size,
            data_hash: record.data_hash, data: bytes }))
    }
    pub fn finalized_height(&self) -> BlockHeight { self.data.read().finality.last_finalized_height() }
    pub fn is_finalized(&self, hash: &Hash256) -> bool { self.data.read().finality.is_finalized(hash) }
    pub fn validator_set(&self) -> ValidatorSet { self.data.read().execution.validators.validator_set().clone() }
    pub fn state_root(&self) -> StateRoot { self.execution_root(&self.data.read().execution) }
    pub fn stats(&self) -> ChainStats {
        let data = self.data.read();
        ChainStats { height: data.height, finalized_height: data.finality.last_finalized_height(),
            block_count: data.blocks.len(), account_count: data.execution.state.account_count(),
            validator_count: data.execution.validators.validator_set().active_count(),
            l2_batch_count: data.execution.l2_batches.len() }
    }
}

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

    #[tokio::test]
    async fn monetary_restore_rejects_forged_balances_or_counters_even_with_matching_archived_roots() {
        use nexus_core::checkpoint::{decode, encode};
        use crate::MonetaryPolicy;
        let config = AnchorChainConfig { block_reward: Amount::ZERO, fee_percentage: 0, ..Default::default() };
        let address = Address::new([7; 32]);
        let monetary = MonetaryGenesis { deployment: Hash256::new([1; 32]),
            allocations: vec![(address, Amount(1000))],
            policy: MonetaryPolicy { max_issued: Amount(2000), initial_block_reward: Amount(10),
                halving_interval: 2, min_gas_price: Amount(1), burn_basis_points: 2500 } };
        let chain = AnchorChain::new_monetary(config.clone(), monetary.clone()).unwrap();
        chain.process_block(chain.prepare_block_at(vec![], address, Timestamp(1)).unwrap()).await.unwrap();
        let archive = chain.export_checkpoint().unwrap();
        for forge_counter in [false, true] {
            let mut snapshot: AnchorCheckpoint = decode(&archive).unwrap();
            let mut data: ChainData = decode(&snapshot.data).unwrap();
            if forge_counter { data.execution.money.as_mut().unwrap().issued.0 += 1; }
            else { data.execution.state.get_or_create_account(&address).balance.0 += 1; }
            let mut block = data.blocks.remove(&data.blocks_by_height[&BlockHeight(1)]).unwrap();
            // Also forge a self-consistent archive root and its block index.
            // Only replay of the declared rules detects the unjustified unit.
            block.header.state_root = chain.execution_root(&data.execution).0;
            data.blocks_by_height.insert(BlockHeight(1), block.hash());
            data.blocks.insert(block.hash(), block);
            snapshot.data = encode(&data).unwrap();
            assert!(AnchorChain::restore_monetary_checkpoint(&encode(&snapshot).unwrap(), &config, &monetary).is_err());
        }
    }

    #[tokio::test]
    async fn processed_packet_validation_propagates_inconsistent_da_storage() {
        let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let chain = AnchorChain::new(Default::default(), signer.clone());
        let signed = chain.prepare_batch_submission(&signer, StateRoot::EMPTY, 1, vec![9], Default::default()).unwrap();
        chain.process_block(chain.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        assert!(chain.validate_processed_batch_submission(&signed).is_ok());
        chain.data.write().execution.l2_batches[0].data_hash = Hash256::ZERO;
        assert!(chain.find_processed_batch_inclusion(&signed.hash()).is_err());
        assert!(chain.validate_processed_batch_submission(&signed).is_err());
    }

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
