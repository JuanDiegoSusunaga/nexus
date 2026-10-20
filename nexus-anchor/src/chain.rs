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
use nexus_crypto::{signer::verify_signed_transaction_at, DilithiumKeypair};
use parking_lot::RwLock;
use std::collections::HashMap;

#[derive(Debug, Clone)]
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

#[derive(Clone)]
struct ExecutionState {
    state: InMemoryState,
    validators: ValidatorRegistry,
    da_layer: DataAvailabilityLayer,
    l2_batches: Vec<L2BatchRecord>,
}

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
    data: RwLock<ChainData>,
    genesis: Block,
}

#[derive(Debug, Clone)]
pub struct L2BatchRecord {
    pub index: u64,
    pub pre_state_root: StateRoot,
    pub post_state_root: StateRoot,
    pub data_hash: Hash256,
    pub l1_height: BlockHeight,
    pub timestamp: Timestamp,
}

impl AnchorChain {
    pub fn new(config: AnchorChainConfig, _keypair: DilithiumKeypair) -> Self {
        let genesis = Block::genesis(Layer::Anchor);
        let hash = genesis.hash();
        let execution = ExecutionState { state: InMemoryState::new(),
            validators: ValidatorRegistry::new(config.min_stake),
            da_layer: DataAvailabilityLayer::new(), l2_batches: Vec::new() };
        Self { config, data: RwLock::new(ChainData { execution,
            blocks: HashMap::from([(hash, genesis.clone())]),
            blocks_by_height: HashMap::from([(BlockHeight::GENESIS, hash)]),
            height: BlockHeight::GENESIS, finality: FinalityGadget::new() }), genesis }
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

    /// Prepare a local candidate without publishing effects or certifying consensus.
    /// The root includes all successful transactions and the final block reward.
    pub fn prepare_block(&self, transactions: Vec<SignedTransaction>, proposer: Address) -> Result<Block, NexusError> {
        let data = self.data.read();
        let height = BlockHeight(data.height.0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Block heights exhausted".into()))?);
        let parent = data.blocks.get(data.blocks_by_height.get(&data.height)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?)
            .ok_or(NexusError::BlockHeightNotFound(data.height))?;
        let mut header = BlockHeader::new(height, parent.hash(), proposer, Layer::Anchor);
        header.timestamp = Timestamp::now().max(parent.header.timestamp);
        header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
        let mut block = Block::new(header, BlockBody::new(transactions));
        block.header.state_root = self.stage_block(&block, &data)?.state.compute_root().0;
        Ok(block)
    }

    fn stage_block(&self, block: &Block, data: &ChainData) -> Result<ExecutionState, NexusError> {
        self.validate_block(block, data)?;
        // Stage every fallible effect, including registry, DA, and L2 records.
        let mut staged = data.execution.clone();
        for tx in &block.body.transactions {
            self.execute_transaction(&mut staged, tx, block.height(), block.header.timestamp)?;
        }
        staged.state.get_or_create_account(&block.header.proposer).credit(self.config.block_reward)?;
        Ok(staged)
    }

    pub async fn process_block(&self, block: Block) -> Result<(), NexusError> {
        let mut data = self.data.write();
        let staged = self.stage_block(&block, &data)?;
        let expected = staged.state.compute_root().0;
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
            if tx.transaction.intrinsic_gas()? > tx.transaction.gas_limit {
                return Err(NexusError::InvalidTransaction("Transaction gas limit exceeded".into()));
            }
        }
        Ok(())
    }

    fn execute_transaction(&self, execution: &mut ExecutionState, tx: &SignedTransaction,
        height: BlockHeight, timestamp: Timestamp) -> Result<(), NexusError> {
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
                execution.da_layer.submit_data(height, compressed_data.clone())?;
                execution.l2_batches.push(L2BatchRecord { index: execution.l2_batches.len() as u64,
                    pre_state_root: StateRoot::EMPTY, post_state_root: StateRoot::new(*batch_root),
                    data_hash: Hash256::hash(compressed_data), l1_height: height, timestamp });
            }
            _ => return Err(NexusError::NotImplemented("L1 transaction type".into())),
        }
        let next = sender.nonce.0.checked_add(1)
            .ok_or_else(|| NexusError::InvalidTransaction("Transaction nonce exhausted".into()))?;
        execution.state.get_or_create_account(&tx.sender).nonce = nexus_core::Nonce(next);
        Ok(())
    }

    /// Local DA registration, distinct from verifying an L2 validity certificate.
    pub fn submit_l2_batch(&self, batch_root: StateRoot, bytes: Vec<u8>) -> Result<Hash256, NexusError> {
        let mut data = self.data.write();
        let mut staged = data.execution.clone();
        let commitment = staged.da_layer.submit_data(data.height, bytes)?;
        staged.l2_batches.push(L2BatchRecord { index: staged.l2_batches.len() as u64,
            pre_state_root: StateRoot::EMPTY, post_state_root: batch_root,
            data_hash: commitment.commitment, l1_height: data.height, timestamp: Timestamp::now() });
        data.execution = staged;
        Ok(commitment.commitment)
    }
    pub fn get_l2_batch(&self, index: u64) -> Option<L2BatchRecord> {
        self.data.read().execution.l2_batches.get(usize::try_from(index).ok()?).cloned()
    }
    pub fn finalized_height(&self) -> BlockHeight { self.data.read().finality.last_finalized_height() }
    pub fn is_finalized(&self, hash: &Hash256) -> bool { self.data.read().finality.is_finalized(hash) }
    pub fn validator_set(&self) -> ValidatorSet { self.data.read().execution.validators.validator_set().clone() }
    pub fn state_root(&self) -> StateRoot { self.data.read().execution.state.compute_root() }
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
