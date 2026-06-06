//! Core traits for NEXUS blockchain components
//!
//! Defines the interfaces that must be implemented by various components
//! of the NEXUS dual-chain architecture.

use crate::{
    Address, Amount, BlockHeight, Hash256, NexusError, SignedTransaction, Block,
    StateRoot, AccountState,
};
use async_trait::async_trait;

/// Trait for components that can be uniquely identified by a hash
pub trait Hashable {
    /// Compute the unique hash of this object
    fn hash(&self) -> Hash256;
}

/// Trait for serializable objects
pub trait Encodable {
    /// Encode to bytes
    fn encode(&self) -> Vec<u8>;

    /// Decode from bytes
    fn decode(bytes: &[u8]) -> Result<Self, NexusError>
    where
        Self: Sized;
}

/// Trait for cryptographic signature verification
pub trait Verifiable {
    /// The type of public key used for verification
    type PublicKey;

    /// Verify the signature/proof
    fn verify(&self, public_key: &Self::PublicKey) -> Result<bool, NexusError>;
}

/// Consensus engine interface
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Validate a proposed block
    async fn validate_block(&self, block: &Block) -> Result<bool, NexusError>;

    /// Propose a new block with given transactions
    async fn propose_block(
        &self,
        transactions: Vec<SignedTransaction>,
        parent: Hash256,
    ) -> Result<Block, NexusError>;

    /// Finalize a block (mark as irreversible)
    async fn finalize_block(&self, block_hash: Hash256) -> Result<(), NexusError>;

    /// Get the current validator set
    fn get_validators(&self) -> Vec<Address>;
}

/// State database interface
#[async_trait]
pub trait StateDB: Send + Sync {
    /// Get account state by address
    async fn get_account(&self, address: &Address) -> Result<Option<AccountState>, NexusError>;

    /// Update account state
    async fn set_account(&self, address: &Address, state: AccountState) -> Result<(), NexusError>;

    /// Get the current state root
    async fn state_root(&self) -> Result<StateRoot, NexusError>;

    /// Create a snapshot at current state
    async fn snapshot(&self) -> Result<Hash256, NexusError>;

    /// Revert to a previous snapshot
    async fn revert(&self, snapshot: Hash256) -> Result<(), NexusError>;

    /// Commit pending changes
    async fn commit(&self) -> Result<StateRoot, NexusError>;
}

/// Block storage interface
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Store a block
    async fn put_block(&self, block: Block) -> Result<(), NexusError>;

    /// Get block by hash
    async fn get_block(&self, hash: &Hash256) -> Result<Option<Block>, NexusError>;

    /// Get block by height
    async fn get_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>, NexusError>;

    /// Get the latest block
    async fn get_latest_block(&self) -> Result<Option<Block>, NexusError>;

    /// Get current chain height
    async fn get_height(&self) -> Result<BlockHeight, NexusError>;
}

/// Transaction pool interface
#[async_trait]
pub trait TransactionPool: Send + Sync {
    /// Add a transaction to the pool
    async fn add_transaction(&self, tx: SignedTransaction) -> Result<Hash256, NexusError>;

    /// Get pending transactions for block inclusion
    async fn get_pending(&self, max_count: usize) -> Result<Vec<SignedTransaction>, NexusError>;

    /// Remove transactions (after block inclusion)
    async fn remove_transactions(&self, tx_hashes: &[Hash256]) -> Result<(), NexusError>;

    /// Get transaction by hash
    async fn get_transaction(&self, hash: &Hash256) -> Result<Option<SignedTransaction>, NexusError>;

    /// Get pool size
    async fn size(&self) -> usize;
}

/// Sequencer interface for L2 (Active Layer)
#[async_trait]
pub trait Sequencer: Send + Sync {
    /// Submit a batch of transactions to L1
    async fn submit_batch(&self, transactions: Vec<SignedTransaction>) -> Result<Hash256, NexusError>;

    /// Get current batch being built
    async fn current_batch(&self) -> Result<Vec<SignedTransaction>, NexusError>;

    /// Force batch submission (for timeout or size threshold)
    async fn force_submit(&self) -> Result<Hash256, NexusError>;

    /// Get sequencer's stake amount
    fn stake(&self) -> Amount;

    /// Check if this node is the active sequencer
    fn is_active(&self) -> bool;
}

/// ZK Verifier interface
#[async_trait]
pub trait ZKVerifier: Send + Sync {
    /// Proof type
    type Proof;

    /// Public inputs type
    type PublicInputs;

    /// Verify a zero-knowledge proof
    async fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
    ) -> Result<bool, NexusError>;

    /// Get verification key hash
    fn verification_key_hash(&self) -> Hash256;
}

/// Key rotation manager interface
#[async_trait]
pub trait KeyRotationManager: Send + Sync {
    /// Check if key rotation is needed based on entropy
    async fn should_rotate(&self) -> Result<bool, NexusError>;

    /// Perform key rotation
    async fn rotate_keys(&self) -> Result<(), NexusError>;

    /// Get current key epoch
    fn current_epoch(&self) -> u64;

    /// Get entropy level of current seed
    fn entropy_level(&self) -> f64;
}

/// Network message handler
#[async_trait]
pub trait NetworkHandler: Send + Sync {
    /// Handle incoming block announcement
    async fn on_block(&self, block: Block) -> Result<(), NexusError>;

    /// Handle incoming transaction
    async fn on_transaction(&self, tx: SignedTransaction) -> Result<(), NexusError>;

    /// Handle consensus message
    async fn on_consensus_message(&self, message: Vec<u8>) -> Result<(), NexusError>;
}

/// Balance transfer execution
pub trait Transferable {
    /// Execute a transfer between accounts
    fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: Amount,
    ) -> Result<(), NexusError>;
}
