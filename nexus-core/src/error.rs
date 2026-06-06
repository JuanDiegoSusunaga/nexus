//! Error types for NEXUS blockchain
//!
//! Comprehensive error handling with specific error variants for
//! each component of the NEXUS dual-chain architecture.

use thiserror::Error;
use crate::{Address, Hash256, BlockHeight};

/// Main error type for NEXUS operations
#[derive(Error, Debug)]
pub enum NexusError {
    // ============ Cryptographic Errors ============
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed for address {0}")]
    SignatureVerificationFailed(Address),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    // ============ Transaction Errors ============
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Transaction already exists: {0}")]
    DuplicateTransaction(Hash256),

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Transaction pool full")]
    TransactionPoolFull,

    #[error("Transaction expired")]
    TransactionExpired,

    // ============ Block Errors ============
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Block not found: {0}")]
    BlockNotFound(Hash256),

    #[error("Block at height {0} not found")]
    BlockHeightNotFound(BlockHeight),

    #[error("Invalid parent block: expected {expected}, got {got}")]
    InvalidParentBlock { expected: Hash256, got: Hash256 },

    #[error("Block too large: {size} bytes (max: {max})")]
    BlockTooLarge { size: usize, max: usize },

    #[error("Invalid block timestamp")]
    InvalidBlockTimestamp,

    #[error("Invalid state root: expected {expected}, got {got}")]
    InvalidStateRoot { expected: Hash256, got: Hash256 },

    // ============ Consensus Errors ============
    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),

    #[error("Not a validator")]
    NotValidator,

    #[error("Invalid validator signature")]
    InvalidValidatorSignature,

    #[error("Quorum not reached: {votes}/{required}")]
    QuorumNotReached { votes: usize, required: usize },

    #[error("Block already finalized")]
    BlockAlreadyFinalized,

    // ============ State Errors ============
    #[error("State error: {0}")]
    StateError(String),

    #[error("Account not found: {0}")]
    AccountNotFound(Address),

    #[error("Invalid state transition")]
    InvalidStateTransition,

    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(Hash256),

    // ============ Network Errors ============
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Message serialization failed: {0}")]
    SerializationError(String),

    // ============ Storage Errors ============
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Database corruption detected")]
    DatabaseCorruption,

    // ============ ZK Proof Errors ============
    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Invalid proof format")]
    InvalidProofFormat,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    // ============ Sequencer Errors ============
    #[error("Sequencer error: {0}")]
    SequencerError(String),

    #[error("Not the active sequencer")]
    NotActiveSequencer,

    #[error("Batch submission failed: {0}")]
    BatchSubmissionFailed(String),

    #[error("Batch too large")]
    BatchTooLarge,

    // ============ Security Errors ============
    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Entropy too low: {current} (minimum: {required})")]
    EntropyTooLow { current: f64, required: f64 },

    #[error("Key rotation required")]
    KeyRotationRequired,

    #[error("Invalid biometric data")]
    InvalidBiometricData,

    // ============ Configuration Errors ============
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid chain ID")]
    InvalidChainId,

    // ============ Generic Errors ============
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Timeout")]
    Timeout,

    #[error("Operation cancelled")]
    Cancelled,
}

impl NexusError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            NexusError::NetworkError(_)
                | NexusError::Timeout
                | NexusError::TransactionPoolFull
                | NexusError::QuorumNotReached { .. }
        )
    }

    /// Check if error is related to security
    pub fn is_security_related(&self) -> bool {
        matches!(
            self,
            NexusError::InvalidSignature(_)
                | NexusError::SignatureVerificationFailed(_)
                | NexusError::SecurityViolation(_)
                | NexusError::EntropyTooLow { .. }
                | NexusError::KeyRotationRequired
                | NexusError::InvalidBiometricData
                | NexusError::ProofVerificationFailed
        )
    }
}

impl From<std::io::Error> for NexusError {
    fn from(err: std::io::Error) -> Self {
        NexusError::StorageError(err.to_string())
    }
}

impl From<bincode::Error> for NexusError {
    fn from(err: bincode::Error) -> Self {
        NexusError::SerializationError(err.to_string())
    }
}

impl From<serde_json::Error> for NexusError {
    fn from(err: serde_json::Error) -> Self {
        NexusError::SerializationError(err.to_string())
    }
}

/// Result type alias for NEXUS operations
pub type NexusResult<T> = Result<T, NexusError>;
