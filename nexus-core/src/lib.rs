//! # NEXUS Core
//!
//! Core types, traits, and primitives for the NEXUS Dual-Chain blockchain.
//! This crate provides the foundational building blocks used across all NEXUS components.

pub mod types;
pub mod traits;
pub mod error;
pub mod block;
pub mod transaction;
pub mod state;
pub mod merkle;

pub use types::*;
pub use traits::*;
pub use error::NexusError;
pub use block::{Block, BlockHeader, BlockBody};
pub use transaction::{Transaction, TransactionType, SignedTransaction};
pub use state::{AccountState, StateRoot, InMemoryState, StateDiff, ValidatorStake};
pub use merkle::MerkleTree;

/// NEXUS protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum block size in bytes (1 MB)
pub const MAX_BLOCK_SIZE: usize = 1_048_576;

/// Maximum transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 10_000;

/// Block time target in milliseconds (2 seconds for L2, 12 seconds for L1)
pub const L1_BLOCK_TIME_MS: u64 = 12_000;
pub const L2_BLOCK_TIME_MS: u64 = 2_000;
