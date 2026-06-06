//! # NEXUS Active Layer (L2)
//!
//! The Active Layer provides high-throughput execution for the NEXUS dual-chain:
//!
//! - **Nexus Sequencer**: Orders and batches transactions
//! - **Nitro Verifier**: Validates state transitions with ZK proofs
//! - **Execution Engine**: Processes transactions at high speed
//! - **Batch Submission**: Commits state to Anchor Layer
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   Active Layer (L2)                      │
//! ├─────────────────────────────────────────────────────────┤
//! │  ┌───────────────────┐  ┌─────────────────────────────┐ │
//! │  │  Nexus Sequencer  │  │      Nitro Verifier         │ │
//! │  │  - Tx Ordering    │  │  - State Transition Proofs  │ │
//! │  │  - Batch Building │  │  - Fraud Proof Detection    │ │
//! │  └───────────────────┘  └─────────────────────────────┘ │
//! │  ┌───────────────────┐  ┌─────────────────────────────┐ │
//! │  │ Execution Engine  │  │    Batch Submitter          │ │
//! │  │  - Fast Processing│  │  - L1 Commitment            │ │
//! │  │  - State Updates  │  │  - DA Publication           │ │
//! │  └───────────────────┘  └─────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod sequencer;
pub mod verifier;
pub mod pq_verifier;
pub mod execution;
pub mod batch;
pub mod chain;

pub use sequencer::{NexusSequencer, SequencerConfig, SequencerMode};
pub use verifier::{NitroVerifier, VerificationResult, StateProof};
pub use pq_verifier::PqValidityProof;
pub use execution::{ExecutionEngine, ExecutionResult};
pub use batch::{BatchBuilder, L2Batch, BatchStatus};
pub use chain::{ActiveChain, ActiveChainConfig};
