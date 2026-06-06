//! # NEXUS Anchor Layer (L1)
//!
//! The Anchor Layer provides the foundation for the NEXUS dual-chain architecture:
//!
//! - **Consensus**: Proof-of-Stake consensus with post-quantum signatures
//! - **Data Availability**: Ensures L2 data can always be reconstructed
//! - **Settlement**: Final settlement layer for L2 state transitions
//! - **Validator Management**: Registration, staking, and slashing
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Anchor Layer (L1)               │
//! ├─────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │  Consensus  │  │  Data Availability  │  │
//! │  │   Engine    │  │      Layer          │  │
//! │  └─────────────┘  └─────────────────────┘  │
//! │  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │  Validator  │  │     Finality        │  │
//! │  │    Set      │  │     Gadget          │  │
//! │  └─────────────┘  └─────────────────────┘  │
//! └─────────────────────────────────────────────┘
//! ```

pub mod consensus;
pub mod validator;
pub mod data_availability;
pub mod finality;
pub mod chain;

pub use consensus::{ConsensusEngine, ProofOfStake, ConsensusConfig};
pub use validator::{Validator, ValidatorSet, ValidatorRegistry};
pub use data_availability::{DataAvailabilityLayer, DAProof, DACommitment};
pub use finality::{FinalityGadget, FinalizedBlock};
pub use chain::{AnchorChain, AnchorChainConfig};
