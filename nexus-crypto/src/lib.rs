//! # NEXUS Crypto
//!
//! Post-Quantum Cryptography module for the NEXUS blockchain.
//!
//! This crate provides:
//! - CRYSTALS-Dilithium digital signatures (NIST PQC standard)
//! - Active key-lifecycle management (min-entropy, NIST SP 800-90B health, rotation)
//! - Secure key management
//!
//! ## Security Considerations
//!
//! All private keys are zeroized on drop to prevent memory leaks.
//! The implementation uses constant-time operations where possible.

pub mod dilithium;
pub mod entropy;
pub mod keypair;
pub mod signer;

pub use dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
pub use entropy::{EntropyMonitor, SentinelSeed};
pub use keypair::{NexusKeypair, KeyManager};
pub use signer::{Signer, Verifier, verify_signed_transaction};

/// Minimum acceptable entropy level (Shannon entropy)
pub const MIN_ENTROPY_THRESHOLD: f64 = 7.5;

/// Key rotation interval in blocks
pub const KEY_ROTATION_INTERVAL: u64 = 100_000;
