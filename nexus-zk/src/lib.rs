//! # NEXUS ZK
//!
//! Zero-Knowledge proof system for the NEXUS blockchain.
//! Provides ZK-SNARK based proofs for:
//! - State transition validity
//! - Privacy-preserving transactions
//! - Biometric proof of possession

use nexus_core::{Hash256, NexusError, StateRoot};
use serde::{Deserialize, Serialize};

pub mod circuits;
pub mod prover;
pub mod verifier;

/// STARK hash-based post-cuántico (PoC del Nitro Verifier).
///
/// Implementación de referencia de un sistema de pruebas de validez cuya
/// seguridad reposa solo en funciones hash y aritmética de campo (sin
/// emparejamientos), a diferencia del andamiaje Groth16/BN254 de [`prover`] /
/// [`verifier`]. Véase [`stark`] y `nexus_active::pq_verifier`.
pub mod stark;

pub use stark::{prove_state_transition, verify_state_transition, StarkProof, TransitionStatement};

/// ZK Proof wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// Proof bytes (Groth16)
    pub proof_bytes: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<u8>,
    /// Proof type
    pub proof_type: ProofType,
}

/// Types of ZK proofs supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// State transition proof
    StateTransition,
    /// Balance proof (prove balance >= amount without revealing)
    BalanceProof,
    /// Biometric possession proof
    BiometricProof,
    /// Merkle inclusion proof
    MerkleInclusion,
}

/// Verification key for ZK proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub key_bytes: Vec<u8>,
    pub proof_type: ProofType,
}

impl VerificationKey {
    pub fn hash(&self) -> Hash256 {
        Hash256::hash(&self.key_bytes)
    }
}

/// Proving key for ZK proofs
pub struct ProvingKey {
    pub key_bytes: Vec<u8>,
    pub proof_type: ProofType,
}

/// State transition circuit inputs
#[derive(Debug, Clone)]
pub struct StateTransitionInputs {
    pub pre_state_root: StateRoot,
    pub post_state_root: StateRoot,
    pub transactions_root: Hash256,
    pub block_number: u64,
}

/// Result of ZK verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<String>,
}

impl VerificationResult {
    pub fn valid() -> Self {
        Self { valid: true, error: None }
    }

    pub fn invalid(error: String) -> Self {
        Self { valid: false, error: Some(error) }
    }
}
