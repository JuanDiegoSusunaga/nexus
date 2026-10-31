//! ZK Verifier implementation

use crate::{ZKProof, ProofType, VerificationKey, VerificationResult};
use nexus_core::NexusError;
use std::collections::HashMap;

/// ZK Verifier
pub struct Verifier {
    verification_keys: HashMap<ProofType, VerificationKey>,
}

impl Verifier {
    pub fn new() -> Self {
        Self {
            verification_keys: HashMap::new(),
        }
    }

    /// The generic Groth16 API is scaffolding, not a cryptographic verifier.
    /// Loading a key or supplying nonempty bytes must never authorize a proof.
    /// The scalar AIR/FRI verifier is a separate, explicitly bounded API.
    pub fn verify(&self, _proof: &ZKProof) -> Result<VerificationResult, NexusError> {
        Err(NexusError::NotImplemented("Generic Groth16 proof verification".into()))
    }

    /// Load verification key
    pub fn load_verification_key(&mut self, key: VerificationKey) {
        self.verification_keys.insert(key.proof_type, key);
    }

    /// Get verification key hash
    pub fn get_vk_hash(&self, proof_type: ProofType) -> Option<nexus_core::Hash256> {
        self.verification_keys.get(&proof_type).map(|k| k.hash())
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}
