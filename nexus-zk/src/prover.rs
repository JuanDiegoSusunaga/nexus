//! ZK Prover implementation

use crate::{ZKProof, ProofType, ProvingKey, StateTransitionInputs};
use nexus_core::NexusError;

/// ZK Prover
pub struct Prover {
    proving_keys: std::collections::HashMap<ProofType, ProvingKey>,
}

impl Prover {
    pub fn new() -> Self {
        Self {
            proving_keys: std::collections::HashMap::new(),
        }
    }

    /// Generic Groth16 proving is not implemented. Never fabricate a certificate.
    pub fn prove_state_transition(
        &self,
        _inputs: &StateTransitionInputs,
    ) -> Result<ZKProof, NexusError> {
        Err(NexusError::NotImplemented("Generic Groth16 proof generation".into()))
    }

    /// Load proving key
    pub fn load_proving_key(&mut self, key: ProvingKey) {
        self.proving_keys.insert(key.proof_type, key);
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
