//! Nitro Verifier - State Transition Verification
//!
//! The Nitro Verifier validates state transitions using:
//! - Zero-knowledge proofs for validity
//! - Fraud proofs for optimistic mode
//! - State commitment verification

use nexus_core::{Hash256, NexusError, StateRoot, BlockHeight, Address, SignedTransaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// State transition proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// Proof type
    pub proof_type: ProofType,
    /// Pre-state root
    pub pre_state_root: StateRoot,
    /// Post-state root
    pub post_state_root: StateRoot,
    /// Block height
    pub height: BlockHeight,
    /// Proof data (ZK proof or fraud proof)
    pub proof_data: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<u8>,
}

/// Type of proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Zero-knowledge validity proof
    ZKValidity,
    /// Optimistic with fraud proof window
    Optimistic,
    /// Fraud proof (proves invalid transition)
    FraudProof,
}

/// Result of verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification passed
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Gas used for verification
    pub gas_used: u64,
    /// Verification time (ms)
    pub verification_time_ms: u64,
}

impl VerificationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            error: None,
            gas_used: 0,
            verification_time_ms: 0,
        }
    }

    pub fn invalid(error: String) -> Self {
        Self {
            valid: false,
            error: Some(error),
            gas_used: 0,
            verification_time_ms: 0,
        }
    }
}

/// The Nitro Verifier
#[derive(Serialize, Deserialize)]
pub struct NitroVerifier {
    /// Verification mode
    mode: VerificationMode,
    /// Verified state roots
    verified_roots: HashMap<BlockHeight, StateRoot>,
    /// Pending proofs (for optimistic mode)
    pending_proofs: HashMap<Hash256, PendingProof>,
    /// Challenge period (ms) for optimistic mode
    challenge_period_ms: u64,
    /// ZK verification key hash
    vk_hash: Hash256,
}

/// Verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Full ZK verification (validity rollup)
    ZKValidity,
    /// Optimistic with fraud proofs
    Optimistic,
    /// Hybrid (ZK for large batches, optimistic for small)
    Hybrid { threshold: usize },
}

/// Pending proof for optimistic mode
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingProof {
    proof: StateProof,
    submitted_at: nexus_core::Timestamp,
    challenger: Option<Address>,
}

impl NitroVerifier {
    /// Create a new Nitro Verifier
    pub fn new(mode: VerificationMode) -> Self {
        Self {
            mode,
            verified_roots: HashMap::new(),
            pending_proofs: HashMap::new(),
            challenge_period_ms: 7 * 24 * 60 * 60 * 1000, // 7 days
            vk_hash: Hash256::ZERO, // Would be set from actual VK
        }
    }

    /// Create with custom challenge period
    pub fn with_challenge_period(mode: VerificationMode, challenge_period_ms: u64) -> Self {
        Self {
            mode,
            verified_roots: HashMap::new(),
            pending_proofs: HashMap::new(),
            challenge_period_ms,
            vk_hash: Hash256::ZERO,
        }
    }

    /// La entrada sin contexto no acepta pruebas de validez ni modo híbrido.
    /// Para esos modos debe usarse `verify_expected`; el modo optimista queda separado.
    pub fn verify(&mut self, proof: &StateProof) -> Result<VerificationResult, NexusError> {
        let start = std::time::Instant::now();

        let result = match self.mode {
            VerificationMode::ZKValidity | VerificationMode::Hybrid { .. } =>
                Ok(VerificationResult::invalid("Se requiere verify_expected con contexto confiable y certificado vinculado".into())),
            VerificationMode::Optimistic => self.verify_optimistic(proof),
        };

        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(mut res) => {
                res.verification_time_ms = elapsed;
                // Una prueba optimista pendiente no es una raíz finalizada.
                Ok(res)
            }
            Err(e) => Err(e),
        }
    }

    /// Valida el perfil matemático antes de registrar la raíz del contexto.
    /// No extrae contexto confiable del mensaje ni implementa una L2 completa.
    pub fn verify_expected(&mut self, proof: &StateProof, expected: &crate::linked_verifier::ExpectedTransition)
        -> Result<VerificationResult, NexusError> {
        let start = std::time::Instant::now();
        if self.mode == VerificationMode::Optimistic {
            return Ok(VerificationResult::invalid("El modo optimista no valida el contrato de Lean".into()));
        }
        if let Some(root) = self.verified_roots.get(&expected.height) {
            if *root != expected.post {
                return Ok(VerificationResult::invalid("La altura ya tiene otra raíz verificada".into()));
            }
        }
        if let Err(error) = crate::linked_verifier::verify_expected(proof, expected) {
            return Ok(VerificationResult::invalid(error.to_string()));
        }
        self.verified_roots.insert(expected.height, expected.post);
        let mut result = VerificationResult::valid();
        result.verification_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Verify using optimistic approach
    fn verify_optimistic(&mut self, proof: &StateProof) -> Result<VerificationResult, NexusError> {
        let proof_hash = Hash256::hash(&bincode::serialize(proof).unwrap());

        // Add to pending
        self.pending_proofs.insert(
            proof_hash,
            PendingProof {
                proof: proof.clone(),
                submitted_at: nexus_core::Timestamp::now(),
                challenger: None,
            },
        );

        // In optimistic mode, we accept immediately but allow challenges
        Ok(VerificationResult {
            valid: true,
            error: None,
            gas_used: 21000, // Base gas
            verification_time_ms: 0,
        })
    }

    /// Submit a fraud proof
    pub fn submit_fraud_proof(
        &mut self,
        proof_hash: Hash256,
        fraud_proof: FraudProof,
    ) -> Result<bool, NexusError> {
        let pending = self
            .pending_proofs
            .get(&proof_hash)
            .ok_or(NexusError::StateError("Proof not found".into()))?;

        // Check challenge period hasn't expired
        let elapsed = nexus_core::Timestamp::now().elapsed_since(pending.submitted_at);
        if elapsed > self.challenge_period_ms {
            return Err(NexusError::StateError("Challenge period expired".into()));
        }

        // Verify fraud proof
        if self.verify_fraud_proof(&fraud_proof, &pending.proof)? {
            // Fraud proven - remove the invalid state root
            self.verified_roots.remove(&pending.proof.height);
            self.pending_proofs.remove(&proof_hash);
            return Ok(true);
        }

        Ok(false)
    }

    /// Verify a fraud proof
    fn verify_fraud_proof(
        &self,
        _fraud_proof: &FraudProof,
        _original: &StateProof,
    ) -> Result<bool, NexusError> {
        // There is no authenticated prestate/inclusion/re-execution contract yet.
        // Untrusted traces cannot certify fraud (thesis sections 3.5 and 6.7.9).
        Ok(false)
    }

    /// Entradas de las pruebas históricas; no habilitan aceptación por formato.
    #[cfg(test)]
    fn compute_public_inputs(&self, proof: &StateProof) -> Vec<u8> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(proof.pre_state_root.0.as_bytes());
        inputs.extend_from_slice(proof.post_state_root.0.as_bytes());
        inputs.extend_from_slice(&proof.height.0.to_le_bytes());
        inputs
    }

    /// Finalize a pending proof (after challenge period)
    pub fn finalize_proof(&mut self, proof_hash: Hash256) -> Result<bool, NexusError> {
        let pending = self
            .pending_proofs
            .get(&proof_hash)
            .ok_or(NexusError::StateError("Proof not found".into()))?;

        let elapsed = nexus_core::Timestamp::now().elapsed_since(pending.submitted_at);
        if elapsed < self.challenge_period_ms {
            return Ok(false); // Challenge period not over
        }

        // A timeout cannot replace the missing fraud-verification contract.
        // Optimistic acceptance stays provisional until that contract exists.
        Err(NexusError::NotImplemented("Authenticated optimistic finalization".into()))
    }

    /// Get verified state root at height
    pub fn get_verified_root(&self, height: BlockHeight) -> Option<StateRoot> {
        self.verified_roots.get(&height).copied()
    }

    /// Check if a state root is verified
    pub fn is_verified(&self, height: BlockHeight, root: StateRoot) -> bool {
        self.verified_roots.get(&height) == Some(&root)
    }

    /// Get verification mode
    pub fn mode(&self) -> VerificationMode {
        self.mode
    }

    /// Get challenge period
    pub fn challenge_period_ms(&self) -> u64 {
        self.challenge_period_ms
    }
}

/// Fraud proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProof {
    /// Index of the disputed transaction
    pub disputed_tx_index: usize,
    /// The disputed transaction
    pub disputed_tx: SignedTransaction,
    /// Pre-state for re-execution
    pub pre_state: Vec<u8>,
    /// Execution trace
    pub execution_trace: Vec<ExecutionStep>,
    /// Claimed (incorrect) root
    pub claimed_root: StateRoot,
    /// Correct root after re-execution
    pub correct_root: StateRoot,
}

/// Single execution step in trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    /// Operation type
    pub op: String,
    /// State before
    pub pre_state_hash: Hash256,
    /// State after
    pub post_state_hash: Hash256,
    /// Computed root
    pub computed_root: StateRoot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let verifier = NitroVerifier::new(VerificationMode::ZKValidity);
        assert_eq!(verifier.mode(), VerificationMode::ZKValidity);
    }

    #[test]
    fn test_zk_rejects_format_only_without_context() {
        let mut verifier = NitroVerifier::new(VerificationMode::ZKValidity);

        let proof = StateProof {
            proof_type: ProofType::ZKValidity,
            pre_state_root: StateRoot::EMPTY,
            post_state_root: StateRoot::new(Hash256::hash(b"post")),
            height: BlockHeight::new(1),
            proof_data: vec![1, 2, 3, 4], // Non-empty
            public_inputs: vec![],
        };

        // Update public inputs to match
        let mut proof = proof;
        proof.public_inputs = verifier.compute_public_inputs(&proof);

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_legacy_stark_requires_linked_contract_and_context() {
        use crate::pq_verifier::PqValidityProof;

        let mut verifier = NitroVerifier::new(VerificationMode::ZKValidity);

        // Genera una prueba STARK post-cuántica real para una transición.
        let pre = StateRoot::new(Hash256::hash(b"pre"));
        let pq = PqValidityProof::prove(&pre, 11, 16);
        let post = pq.post_root();

        let proof = StateProof {
            proof_type: ProofType::ZKValidity,
            pre_state_root: pre,
            post_state_root: post,
            height: BlockHeight::new(1),
            proof_data: pq.to_bytes(), // STARK serializado
            public_inputs: vec![],
        };

        // El formato heredado no habilita la aceptación del verificador activo.
        let result = verifier.verify(&proof).unwrap();
        assert!(!result.valid, "el STARK heredado no reemplaza el contrato vinculado ni el contexto confiable");
    }

    #[test]
    fn test_stark_pq_rejects_wrong_post_root() {
        use crate::pq_verifier::PqValidityProof;

        let mut verifier = NitroVerifier::new(VerificationMode::ZKValidity);
        let pre = StateRoot::new(Hash256::hash(b"pre"));
        let pq = PqValidityProof::prove(&pre, 11, 16);

        let proof = StateProof {
            proof_type: ProofType::ZKValidity,
            pre_state_root: pre,
            post_state_root: StateRoot::new(Hash256::hash(b"post-falso")), // no atado
            height: BlockHeight::new(1),
            proof_data: pq.to_bytes(),
            public_inputs: vec![],
        };

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.valid, "un post-state no atado debe rechazarse");
    }

    #[test]
    fn test_optimistic_verification() {
        let mut verifier = NitroVerifier::with_challenge_period(
            VerificationMode::Optimistic,
            1000, // 1 second for testing
        );

        let proof = StateProof {
            proof_type: ProofType::Optimistic,
            pre_state_root: StateRoot::EMPTY,
            post_state_root: StateRoot::new(Hash256::hash(b"post")),
            height: BlockHeight::new(1),
            proof_data: vec![],
            public_inputs: vec![],
        };

        let result = verifier.verify(&proof).unwrap();
        assert!(result.valid);
    }
}
