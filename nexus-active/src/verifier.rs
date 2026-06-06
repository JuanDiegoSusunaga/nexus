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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Full ZK verification (validity rollup)
    ZKValidity,
    /// Optimistic with fraud proofs
    Optimistic,
    /// Hybrid (ZK for large batches, optimistic for small)
    Hybrid { threshold: usize },
}

/// Pending proof for optimistic mode
#[derive(Debug, Clone)]
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

    /// Verify a state proof
    pub fn verify(&mut self, proof: &StateProof) -> Result<VerificationResult, NexusError> {
        let start = std::time::Instant::now();

        let result = match self.mode {
            VerificationMode::ZKValidity => self.verify_zk(proof),
            VerificationMode::Optimistic => self.verify_optimistic(proof),
            VerificationMode::Hybrid { threshold } => {
                // Use ZK for proofs with many transactions
                if proof.proof_data.len() > threshold * 100 {
                    self.verify_zk(proof)
                } else {
                    self.verify_optimistic(proof)
                }
            }
        };

        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(mut res) => {
                res.verification_time_ms = elapsed;
                if res.valid {
                    self.verified_roots.insert(proof.height, proof.post_state_root);
                }
                Ok(res)
            }
            Err(e) => Err(e),
        }
    }

    /// Verify using a validity proof.
    ///
    /// Si `proof_data` contiene una prueba STARK post-cuántica serializada
    /// ([`crate::pq_verifier::PqValidityProof`]), se verifica **de verdad**:
    /// FRI sobre el polinomio de composición + enlace de la traza + atadura del
    /// enunciado a los roots pre/post. Es la ruta post-cuántica (sin
    /// emparejamientos) que sustituye al andamiaje Groth16/BN254.
    fn verify_zk(&self, proof: &StateProof) -> Result<VerificationResult, NexusError> {
        if proof.proof_data.is_empty() {
            return Ok(VerificationResult::invalid("Empty proof data".into()));
        }

        // Ruta post-cuántica real (STARK hash-based).
        if let Some(pq) = crate::pq_verifier::PqValidityProof::from_bytes(&proof.proof_data) {
            return if pq.verify_bound(&proof.pre_state_root, &proof.post_state_root) {
                Ok(VerificationResult::valid())
            } else {
                Ok(VerificationResult::invalid(
                    "Prueba STARK post-cuántica inválida".into(),
                ))
            };
        }

        // Ruta heredada (compatibilidad): verifica el formato de las entradas
        // públicas para pruebas que no portan un STARK serializado.
        let expected_inputs = self.compute_public_inputs(proof);
        if proof.public_inputs != expected_inputs {
            return Ok(VerificationResult::invalid("Public inputs mismatch".into()));
        }
        Ok(VerificationResult::valid())
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
        fraud_proof: &FraudProof,
        original: &StateProof,
    ) -> Result<bool, NexusError> {
        // Re-execute the disputed transaction
        // Compare result with claimed post-state
        // If different, fraud is proven

        // Simplified implementation
        if fraud_proof.disputed_tx_index < fraud_proof.execution_trace.len() {
            // Check if re-execution produces different result
            let trace = &fraud_proof.execution_trace[fraud_proof.disputed_tx_index];
            if trace.computed_root != fraud_proof.claimed_root {
                return Ok(true); // Fraud proven
            }
        }

        Ok(false)
    }

    /// Compute public inputs for ZK verification
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

        // No successful challenge, finalize
        let height = pending.proof.height;
        let root = pending.proof.post_state_root;

        self.verified_roots.insert(height, root);
        self.pending_proofs.remove(&proof_hash);

        Ok(true)
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
    fn test_zk_verification() {
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
        assert!(result.valid);
    }

    #[test]
    fn test_real_stark_pq_verification() {
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

        // La verificación ejecuta FRI + restricciones + atadura de roots.
        let result = verifier.verify(&proof).unwrap();
        assert!(result.valid, "una prueba STARK válida debe aceptarse");
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
