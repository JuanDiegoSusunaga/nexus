//! No generic placeholder may certify arbitrary proof bytes.
use nexus_core::NexusError;
use nexus_zk::{ProofType, VerificationKey, ZKProof, verifier::Verifier};

#[test]
fn generic_prover_never_fabricates_a_transition_certificate() {
    use nexus_core::{Hash256, StateRoot};
    use nexus_zk::{ProvingKey, StateTransitionInputs, prover::Prover};
    let mut prover = Prover::new();
    prover.load_proving_key(ProvingKey { key_bytes: vec![1; 32], proof_type: ProofType::StateTransition });
    let inputs = StateTransitionInputs { pre_state_root: StateRoot::EMPTY,
        post_state_root: StateRoot::EMPTY, transactions_root: Hash256::ZERO, block_number: 1 };
    assert!(matches!(prover.prove_state_transition(&inputs), Err(NexusError::NotImplemented(_))));
}

#[test]
fn generic_api_never_accepts_bytes_even_with_a_registered_key() {
    for proof_type in [ProofType::StateTransition, ProofType::BalanceProof,
        ProofType::BiometricProof, ProofType::MerkleInclusion] {
        let mut verifier = Verifier::new();
        for registered in [false, true] {
            if registered {
                verifier.load_verification_key(VerificationKey { key_bytes: vec![1; 32], proof_type });
            }
            for proof_bytes in [vec![], vec![1], vec![0; 256]] {
                let proof = ZKProof { proof_bytes, public_inputs: vec![2; 104], proof_type };
                assert!(matches!(verifier.verify(&proof), Err(NexusError::NotImplemented(_))));
            }
        }
    }
}
