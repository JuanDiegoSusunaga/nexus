//! La aceptación exige certificado vinculado y contexto suministrado aparte.
use nexus_active::{ExpectedTransition, LinkedValidityProof,
    linked_verifier::{public_inputs, scalar_root, verify_expected},
    verifier::{NitroVerifier, ProofType, StateProof, VerificationMode}};
use nexus_core::{BlockHeight, Hash256, StateRoot};
use nexus_zk::stark::field::{Felt, P};
use std::sync::OnceLock;

fn fixture() -> (StateProof, ExpectedTransition) {
    static CASE: OnceLock<(StateProof, ExpectedTransition)> = OnceLock::new();
    CASE.get_or_init(|| {
        let pre = scalar_root(Felt::new(3));
        let linked = LinkedValidityProof::prove(&pre, 5, 16).unwrap();
        let expected = ExpectedTransition { pre, post: linked.post_root(), height: BlockHeight(1),
            steps: 16, pow_bits: LinkedValidityProof::runtime_pow_bits() };
        let proof = StateProof { proof_type: ProofType::ZKValidity, pre_state_root: pre,
            post_state_root: expected.post, height: expected.height,
            proof_data: linked.to_bytes().unwrap(), public_inputs: public_inputs(&expected) };
        (proof, expected)
    }).clone()
}

#[test]
fn solo_la_ruta_con_contexto_registra_una_raiz_tras_aceptar() {
    let (proof, expected) = fixture();
    let mut verifier = NitroVerifier::new(VerificationMode::ZKValidity);
    assert!(!verifier.verify(&proof).unwrap().valid);
    assert!(verifier.get_verified_root(expected.height).is_none());
    assert!(verifier.verify_expected(&proof, &expected).unwrap().valid);
    assert!(verifier.is_verified(expected.height, expected.post));
}

#[test]
fn rechaza_basura_truncados_sufijos_y_perfiles_sin_cambiar_estado() {
    let (proof, expected) = fixture();
    for payload in [vec![], vec![1, 2, 3, 4], proof.proof_data[..40].to_vec(),
        [proof.proof_data.as_slice(), &[0]].concat()] {
        let mut changed = proof.clone();
        changed.proof_data = payload;
        let mut verifier = NitroVerifier::new(VerificationMode::ZKValidity);
        assert!(!verifier.verify_expected(&changed, &expected).unwrap().valid);
        assert!(verifier.get_verified_root(expected.height).is_none());
    }
    let mut wrong = expected.clone();
    wrong.pow_bits = if expected.pow_bits == 12 { 20 } else { 12 };
    assert!(verify_expected(&proof, &wrong).is_err());
}

#[test]
fn contexto_tipo_altura_entradas_y_todas_las_coordenadas_se_comprueban() {
    let (proof, expected) = fixture();
    for case in 0..4 {
        let mut changed = proof.clone();
        match case {
            0 => changed.proof_type = ProofType::FraudProof,
            1 => changed.proof_type = ProofType::Optimistic,
            2 => changed.height = BlockHeight(99),
            _ => changed.public_inputs[71] ^= 1,
        }
        assert!(verify_expected(&changed, &expected).is_err());
    }
    for byte in 0..32 {
        for pre in [true, false] {
            let mut changed = proof.clone();
            let mut context = expected.clone();
            if pre { context.pre.0.0[byte] ^= 1; changed.pre_state_root = context.pre; }
            else { context.post.0.0[byte] ^= 1; changed.post_state_root = context.post; }
            changed.public_inputs = public_inputs(&context);
            assert!(verify_expected(&changed, &context).is_err());
        }
    }
}

#[test]
fn no_reinterpreta_hashes_arbitrarios_ni_alias_modulares_como_escalares() {
    let (mut proof, mut expected) = fixture();
    expected.pre = StateRoot::new(Hash256::hash(b"raiz de estado completa"));
    proof.pre_state_root = expected.pre;
    proof.public_inputs = public_inputs(&expected);
    assert!(verify_expected(&proof, &expected).is_err());
    let (mut proof, mut expected) = fixture();
    expected.pre.0.0[..8].copy_from_slice(&(P + 3).to_le_bytes());
    proof.pre_state_root = expected.pre;
    proof.public_inputs = public_inputs(&expected);
    assert!(verify_expected(&proof, &expected).is_err());
}

#[test]
fn altura_es_contexto_externo_y_no_se_anuncia_como_restriccion_air() {
    let (mut proof, mut expected) = fixture();
    expected.height = BlockHeight(2);
    proof.height = expected.height;
    proof.public_inputs = public_inputs(&expected);
    assert!(verify_expected(&proof, &expected).is_ok());
}

#[test]
fn modo_hibrido_no_cae_a_aceptacion_optimista_por_tamano() {
    let (proof, expected) = fixture();
    let mut verifier = NitroVerifier::new(VerificationMode::Hybrid { threshold: usize::MAX });
    assert!(!verifier.verify(&proof).unwrap().valid);
    assert!(verifier.get_verified_root(expected.height).is_none());
    assert!(verifier.verify_expected(&proof, &expected).unwrap().valid);
}

#[test]
fn modo_optimista_no_registra_raiz_antes_de_finalizar_ni_acredita_el_contrato() {
    let (mut proof, expected) = fixture();
    proof.proof_type = ProofType::Optimistic;
    let mut verifier = NitroVerifier::new(VerificationMode::Optimistic);
    assert!(!verifier.verify_expected(&proof, &expected).unwrap().valid);
    assert!(verifier.verify(&proof).unwrap().valid);
    assert!(verifier.get_verified_root(expected.height).is_none());
}
