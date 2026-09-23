//! Contrasta la proximidad exigida por S2 con aceptaciones del ejecutable real.
#[path = "../experiments/tg2_trace_proximity.rs"]
mod experiment;

use experiment::{audit_full_trace, prepare, prove, verify_with_full_trace, AuditError, Experiment};
use nexus_core::Hash256;
use nexus_zk::stark::{
    air::StarkProof,
    field::{root_of_unity, Felt, GENERATOR, P},
    merkle::MerkleTree,
    ntt::{coset_ntt, eval_at, intt},
    verify_state_transition,
};
use std::sync::OnceLock;

fn cases() -> &'static Vec<(Experiment, StarkProof)> {
    static CASES: OnceLock<Vec<(Experiment, StarkProof)>> = OnceLock::new();
    CASES.get_or_init(|| [16, 32, 64].into_iter().map(|t| {
        let case = prepare(t, Felt::new(3), Felt::new(5), Felt::ONE).unwrap();
        let proof = prove(&case).unwrap();
        (case, proof)
    }).collect())
}

fn honest() -> &'static (Experiment, StarkProof) {
    static HONEST: OnceLock<(Experiment, StarkProof)> = OnceLock::new();
    HONEST.get_or_init(|| {
        let case = prepare(16, Felt::new(3), Felt::new(5), Felt::ZERO).unwrap();
        let proof = prove(&case).unwrap();
        (case, proof)
    })
}

#[test]
fn familia_conserva_filas_y_composicion_dentro_de_cota() {
    for t in [4, 8, 16, 32, 64, 128, 256] {
        for lambda in [1, 3, 11] {
            let case = prepare(t, Felt::new(3), Felt::new(5), Felt::new(lambda)).unwrap();
            assert_eq!(case.coefficients.iter().rposition(|&c| c != Felt::ZERO), Some(t));
            let g = root_of_unity(t.trailing_zeros());
            for i in 0..t {
                assert_eq!(eval_at(&case.coefficients, g.pow(i as u64)), case.original_trace[i]);
            }
            for component in [0, 1] {
                let evaluations: Vec<_> = case.cp_evals.iter()
                    .map(|c| if component == 0 { c.c0 } else { c.c1 }).collect();
                // La INTT conserva el grado aunque los coeficientes estén escalados por el coset.
                let coefficients = intt(&evaluations);
                assert!(coefficients[t+3..].iter().all(|&c| c == Felt::ZERO));
                assert!(t+2 < 2*t);
            }
        }
    }
}

#[test]
fn verificador_acepta_trazas_a_distancia_siete_octavos() {
    for (case, proof) in cases() {
        let t = case.statement.steps;
        assert!(verify_state_transition(&case.statement, proof));
        assert_eq!(proof.trace_root, MerkleTree::commit(&case.trace_evals).root());
        assert_eq!(case.coefficients[t], Felt::ONE);
        eprintln!("TG2_TRAZA_LEJANA T={t} N={} grado_traza={t} cota_cp={} distancia=7/8 acepta=true",
            8*t, t+2);
        // Corpus optativo y público: inicio 3, testigo de demostración 5 y prueba completa.
        if let Ok(directory) = std::env::var("NEXUS_TG2_TRACE_EVIDENCE_DIR") {
            let directory = std::path::Path::new(&directory);
            std::fs::create_dir_all(directory).unwrap();
            let bytes = bincode::serialize(&(&case.statement, proof, &case.trace_evals)).unwrap();
            let decoded: (nexus_zk::stark::air::TransitionStatement, StarkProof, Vec<Felt>) =
                bincode::deserialize(&bytes).unwrap();
            assert!(verify_state_transition(&decoded.0, &decoded.1));
            assert_eq!(audit_full_trace(&decoded.0, &decoded.1.trace_root, &decoded.2),
                Err(AuditError::Degree));
            std::fs::write(directory.join(format!("traza-lejana-{t}.bin")), bytes).unwrap();
        }
    }
}

#[test]
fn distancia_exacta_al_codigo_tiene_testigo_de_t_acuerdos() {
    for (case, _) in cases() {
        let t = case.statement.steps;
        let n = 8*t;
        let omega = root_of_unity(n.trailing_zeros());
        let mut product = vec![Felt::ONE];
        for i in 0..t {
            let x = Felt::new(GENERATOR).mul(omega.pow(i as u64));
            let mut next = vec![Felt::ZERO; product.len()+1];
            for (j, &c) in product.iter().enumerate() {
                next[j] = next[j].sub(c.mul(x));
                next[j+1] = next[j+1].add(c);
            }
            product = next;
        }
        let mut nearest = case.coefficients.clone();
        for (i, c) in product.into_iter().enumerate() {
            nearest[i] = nearest[i].sub(case.coefficients[t].mul(c));
        }
        assert!(nearest[t..].iter().all(|&c| c == Felt::ZERO));
        let values = coset_ntt(&nearest, Felt::new(GENERATOR));
        assert_eq!(values.iter().zip(&case.trace_evals).filter(|(a,b)| a == b).count(), t);
        // Cualquier otro candidato de grado <T tiene a lo sumo T acuerdos: diferencia de grado T.
        let mut original = intt(&case.original_trace);
        original.resize(n, Felt::ZERO);
        assert!(coset_ntt(&original, Felt::new(GENERATOR)).iter()
            .zip(&case.trace_evals).all(|(a,b)| a != b));
    }
}

#[test]
fn control_exhaustivo_acepta_ejecucion_honesta() {
    let (case, proof) = honest();
    assert!(verify_state_transition(&case.statement, proof));
    assert_eq!(audit_full_trace(&case.statement, &proof.trace_root, &case.trace_evals),
        Ok(case.original_trace.clone()));
    assert_eq!(verify_with_full_trace(&case.statement, proof, &case.trace_evals), Ok(()));
}

#[test]
fn control_exhaustivo_rechaza_el_grado_de_las_aceptaciones_heredadas() {
    for (case, proof) in cases() {
        assert!(verify_state_transition(&case.statement, proof));
        assert_eq!(verify_with_full_trace(&case.statement, proof, &case.trace_evals),
            Err(AuditError::Degree));
    }
}

#[test]
fn control_exhaustivo_valida_limites_compromiso_y_restricciones() {
    let (case, proof) = honest();
    let mut statement = case.statement.clone();
    statement.steps = 512;
    assert_eq!(audit_full_trace(&statement, &proof.trace_root, &[]), Err(AuditError::Rows));
    assert_eq!(audit_full_trace(&case.statement, &proof.trace_root, &[]), Err(AuditError::Length));
    let noncanonical: Felt = bincode::deserialize(&P.to_le_bytes()).unwrap();
    let mut noncanonical_values = case.trace_evals.clone();
    noncanonical_values[0] = noncanonical;
    assert_eq!(audit_full_trace(&case.statement, &proof.trace_root, &noncanonical_values),
        Err(AuditError::NonCanonical));
    statement = case.statement.clone();
    statement.start = noncanonical;
    assert_eq!(audit_full_trace(&statement, &proof.trace_root, &case.trace_evals),
        Err(AuditError::NonCanonical));
    assert_eq!(audit_full_trace(&case.statement, &Hash256::hash(b"otra raiz"), &case.trace_evals),
        Err(AuditError::Commitment));
    statement = case.statement.clone();
    statement.start = statement.start.add(Felt::ONE);
    assert_eq!(audit_full_trace(&statement, &proof.trace_root, &case.trace_evals), Err(AuditError::Initial));
    statement = case.statement.clone();
    statement.output = statement.output.add(Felt::ONE);
    assert_eq!(audit_full_trace(&statement, &proof.trace_root, &case.trace_evals), Err(AuditError::Final));
    let mut changed = case.original_trace.clone();
    changed[8] = changed[8].add(Felt::ONE);
    let mut coefficients = intt(&changed);
    coefficients.resize(128, Felt::ZERO);
    let values = coset_ntt(&coefficients, Felt::new(GENERATOR));
    assert_eq!(audit_full_trace(&case.statement, &MerkleTree::commit(&values).root(), &values),
        Err(AuditError::Transition));
    assert!(prepare(3, Felt::ZERO, Felt::ZERO, Felt::ONE).is_err());
}

#[test]
fn pruebas_reales_siguen_ligadas_al_enunciado_y_aperturas() {
    let (case, proof) = &cases()[0];
    let mut statement = case.statement.clone();
    statement.start = statement.start.add(Felt::ONE);
    assert!(!verify_state_transition(&statement, proof));
    statement = case.statement.clone();
    statement.output = statement.output.add(Felt::ONE);
    assert!(!verify_state_transition(&statement, proof));
    let mut changed = proof.clone();
    changed.queries[0].trace[0].value = changed.queries[0].trace[0].value.add(Felt::ONE);
    assert!(!verify_state_transition(&case.statement, &changed));
    let (good_case, good_proof) = honest();
    let mut changed = good_proof.clone();
    changed.fri_final = changed.fri_final.add(nexus_zk::stark::field::Fp2::ONE);
    assert_eq!(verify_with_full_trace(&good_case.statement, &changed, &good_case.trace_evals),
        Err(AuditError::Stark));
}
