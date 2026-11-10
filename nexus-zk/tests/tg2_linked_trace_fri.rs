//! Pruebas de la variante TG2: raíz compartida, transcripción y doble FRI.
#[path = "../experiments/tg2_linked_trace_fri.rs"]
mod linked;

use linked::{prove_from_evals, verify, LinkedProof, VerifyError};
use nexus_core::Hash256;
use nexus_zk::stark::{
    air::{StarkProof, TransitionStatement},
    channel::{Channel, TAG_FINAL, TAG_FRI_ROOT, TAG_STATEMENT, TAG_TRACE_ROOT},
    field::{Felt, Fp2, GENERATOR, P},
    fri::{derive_query_indices, NUM_QUERIES},
    merkle::MerkleTree,
    ntt::{coset_ntt, intt},
    params::POW_BITS_RUNTIME,
    verify_state_transition,
};
use std::{path::PathBuf, sync::OnceLock};

fn input(t: usize) -> (TransitionStatement, Vec<Felt>) {
    let mut trace = vec![Felt::new(3), Felt::new(5)];
    for i in 2..t { trace.push(trace[i-1].mul(trace[i-1]).add(trace[i-2].mul(trace[i-2]))); }
    let statement = TransitionStatement { start: trace[0], output: trace[t-1], steps: t };
    let mut coefficients = intt(&trace);
    coefficients.resize(8*t, Felt::ZERO);
    (statement, coset_ntt(&coefficients, Felt::new(GENERATOR)))
}

fn honest() -> &'static Vec<(TransitionStatement, Vec<Felt>, LinkedProof)> {
    static CASES: OnceLock<Vec<(TransitionStatement, Vec<Felt>, LinkedProof)>> = OnceLock::new();
    CASES.get_or_init(|| [16, 64, 256, 4096].into_iter().map(|t| {
        let (statement, values) = input(t);
        let proof = prove_from_evals(&statement, &values).unwrap();
        (statement, values, proof)
    }).collect())
}

fn corpus(t: usize) -> (TransitionStatement, StarkProof, Vec<Felt>) {
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Documentos/06-Evidencia-TG2/2026-09-22/R4-proximidad")
        .join(format!("corpus-{profile}/traza-lejana-{t}.bin"));
    bincode::deserialize(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn acepta_casos_honestos_y_serializacion_sin_lde_completo() {
    for (statement, _, proof) in honest() {
        assert_eq!(verify(statement, proof), Ok(()));
        let bytes = bincode::serialize(&(statement, proof)).unwrap();
        let decoded: (TransitionStatement, LinkedProof) = bincode::deserialize(&bytes).unwrap();
        assert_eq!(verify(&decoded.0, &decoded.1), Ok(()));
        assert_eq!(proof.queries.len(), 40);
        assert!(proof.queries.iter().all(|q| q.trace.len() == 6));
        eprintln!("TG2_FRI_VINCULADO T={} N={} bytes={} capas_traza={} capas_cp={} consultas=40 honesto=true",
            statement.steps, 8*statement.steps, bytes.len(),
            proof.trace_fri.roots.len(), proof.composition_fri.roots.len());
        if let Ok(directory) = std::env::var("NEXUS_TG2_LINKED_EVIDENCE_DIR") {
            let directory = PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(format!("honesto-{}.bin", statement.steps)), bytes).unwrap();
        }
    }
}

#[test]
fn rechaza_los_tres_contraejemplos_preservados_en_fri_de_traza() {
    for t in [16, 32, 64] {
        let (statement, legacy, values) = corpus(t);
        assert!(verify_state_transition(&statement, &legacy));
        let proof = prove_from_evals(&statement, &values).unwrap();
        assert_eq!(verify(&statement, &proof), Err(VerifyError::TraceFri));
        eprintln!("TG2_FRI_RECHAZO T={t} legado=true variante=TraceFri");
        if let Ok(directory) = std::env::var("NEXUS_TG2_LINKED_EVIDENCE_DIR") {
            let directory = PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(format!("lejano-{t}.bin")),
                bincode::serialize(&(statement, proof)).unwrap()).unwrap();
        }
    }
}

#[test]
fn raiz_y_codificacion_son_comunes_al_air_y_fri_de_traza() {
    let (statement, values, proof) = &honest()[0];
    let lifted: Vec<_> = values.iter().copied().map(Fp2::from_base).collect();
    assert_eq!(proof.trace_root, MerkleTree::commit(&lifted).root());
    assert_eq!(proof.trace_root, proof.trace_fri.roots[0]);
    assert_ne!(proof.trace_root, MerkleTree::commit(values).root());
    let mut changed = proof.clone();
    changed.trace_fri.roots[0] = honest()[1].2.trace_fri.roots[0];
    assert_eq!(verify(statement, &changed), Err(VerifyError::TraceRoot));
}

#[test]
fn enunciado_version_y_perfil_no_se_pueden_sustituir() {
    let (statement, _, proof) = &honest()[0];
    for field in 0..3 {
        let mut changed = statement.clone();
        match field {
            0 => changed.start = changed.start.add(Felt::ONE),
            1 => changed.output = changed.output.add(Felt::ONE),
            _ => changed.steps *= 2,
        }
        assert!(verify(&changed, proof).is_err());
    }
    let mut changed = proof.clone();
    changed.version += 1;
    assert_eq!(verify(statement, &changed), Err(VerifyError::Profile));
    changed = proof.clone();
    changed.pow_bits = 0;
    assert_eq!(verify(statement, &changed), Err(VerifyError::Profile));
}

#[test]
fn detecta_valores_caminos_y_enlaces_alterados() {
    let (statement, _, proof) = &honest()[0];
    for kind in 0..6 {
        let mut changed = proof.clone();
        let query = &mut changed.queries[0];
        match kind {
            0 => query.trace[0].value = query.trace[0].value.add(Felt::ONE),
            1 => query.trace[1].proof.siblings[0] = Hash256::hash(b"camino alterado"),
            2 => query.trace_fri.layers[0].left = query.trace_fri.layers[0].left.add(Fp2::ONE),
            3 => query.trace_fri.layers[1].left_proof.siblings[0] = Hash256::hash(b"FRI traza"),
            4 => query.composition_fri.layers[0].left = query.composition_fri.layers[0].left.add(Fp2::ONE),
            _ => query.composition_fri.layers[1].left_proof.siblings[0] = Hash256::hash(b"FRI CP"),
        }
        assert!(verify(statement, &changed).is_err());
    }
}

#[test]
fn rechaza_formas_truncadas_excesivas_y_consultas_reordenadas() {
    let (statement, _, proof) = &honest()[0];
    for kind in 0..9 {
        let mut changed = proof.clone();
        match kind {
            0 => changed.trace_fri.roots.clear(),
            1 => { changed.composition_fri.roots.pop(); },
            2 => { changed.queries.pop(); },
            3 => changed.queries.push(changed.queries[0].clone()),
            4 => { changed.queries[0].trace.pop(); },
            5 => changed.queries[0].trace_fri.layers.clear(),
            6 => { changed.queries[0].composition_fri.layers.pop(); },
            7 => { changed.queries[0].trace[0].proof.siblings.pop(); },
            _ => changed.queries.swap(0, 1),
        }
        assert!(verify(statement, &changed).is_err());
    }
}

#[test]
fn rechaza_elementos_no_canonicos_antes_de_la_aritmetica() {
    let (statement, values, proof) = &honest()[0];
    let bad: Felt = bincode::deserialize(&P.to_le_bytes()).unwrap();
    let mut changed_statement = statement.clone();
    changed_statement.start = bad;
    assert_eq!(verify(&changed_statement, proof), Err(VerifyError::NonCanonical));
    let mut changed_values = values.clone();
    changed_values[0] = bad;
    assert!(matches!(prove_from_evals(statement, &changed_values), Err(VerifyError::NonCanonical)));
    for kind in 0..4 {
        let mut changed = proof.clone();
        match kind {
            0 => changed.queries[0].trace[0].value = bad,
            1 => changed.trace_fri.final_value.c0 = bad,
            2 => changed.queries[0].trace_fri.layers[0].right.c1 = bad,
            _ => changed.queries[0].composition_fri.layers[0].left.c0 = bad,
        }
        assert_eq!(verify(statement, &changed), Err(VerifyError::NonCanonical));
    }
}

#[test]
fn valida_limites_antes_de_multiplicar_o_indexar() {
    let (statement, _, proof) = &honest()[0];
    for t in [0, 4, 8, 17, 8192, usize::MAX] {
        let mut changed = statement.clone();
        changed.steps = t;
        assert_eq!(verify(&changed, proof), Err(VerifyError::Rows));
        assert!(matches!(prove_from_evals(&changed, &[]), Err(VerifyError::Rows)));
    }
    assert!(matches!(prove_from_evals(statement, &[]), Err(VerifyError::Length)));
}

#[test]
fn fri_de_composicion_sigue_exigiendo_las_restricciones() {
    let (mut statement, values) = input(16);
    statement.start = statement.start.add(Felt::ONE);
    let proof = prove_from_evals(&statement, &values).unwrap();
    // La traza es de bajo grado; falla la composición respecto de la frontera anunciada.
    assert_eq!(verify(&statement, &proof), Err(VerifyError::CompositionFri));
}

#[test]
fn transcripcion_independiente_reproduce_indices_y_distingue_fases() {
    let (statement, _, proof) = &honest()[0];
    let t = statement.steps;
    let mut channel = Channel::new(b"NEXUS-TG2-LINKED-FRI-v1");
    let mut profile = 1u16.to_le_bytes().to_vec();
    profile.extend_from_slice(&POW_BITS_RUNTIME.to_le_bytes());
    for value in [8*t, t, 2*t, NUM_QUERIES] { profile.extend_from_slice(&(value as u64).to_le_bytes()); }
    channel.absorb_tagged(16, &profile);
    let mut bytes = statement.start.to_bytes().to_vec();
    bytes.extend_from_slice(&statement.output.to_bytes());
    bytes.extend_from_slice(&(t as u64).to_le_bytes());
    channel.absorb_tagged(TAG_STATEMENT, &bytes);
    channel.absorb_tagged(TAG_TRACE_ROOT, proof.trace_root.as_bytes());
    for _ in 0..3 { let _ = channel.challenge_ext(); }
    let mut another = channel.clone();
    another.absorb_tagged(17, b"composition");
    let mut trace_phase = channel.clone();
    trace_phase.absorb_tagged(17, b"trace");
    assert_ne!(another.challenge_ext(), trace_phase.challenge_ext());
    for (role, commitment) in [
        (b"trace".as_slice(), &proof.trace_fri),
        (b"composition".as_slice(), &proof.composition_fri),
    ] {
        channel.absorb_tagged(17, role);
        for root in &commitment.roots {
            channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes());
            let _ = channel.challenge_ext();
        }
        channel.absorb_tagged(TAG_FINAL, &commitment.final_value.to_bytes());
    }
    assert!(channel.check_grinding(proof.nonce, POW_BITS_RUNTIME));
    let indices = derive_query_indices(&mut channel, 8*t);
    assert_eq!(indices.iter().copied().collect::<std::collections::HashSet<_>>().len(), 40);
    for (query, i) in proof.queries.iter().zip(indices) {
        assert!(nexus_zk::stark::merkle::verify(&proof.trace_root, 8*t, i,
            Fp2::from_base(query.trace[0].value), &query.trace[0].proof));
    }
}
