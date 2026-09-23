//! Contraste del argumento algebraico condicional; no prueba solidez global.
#[path = "../experiments/tg2_air_algebra.rs"]
mod algebra;

use nexus_zk::stark::{
    air::BLOWUP,
    channel::{Channel, TAG_FINAL, TAG_FRI_ROOT, TAG_STATEMENT, TAG_TRACE_ROOT},
    field::{root_of_unity, Felt, Fp2, GENERATOR},
    ntt::{coset_ntt, eval_at},
    fri::derive_query_indices,
    params::POW_BITS_RUNTIME,
    prove_state_transition, verify_state_transition,
};

fn trace(rows: usize, start: u64, witness: u64) -> Vec<Felt> {
    let mut values = vec![Felt::new(start), Felt::new(witness)];
    for i in 2..rows { values.push(values[i-1].mul(values[i-1]).add(values[i-2].mul(values[i-2]))); }
    values
}

fn alphas() -> [Fp2; 3] {
    [Fp2::new(Felt::new(2), Felt::new(3)), Fp2::new(Felt::new(5), Felt::new(7)),
     Fp2::new(Felt::new(11), Felt::new(13))]
}

#[test]
fn oraculo_rechaza_tamanos_y_polos_fuera_del_modelo() {
    for t in [0, 2, 3, 6, 512] {
        assert!(algebra::audit(&vec![Felt::ZERO; t], Felt::ZERO, Felt::ZERO).is_err());
    }
    assert!(algebra::local_composition(16, Felt::ZERO, Felt::ZERO, alphas(), Felt::ONE,
        [Felt::ZERO; 3]).is_err());
}

#[test]
fn trazas_validas_dividen_y_respetan_las_cotas() {
    for t in [4, 8, 16, 32, 64, 128, 256] {
        for (start, witness) in [(0, 0), (3, 5), (7, 11)] {
            let values = trace(t, start, witness);
            let audit = algebra::audit(&values, values[0], values[t-1]).unwrap();
            assert!(algebra::degree(&audit.coefficients).is_none_or(|d| d < t));
            for (i, division) in audit.divisions.iter().enumerate() {
                assert!(division.remainder.is_empty());
                assert!(algebra::degree(&division.quotient).is_none_or(|d| d <= if i == 2 { t } else { t-2 }));
            }
            let combined = algebra::compose(&audit, alphas());
            assert!(algebra::degree_ext(&combined.remainder).is_none());
            assert!(algebra::degree_ext(&combined.quotient).is_none_or(|d| d <= t));
        }
    }
}

#[test]
fn errores_de_frontera_y_transicion_dejan_residuos() {
    let values = trace(16, 3, 5);
    for which in 0..3 {
        let mut changed = values.clone();
        let start = if which == 0 { values[0].add(Felt::ONE) } else { values[0] };
        let output = if which == 1 { values[15].add(Felt::ONE) } else { values[15] };
        if which == 2 { changed[8] = changed[8].add(Felt::ONE); }
        let audit = algebra::audit(&changed, start, output).unwrap();
        assert!(!audit.divisions[which].remainder.is_empty());
        let combined = algebra::compose(&audit, alphas());
        assert!(algebra::degree_ext(&combined.remainder).is_some());
    }
}

#[test]
fn errores_pueden_cancelarse_con_tres_coeficientes_no_nulos() {
    let mut values = trace(16, 3, 5);
    values[0] = Felt::new(4);
    let audit = algebra::audit(&values, Felt::new(3), values[15]).unwrap();
    assert!(!audit.divisions[0].remainder.is_empty());
    assert!(!audit.divisions[2].remainder.is_empty());
    let r0 = eval_at(&audit.numerators[0], Felt::ONE);
    let r2 = eval_at(&audit.numerators[2], Felt::ONE);
    let alpha0 = r2.neg().mul(r0.inv());
    assert_ne!(alpha0, Felt::ZERO);
    let combined = algebra::compose(&audit, [Fp2::from_base(alpha0), Fp2::ONE, Fp2::ONE]);
    assert!(algebra::degree_ext(&combined.remainder).is_none());
    assert!(algebra::degree_ext(&combined.quotient).is_none_or(|d| d <= 16));
    eprintln!("TG2_CANCELACION T=16 alpha0={} grado_cp={}", alpha0.value(),
        algebra::degree_ext(&combined.quotient).unwrap());
    // Los coeficientes se eligieron algebraicamente: no son retos forzados a SHA3.
}

#[test]
fn oraculo_coincide_con_las_aperturas_del_probador_heredado() {
    let (statement, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
    assert!(verify_state_transition(&statement, &proof));
    let mut channel = Channel::new(b"NEXUS-STARK-v2");
    let mut bytes = statement.start.to_bytes().to_vec();
    bytes.extend_from_slice(&statement.output.to_bytes());
    bytes.extend_from_slice(&(statement.steps as u64).to_le_bytes());
    channel.absorb_tagged(TAG_STATEMENT, &bytes);
    channel.absorb_tagged(TAG_TRACE_ROOT, proof.trace_root.as_bytes());
    let coefficients = [channel.challenge_ext(), channel.challenge_ext(), channel.challenge_ext()];
    let values = trace(16, 3, 5);
    let audit = algebra::audit(&values, statement.start, statement.output).unwrap();
    let combined = algebra::compose(&audit, coefficients);
    let mut f = audit.coefficients.clone();
    f.resize(128, Felt::ZERO);
    let lde = coset_ntt(&f, Felt::new(GENERATOR));
    let omega = root_of_unity(7);
    for j in 0..128 {
        let x = Felt::new(GENERATOR).mul(omega.pow(j as u64));
        let local = algebra::local_composition(16, statement.start, statement.output, coefficients,
            x, [lde[j], lde[(j+BLOWUP)%128], lde[(j+2*BLOWUP)%128]]).unwrap();
        assert_eq!(local, algebra::eval_ext(&combined.quotient, x));
    }
    // Se reconstruyen las consultas para cotejar cada apertura en su índice real.
    for root in &proof.fri_roots {
        channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes());
        let _beta = channel.challenge_ext();
    }
    channel.absorb_tagged(TAG_FINAL, &proof.fri_final.to_bytes());
    assert!(channel.check_grinding(proof.pow_nonce, POW_BITS_RUNTIME));
    let indices = derive_query_indices(&mut channel, 128);
    for (query, j) in proof.queries.iter().zip(indices) {
        let x = Felt::new(GENERATOR).mul(omega.pow(j as u64));
        assert_eq!(query.trace[0].value, lde[j]);
        assert_eq!(query.trace[3].value, lde[j+64]);
        assert_eq!(query.fri.layers[0].left, algebra::eval_ext(&combined.quotient, x));
        assert_eq!(query.fri.layers[0].right, algebra::eval_ext(&combined.quotient, x.neg()));
    }
}

#[test]
fn identidad_residual_y_cota_de_raices_en_caso_invalido() {
    let values = trace(16, 3, 5);
    let audit = algebra::audit(&values, Felt::new(4), values[15]).unwrap();
    let combined = algebra::compose(&audit, alphas());
    let mut q = vec![Fp2::ZERO; 32];
    q[31] = Fp2::ONE;
    let mut residual = combined.numerator.clone();
    residual.resize(48, Fp2::ZERO);
    for (i, coefficient) in q.iter().enumerate() {
        residual[i+16] = residual[i+16].sub(*coefficient);
        residual[i] = residual[i].add(*coefficient);
    }
    assert_eq!(algebra::degree_ext(&residual), Some(47));
    let omega = root_of_unity(7);
    let mut agreements = 0;
    for j in 0..128 {
        let x = Felt::new(GENERATOR).mul(omega.pow(j));
        let d = x.pow(16).sub(Felt::ONE);
        assert_ne!(d, Felt::ZERO);
        let rational = algebra::eval_ext(&combined.numerator, x).mul_base(d.inv());
        assert_eq!(rational.sub(algebra::eval_ext(&q, x)).mul_base(d),
            algebra::eval_ext(&residual, x));
        if rational == algebra::eval_ext(&q, x) { agreements += 1; }
    }
    assert!(agreements <= 47);
}

#[test]
fn dos_errores_de_oraculo_afectan_como_maximo_seis_composiciones() {
    let values = trace(16, 3, 5);
    let audit = algebra::audit(&values, values[0], values[15]).unwrap();
    let mut f = audit.coefficients.clone();
    f.resize(128, Felt::ZERO);
    let lde = coset_ntt(&f, Felt::new(GENERATOR));
    let mut changed = lde.clone();
    for i in [3, 70] { changed[i] = changed[i].add(Felt::ONE); }
    let omega = root_of_unity(7);
    let mut differences = 0;
    for j in 0..128 {
        let x = Felt::new(GENERATOR).mul(omega.pow(j as u64));
        let evaluate = |v: &[Felt]| algebra::local_composition(16, values[0], values[15], alphas(),
            x, [v[j], v[(j+8)%128], v[(j+16)%128]]).unwrap();
        if evaluate(&lde) != evaluate(&changed) { differences += 1; }
    }
    assert!(differences > 0 && differences <= 6);
    eprintln!("TG2_TRANSFERENCIA errores_traza=2 diferencias_cp={differences} dominio=128");
}
