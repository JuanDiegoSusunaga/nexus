//! Ensayo TG2 de la premisa de proximidad y control exhaustivo de referencia.
//! Conserva el protocolo heredado; el control adicional revela todo el LDE.
#[path = "tg2_air_algebra.rs"]
mod algebra;

use nexus_core::Hash256;
use nexus_zk::stark::{
    air::{AirQuery, StarkProof, TracePoint, TransitionStatement, BLOWUP},
    channel::{Channel, TAG_STATEMENT, TAG_TRACE_ROOT},
    field::{root_of_unity, Felt, Fp2, GENERATOR, P},
    fri,
    merkle::MerkleTree,
    ntt::{coset_ntt, intt, ntt},
    params::POW_BITS_RUNTIME,
    verify_state_transition,
};

pub const MAX_ROWS: usize = 256;

pub struct Experiment {
    pub statement: TransitionStatement,
    pub original_trace: Vec<Felt>,
    pub coefficients: Vec<Felt>,
    pub trace_evals: Vec<Felt>,
    pub cp_evals: Vec<Fp2>,
}

fn valid_rows(rows: usize) -> bool {
    (4..=MAX_ROWS).contains(&rows) && rows.is_power_of_two()
}

fn channel(statement: &TransitionStatement, root: &Hash256) -> Channel {
    let mut bytes = statement.start.to_bytes().to_vec();
    bytes.extend_from_slice(&statement.output.to_bytes());
    bytes.extend_from_slice(&(statement.steps as u64).to_le_bytes());
    let mut channel = Channel::new(b"NEXUS-STARK-v2");
    channel.absorb_tagged(TAG_STATEMENT, &bytes);
    channel.absorb_tagged(TAG_TRACE_ROOT, root.as_bytes());
    channel
}

/// Construye F=f+lambda*(X^T-1), preservando las filas de una ejecución válida.
pub fn prepare(rows: usize, start: Felt, witness: Felt, lambda: Felt) -> Result<Experiment, String> {
    if !valid_rows(rows) || [start, witness, lambda].iter().any(|x| x.value() >= P) {
        return Err("Parámetros fuera del ensayo acotado".into());
    }
    let mut original_trace = vec![start, witness];
    for i in 2..rows {
        original_trace.push(original_trace[i-1].mul(original_trace[i-1])
            .add(original_trace[i-2].mul(original_trace[i-2])));
    }
    let statement = TransitionStatement { start, output: original_trace[rows-1], steps: rows };
    let n = rows*BLOWUP;
    let mut coefficients = intt(&original_trace);
    coefficients.resize(n, Felt::ZERO);
    coefficients[0] = coefficients[0].sub(lambda);
    coefficients[rows] = lambda;
    let trace_evals = coset_ntt(&coefficients, Felt::new(GENERATOR));
    let root = MerkleTree::commit(&trace_evals).root();
    let mut transcript = channel(&statement, &root);
    let alphas = [transcript.challenge_ext(), transcript.challenge_ext(), transcript.challenge_ext()];
    let omega = root_of_unity(n.trailing_zeros());
    let cp_evals = (0..n).map(|j| {
        let x = Felt::new(GENERATOR).mul(omega.pow(j as u64));
        algebra::local_composition(rows, start, statement.output, alphas, x,
            [trace_evals[j], trace_evals[(j+BLOWUP)%n], trace_evals[(j+2*BLOWUP)%n]])
    }).collect::<Result<Vec<_>, _>>()?;
    Ok(Experiment { statement, original_trace, coefficients, trace_evals, cp_evals })
}

/// Completa la transcripción real con el grinding del perfil y aperturas auténticas.
pub fn prove(experiment: &Experiment) -> Result<StarkProof, String> {
    let t = experiment.statement.steps;
    if !valid_rows(t) || experiment.trace_evals.len() != t*BLOWUP
        || experiment.cp_evals.len() != t*BLOWUP {
        return Err("Dimensiones inconsistentes en el ensayo".into());
    }
    let n = t*BLOWUP;
    let tree = MerkleTree::commit(&experiment.trace_evals);
    let root = tree.root();
    let mut transcript = channel(&experiment.statement, &root);
    for _ in 0..3 { let _alpha = transcript.challenge_ext(); }
    let (data, fri_roots, fri_final, _) = fri::commit(
        experiment.cp_evals.clone(), 2*t, Felt::new(GENERATOR), &mut transcript);
    let pow_nonce = transcript.grind(POW_BITS_RUNTIME);
    let indices = fri::derive_query_indices(&mut transcript, n);
    let queries = indices.into_iter().map(|i| {
        let positions = [i, (i+BLOWUP)%n, (i+2*BLOWUP)%n,
            i+n/2, (i+n/2+BLOWUP)%n, (i+n/2+2*BLOWUP)%n];
        AirQuery {
            fri: fri::open(&data, i, n),
            trace: positions.into_iter().map(|j| TracePoint {
                value: experiment.trace_evals[j], proof: tree.open(j),
            }).collect(),
        }
    }).collect();
    Ok(StarkProof { trace_root: root, fri_roots, fri_final, pow_nonce, queries })
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuditError {
    Rows, Length, NonCanonical, Commitment, Degree, Initial, Final, Transition, Stark,
}

/// Control exacto de referencia: reconstruye el LDE comprometido y todas las filas.
/// Costo O(N log N), memoria O(N), comunicación adicional N elementos; no es sucinto.
pub fn audit_full_trace(
    statement: &TransitionStatement, root: &Hash256, values: &[Felt],
) -> Result<Vec<Felt>, AuditError> {
    let t = statement.steps;
    if !valid_rows(t) { return Err(AuditError::Rows); }
    if values.len() != t*BLOWUP { return Err(AuditError::Length); }
    if statement.start.value() >= P || statement.output.value() >= P
        || values.iter().any(|v| v.value() >= P) {
        return Err(AuditError::NonCanonical);
    }
    if MerkleTree::commit(values).root() != *root { return Err(AuditError::Commitment); }
    let mut coefficients = intt(values);
    let inverse_offset = Felt::new(GENERATOR).inv();
    let mut power = Felt::ONE;
    for coefficient in &mut coefficients {
        *coefficient = coefficient.mul(power);
        power = power.mul(inverse_offset);
    }
    if coefficients[t..].iter().any(|&c| c != Felt::ZERO) { return Err(AuditError::Degree); }
    let trace = ntt(&coefficients[..t]);
    if trace[0] != statement.start { return Err(AuditError::Initial); }
    if trace[t-1] != statement.output { return Err(AuditError::Final); }
    for row in trace.windows(3) {
        if row[2] != row[1].mul(row[1]).add(row[0].mul(row[0])) {
            return Err(AuditError::Transition);
        }
    }
    Ok(trace)
}

/// Variante de control para ensayos: apertura completa más verificador heredado.
pub fn verify_with_full_trace(
    statement: &TransitionStatement, proof: &StarkProof, values: &[Felt],
) -> Result<(), AuditError> {
    let _trace = audit_full_trace(statement, &proof.trace_root, values)?;
    if !verify_state_transition(statement, proof) { return Err(AuditError::Stark); }
    Ok(())
}
