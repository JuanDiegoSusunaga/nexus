//! Verificador de la recurrencia con el contrato de bytes de Lean.
//!
//! FRI de traza y composición comparten el compromiso AIR. Se conservan el
//! dominio y el formato de los certificados de investigación. El selector
//! rechaza al agotar 512 extracciones, igual que `Verificador.Completo`.
//! No demuestra equivalencia universal con Lean, ZK ni validez de una L2.

use super::{
    air::{TracePoint, TransitionStatement, BLOWUP},
    channel::{Channel, TAG_FINAL, TAG_FRI_ROOT, TAG_STATEMENT, TAG_TRACE_ROOT},
    field::{root_of_unity, Felt, Fp2, GENERATOR, P},
    fri::{self, QueryProof, NUM_QUERIES},
    merkle::{self, MerkleTree},
    ntt::{coset_ntt, intt},
    params::POW_BITS_RUNTIME,
};
use nexus_core::Hash256;
use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const MIN_ROWS: usize = 16;
pub const MAX_ROWS: usize = 4096;
pub const INDEX_DRAWS: usize = 512;
pub const MAX_CERTIFICATE_BYTES: usize = 2 * 1024 * 1024;
const DOMAIN: &[u8] = b"NEXUS-TG2-LINKED-FRI-v1";
const TAG_PROFILE: u8 = 16;
const TAG_STAGE: u8 = 17;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriCommitment {
    pub roots: Vec<Hash256>,
    pub final_value: Fp2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkedQuery {
    pub trace: Vec<TracePoint>,
    pub trace_fri: QueryProof,
    pub composition_fri: QueryProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkedProof {
    pub version: u16,
    pub pow_bits: u32,
    pub trace_root: Hash256,
    pub trace_fri: FriCommitment,
    pub composition_fri: FriCommitment,
    pub nonce: u64,
    pub queries: Vec<LinkedQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Rows, Profile, Length, NonCanonical, Shape, TraceRoot, Grinding,
    TraceOpening, TraceLink, TraceFri, CompositionLink, CompositionFri,
    Selector, Decode, TrailingBytes,
}

fn canonical(x: Felt) -> bool { x.value() < P }
fn canonical_ext(x: Fp2) -> bool { canonical(x.c0) && canonical(x.c1) }

fn dimensions(statement: &TransitionStatement) -> Result<(usize, usize), VerifyError> {
    let t = statement.steps;
    if !(MIN_ROWS..=MAX_ROWS).contains(&t) || !t.is_power_of_two() {
        return Err(VerifyError::Rows);
    }
    if !canonical(statement.start) || !canonical(statement.output) {
        return Err(VerifyError::NonCanonical);
    }
    Ok((t, t * BLOWUP))
}

fn profile(bits: u32) -> Result<(), VerifyError> {
    if bits == 12 || bits == 20 { Ok(()) } else { Err(VerifyError::Profile) }
}

fn begin(statement: &TransitionStatement, root: &Hash256, bits: u32) -> (Channel, [Fp2; 3]) {
    let t = statement.steps;
    let mut channel = Channel::new(DOMAIN);
    let mut data = VERSION.to_le_bytes().to_vec();
    data.extend_from_slice(&bits.to_le_bytes());
    for value in [t * BLOWUP, t, 2 * t, NUM_QUERIES] {
        data.extend_from_slice(&(value as u64).to_le_bytes());
    }
    channel.absorb_tagged(TAG_PROFILE, &data);
    let mut data = statement.start.to_bytes().to_vec();
    data.extend_from_slice(&statement.output.to_bytes());
    data.extend_from_slice(&(t as u64).to_le_bytes());
    channel.absorb_tagged(TAG_STATEMENT, &data);
    channel.absorb_tagged(TAG_TRACE_ROOT, root.as_bytes());
    let alphas = [channel.challenge_ext(), channel.challenge_ext(), channel.challenge_ext()];
    (channel, alphas)
}

fn positions(i: usize, n: usize) -> [usize; 6] {
    [i, (i + BLOWUP) % n, (i + 2 * BLOWUP) % n,
     i + n / 2, (i + n / 2 + BLOWUP) % n, (i + n / 2 + 2 * BLOWUP) % n]
}

fn compose(statement: &TransitionStatement, alphas: [Fp2; 3], x: Felt, f: [Felt; 3]) -> Fp2 {
    let t = statement.steps;
    let g = root_of_unity(t.trailing_zeros());
    let h1 = g.pow((t - 1) as u64);
    let h2 = g.pow((t - 2) as u64);
    let c = f[2].sub(f[1].mul(f[1])).sub(f[0].mul(f[0]));
    let parts = [
        f[0].sub(statement.start).mul(x.sub(Felt::ONE).inv()),
        f[0].sub(statement.output).mul(x.sub(h1).inv()),
        c.mul(x.sub(h1)).mul(x.sub(h2)).mul(x.pow(t as u64).sub(Felt::ONE).inv()),
    ];
    alphas.into_iter().zip(parts).fold(Fp2::ZERO, |sum, (a, v)| sum.add(a.mul_base(v)))
}

/// Cuenta todas las extracciones, incluidos duplicados, y conserva su orden.
fn select_with(domain: usize, mut next: impl FnMut() -> usize) -> Result<Vec<usize>, VerifyError> {
    if !domain.is_power_of_two() || domain < NUM_QUERIES { return Err(VerifyError::Rows); }
    let mut indices = Vec::with_capacity(NUM_QUERIES);
    for _ in 0..INDEX_DRAWS {
        let index = next();
        if index >= domain { return Err(VerifyError::Shape); }
        if !indices.contains(&index) { indices.push(index); }
        if indices.len() == NUM_QUERIES { return Ok(indices); }
    }
    Err(VerifyError::Selector)
}

fn indices(channel: &mut Channel, n: usize) -> Result<Vec<usize>, VerifyError> {
    select_with(n / 2, || channel.challenge_index(n / 2))
}

/// Generación limitada a la recurrencia ilustrativa, no a transacciones ML-DSA.
pub fn prove_transition(start: Felt, witness: Felt, rows: usize)
    -> Result<(TransitionStatement, LinkedProof), VerifyError> {
    let mut statement = TransitionStatement { start, output: Felt::ZERO, steps: rows };
    dimensions(&statement)?;
    if !canonical(witness) { return Err(VerifyError::NonCanonical); }
    let mut trace = vec![start, witness];
    for i in 2..rows { trace.push(trace[i - 1].mul(trace[i - 1]).add(trace[i - 2].mul(trace[i - 2]))); }
    statement.output = trace[rows - 1];
    let mut coefficients = intt(&trace);
    coefficients.resize(rows * BLOWUP, Felt::ZERO);
    let values = coset_ntt(&coefficients, Felt::new(GENERATOR));
    let proof = prove_from_evals(&statement, &values)?;
    Ok((statement, proof))
}

pub fn prove_from_evals(statement: &TransitionStatement, values: &[Felt]) -> Result<LinkedProof, VerifyError> {
    let (t, n) = dimensions(statement)?;
    if values.len() != n { return Err(VerifyError::Length); }
    if values.iter().any(|&v| !canonical(v)) { return Err(VerifyError::NonCanonical); }
    let lifted: Vec<_> = values.iter().copied().map(Fp2::from_base).collect();
    let tree = MerkleTree::commit(&lifted);
    let trace_root = tree.root();
    let (mut channel, alphas) = begin(statement, &trace_root, POW_BITS_RUNTIME);
    let omega = root_of_unity(n.trailing_zeros());
    let offset = Felt::new(GENERATOR);
    let cp: Vec<_> = (0..n).map(|j| compose(statement, alphas, offset.mul(omega.pow(j as u64)),
        [values[j], values[(j + BLOWUP) % n], values[(j + 2 * BLOWUP) % n]])).collect();
    channel.absorb_tagged(TAG_STAGE, b"trace");
    let (trace_data, trace_roots, trace_final, _) = fri::commit(lifted, t, offset, &mut channel);
    channel.absorb_tagged(TAG_STAGE, b"composition");
    let (cp_data, cp_roots, cp_final, _) = fri::commit(cp, 2 * t, offset, &mut channel);
    let nonce = channel.grind(POW_BITS_RUNTIME);
    let queries = indices(&mut channel, n)?.into_iter().map(|i| LinkedQuery {
        trace: positions(i, n).into_iter().map(|j| TracePoint { value: values[j], proof: tree.open(j) }).collect(),
        trace_fri: fri::open(&trace_data, i, n), composition_fri: fri::open(&cp_data, i, n),
    }).collect();
    Ok(LinkedProof { version: VERSION, pow_bits: POW_BITS_RUNTIME, trace_root,
        trace_fri: FriCommitment { roots: trace_roots, final_value: trace_final },
        composition_fri: FriCommitment { roots: cp_roots, final_value: cp_final }, nonce, queries })
}

fn validate_query_shape(query: &QueryProof, layers: usize, n: usize) -> Result<(), VerifyError> {
    if query.layers.len() != layers { return Err(VerifyError::Shape); }
    for (i, opening) in query.layers.iter().enumerate() {
        let depth = (n >> i).trailing_zeros() as usize;
        if opening.left_proof.siblings.len() != depth || opening.right_proof.siblings.len() != depth {
            return Err(VerifyError::Shape);
        }
        if !canonical_ext(opening.left) || !canonical_ext(opening.right) { return Err(VerifyError::NonCanonical); }
    }
    Ok(())
}

fn read_commitment(channel: &mut Channel, role: &[u8], commitment: &FriCommitment) -> Vec<Fp2> {
    channel.absorb_tagged(TAG_STAGE, role);
    let betas = commitment.roots.iter().map(|root| {
        channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes()); channel.challenge_ext()
    }).collect();
    channel.absorb_tagged(TAG_FINAL, &commitment.final_value.to_bytes());
    betas
}

/// El perfil esperado proviene del llamante, no del certificado recibido.
pub fn verify_with_profile(statement: &TransitionStatement, proof: &LinkedProof, bits: u32) -> Result<(), VerifyError> {
    let (t, n) = dimensions(statement)?;
    profile(bits)?;
    if proof.version != VERSION || proof.pow_bits != bits { return Err(VerifyError::Profile); }
    let trace_layers = t.trailing_zeros() as usize;
    let cp_layers = trace_layers + 1;
    if proof.trace_fri.roots.len() != trace_layers || proof.composition_fri.roots.len() != cp_layers
        || proof.queries.len() != NUM_QUERIES { return Err(VerifyError::Shape); }
    if proof.trace_fri.roots[0] != proof.trace_root { return Err(VerifyError::TraceRoot); }
    if !canonical_ext(proof.trace_fri.final_value) || !canonical_ext(proof.composition_fri.final_value) {
        return Err(VerifyError::NonCanonical);
    }
    for query in &proof.queries {
        if query.trace.len() != 6 { return Err(VerifyError::Shape); }
        for point in &query.trace {
            if point.proof.siblings.len() != n.trailing_zeros() as usize { return Err(VerifyError::Shape); }
            if !canonical(point.value) { return Err(VerifyError::NonCanonical); }
        }
        validate_query_shape(&query.trace_fri, trace_layers, n)?;
        validate_query_shape(&query.composition_fri, cp_layers, n)?;
    }
    let (mut channel, alphas) = begin(statement, &proof.trace_root, bits);
    let trace_betas = read_commitment(&mut channel, b"trace", &proof.trace_fri);
    let cp_betas = read_commitment(&mut channel, b"composition", &proof.composition_fri);
    if !channel.check_grinding(proof.nonce, bits) { return Err(VerifyError::Grinding); }
    let selected = indices(&mut channel, n)?;
    let offset = Felt::new(GENERATOR);
    let omega = root_of_unity(n.trailing_zeros());
    for (query, i) in proof.queries.iter().zip(selected) {
        for (point, j) in query.trace.iter().zip(positions(i, n)) {
            if !merkle::verify(&proof.trace_root, n, j, Fp2::from_base(point.value), &point.proof) {
                return Err(VerifyError::TraceOpening);
            }
        }
        let first = &query.trace_fri.layers[0];
        if first.left != Fp2::from_base(query.trace[0].value) || first.right != Fp2::from_base(query.trace[3].value) {
            return Err(VerifyError::TraceLink);
        }
        if !fri::verify_query(&query.trace_fri, &proof.trace_fri.roots, &trace_betas,
            proof.trace_fri.final_value, i, n, offset) { return Err(VerifyError::TraceFri); }
        let x = offset.mul(omega.pow(i as u64));
        let left = compose(statement, alphas, x, [query.trace[0].value, query.trace[1].value, query.trace[2].value]);
        let right = compose(statement, alphas, x.neg(), [query.trace[3].value, query.trace[4].value, query.trace[5].value]);
        let first = &query.composition_fri.layers[0];
        if first.left != left || first.right != right { return Err(VerifyError::CompositionLink); }
        if !fri::verify_query(&query.composition_fri, &proof.composition_fri.roots, &cp_betas,
            proof.composition_fri.final_value, i, n, offset) { return Err(VerifyError::CompositionFri); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_respeta_limite_512_y_orden() {
        let mut draws = 0;
        let result = select_with(64, || { draws += 1; if draws <= 473 { 0 } else { draws - 473 } });
        assert_eq!(result, Ok((0..40).collect()));
        assert_eq!(draws, 512);
        draws = 0;
        let result = select_with(64, || { draws += 1; if draws <= 474 { 0 } else { draws - 474 } });
        assert_eq!(result, Err(VerifyError::Selector));
        assert_eq!(draws, 512);
    }

    #[test]
    fn selector_cuenta_duplicados_y_rechaza_dominios_invalidos() {
        let mut draws = 0;
        assert_eq!(select_with(64, || { draws += 1; 0 }), Err(VerifyError::Selector));
        assert_eq!(draws, 512);
        assert_eq!(select_with(32, || 0), Err(VerifyError::Rows));
        assert_eq!(select_with(63, || 0), Err(VerifyError::Rows));
        assert_eq!(select_with(64, || 64), Err(VerifyError::Shape));
    }
}
