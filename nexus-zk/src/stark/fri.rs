//! FRI — *Fast Reed–Solomon Interactive Oracle Proof of Proximity*.
//!
//! Prueba sucinta de que un vector de evaluaciones, comprometido vía Merkle,
//! corresponde a un polinomio de **grado acotado**. Es el núcleo de soundness
//! de un STARK: la satisfacción de las restricciones se reduce a una afirmación
//! de bajo grado (módulo [`super::air`]), y FRI la certifica usando **solo**
//! hashes y aritmética de campo.
//!
//! **Codeword en el campo de extensión.** El polinomio de composición vive en
//! `F_{p^2}` (porque los coeficientes de combinación `α` son de extensión), de
//! modo que las capas FRI son `Fp2`-valuadas y los coeficientes de plegado `β`
//! también son de extensión. El **dominio** (puntos `x`, raíces de la unidad,
//! offset del coset) permanece en el campo base `F_p`. Esto eleva el término de
//! soundness del plegado a `~deg/2^128`.
//!
//! Esquema (Fiat–Shamir, no interactivo): el probador compromete capas
//! sucesivas obtenidas por *plegado* `f → f_par + β·f_impar` sobre el dominio
//! elevado al cuadrado; el verificador re-deriva los `β` y los índices de
//! consulta de la transcripción, y comprueba (i) las aperturas de Merkle,
//! (ii) la coherencia del plegado entre capas y (iii) que la última capa es
//! la constante anunciada.

use super::channel::{Channel, TAG_FINAL, TAG_FRI_ROOT};
use super::field::{root_of_unity, Felt, Fp2};
use super::merkle::{self, MerkleProof, MerkleTree};
use nexus_core::Hash256;
use serde::{Deserialize, Serialize};

/// Número de consultas (parámetro de soundness; ver `super::params`).
///
/// A *rate* `ρ = 1/4`, cada consulta aporta `log2(1/ρ) = 2` bits bajo la
/// conjetura de *proximity gaps* (Ben-Sasson et al.); 40 consultas + grinding
/// completan el objetivo de soundness del protocolo (véase `params.rs`).
pub const NUM_QUERIES: usize = 40;

/// Apertura de una capa para una consulta: el par `(f(x), f(-x))` con caminos.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerOpening {
    pub left: Fp2,
    pub right: Fp2,
    pub left_proof: MerkleProof,
    pub right_proof: MerkleProof,
}

/// Aperturas de todas las capas para una consulta.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryProof {
    pub layers: Vec<LayerOpening>,
}

/// Prueba FRI completa.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProof {
    /// Raíces de Merkle de las capas plegadas `0..num_layers`.
    pub layer_roots: Vec<Hash256>,
    /// Valor constante de la última capa.
    pub final_value: Fp2,
    /// Una prueba por consulta.
    pub queries: Vec<QueryProof>,
}

/// Estado del probador FRI tras la fase de compromiso (capas + árboles).
pub struct FriProverData {
    pub layer_evals: Vec<Vec<Fp2>>,
    pub layer_trees: Vec<MerkleTree>,
}

/// Plegado de un par `(left, right) = (f(x), f(-x))` con `x` en el campo base y
/// coeficiente `beta` en el campo de extensión.
#[inline]
fn fold(left: Fp2, right: Fp2, x: Felt, inv2: Felt, beta: Fp2) -> Fp2 {
    let even = left.add(right).mul_base(inv2);
    let odd = left.sub(right).mul_base(inv2).mul_base(x.inv());
    even.add(beta.mul(odd))
}

/// Fase de compromiso: construye y compromete las capas plegadas, absorbiendo
/// cada raíz y extrayendo el `β ∈ F_{p^2}` correspondiente, y finalmente absorbe
/// la constante de la última capa. Devuelve los datos del probador, las raíces,
/// el valor final y los `β`.
pub fn commit(
    evals: Vec<Fp2>,
    degree_bound: usize,
    offset: Felt,
    channel: &mut Channel,
) -> (FriProverData, Vec<Hash256>, Fp2, Vec<Fp2>) {
    let n = evals.len();
    assert!(n.is_power_of_two() && degree_bound.is_power_of_two());
    assert!(degree_bound < n, "degree_bound debe ser < N (rate > 1)");
    let num_layers = degree_bound.trailing_zeros() as usize;
    let inv2 = Felt::new(2).inv();

    let mut layer_evals = Vec::with_capacity(num_layers);
    let mut layer_trees = Vec::with_capacity(num_layers);
    let mut layer_roots = Vec::with_capacity(num_layers);
    let mut betas = Vec::with_capacity(num_layers);

    let mut cur = evals;
    let mut cur_offset = offset;
    let mut cur_omega = root_of_unity(n.trailing_zeros());

    for _ in 0..num_layers {
        let tree = MerkleTree::commit(&cur);
        let root = tree.root();
        channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes());
        let beta = channel.challenge_ext();

        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        for a in 0..half {
            let x = cur_offset.mul(cur_omega.pow(a as u64));
            next.push(fold(cur[a], cur[a + half], x, inv2, beta));
        }

        layer_roots.push(root);
        betas.push(beta);
        layer_evals.push(cur);
        layer_trees.push(tree);

        cur = next;
        cur_offset = cur_offset.mul(cur_offset);
        cur_omega = cur_omega.mul(cur_omega);
    }

    let final_value = cur[0];
    channel.absorb_tagged(TAG_FINAL, &final_value.to_bytes());

    (
        FriProverData {
            layer_evals,
            layer_trees,
        },
        layer_roots,
        final_value,
        betas,
    )
}

/// Aperturas FRI para una consulta cuyo índice de capa 0 es `pos0 ∈ [0, n/2)`.
pub fn open(data: &FriProverData, pos0: usize, n: usize) -> QueryProof {
    let num_layers = data.layer_evals.len();
    let mut pos = pos0;
    let mut cur_n = n;
    let mut openings = Vec::with_capacity(num_layers);
    for i in 0..num_layers {
        let half = cur_n / 2;
        let a = pos % half;
        let ev = &data.layer_evals[i];
        let tr = &data.layer_trees[i];
        openings.push(LayerOpening {
            left: ev[a],
            right: ev[a + half],
            left_proof: tr.open(a),
            right_proof: tr.open(a + half),
        });
        pos = a;
        cur_n = half;
    }
    QueryProof { layers: openings }
}

/// Verifica las aperturas FRI de una sola consulta (Merkle + plegado + final).
pub fn verify_query(
    query: &QueryProof,
    layer_roots: &[Hash256],
    betas: &[Fp2],
    final_value: Fp2,
    pos0: usize,
    n: usize,
    offset: Felt,
) -> bool {
    let num_layers = layer_roots.len();
    if query.layers.len() != num_layers || betas.len() != num_layers {
        return false;
    }
    let inv2 = Felt::new(2).inv();
    let mut pos = pos0;
    let mut cur_n = n;
    let mut cur_offset = offset;
    let mut cur_omega = root_of_unity(n.trailing_zeros());
    let mut carried: Option<Fp2> = None;

    for i in 0..num_layers {
        let half = cur_n / 2;
        let a = pos % half;
        let op = &query.layers[i];

        if !merkle::verify(&layer_roots[i], cur_n, a, op.left, &op.left_proof) {
            return false;
        }
        if !merkle::verify(&layer_roots[i], cur_n, a + half, op.right, &op.right_proof) {
            return false;
        }
        if let Some(c) = carried {
            let val_at_pos = if pos < half { op.left } else { op.right };
            if val_at_pos != c {
                return false;
            }
        }

        let x = cur_offset.mul(cur_omega.pow(a as u64));
        carried = Some(fold(op.left, op.right, x, inv2, betas[i]));

        pos = a;
        cur_n = half;
        cur_offset = cur_offset.mul(cur_offset);
        cur_omega = cur_omega.mul(cur_omega);
    }

    carried == Some(final_value)
}

/// Deriva los índices de consulta de la transcripción, **sin reemplazo**.
///
/// Muestrear con reemplazo desperdiciaría soundness: una consulta repetida no
/// aporta información nueva. Se rechazan los duplicados de forma determinista
/// (idéntica en probador y verificador) hasta reunir `min(NUM_QUERIES, n/2)`
/// índices distintos. Para `n/2 ≥ NUM_QUERIES` —i.e. `T ≥ 16` con *blowup* 8—
/// se obtienen las `NUM_QUERIES` consultas distintas que el presupuesto supone.
pub fn derive_query_indices(channel: &mut Channel, n: usize) -> Vec<usize> {
    let domain = n / 2;
    let target = NUM_QUERIES.min(domain);
    let mut indices = Vec::with_capacity(target);
    while indices.len() < target {
        let idx = channel.challenge_index(domain);
        if !indices.contains(&idx) {
            indices.push(idx);
        }
    }
    indices
}

/// Prueba FRI completa (conveniencia: compromiso + consultas).
pub fn prove(
    evals: Vec<Fp2>,
    degree_bound: usize,
    offset: Felt,
    channel: &mut Channel,
) -> FriProof {
    let n = evals.len();
    let (data, layer_roots, final_value, _betas) = commit(evals, degree_bound, offset, channel);
    let indices = derive_query_indices(channel, n);
    let queries = indices.iter().map(|&idx| open(&data, idx, n)).collect();
    FriProof {
        layer_roots,
        final_value,
        queries,
    }
}

/// Verifica una prueba FRI completa. `n` es el tamaño del dominio de la capa 0.
pub fn verify(
    proof: &FriProof,
    degree_bound: usize,
    n: usize,
    offset: Felt,
    channel: &mut Channel,
) -> bool {
    let num_layers = degree_bound.trailing_zeros() as usize;
    if proof.layer_roots.len() != num_layers {
        return false;
    }
    let mut betas = Vec::with_capacity(num_layers);
    for root in &proof.layer_roots {
        channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes());
        betas.push(channel.challenge_ext());
    }
    channel.absorb_tagged(TAG_FINAL, &proof.final_value.to_bytes());
    let indices = derive_query_indices(channel, n);

    if proof.queries.len() != indices.len() {
        return false;
    }
    for (query, &idx) in proof.queries.iter().zip(indices.iter()) {
        if !verify_query(query, &proof.layer_roots, &betas, proof.final_value, idx, n, offset) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field::GENERATOR;
    use super::super::ntt::coset_ntt;

    fn coset_offset() -> Felt {
        Felt::new(GENERATOR)
    }

    /// Evaluaciones de un polinomio de grado `< deg` sobre el coset, en `F_{p^2}`
    /// (inmersión del campo base: un polinomio de bajo grado sigue siéndolo).
    fn low_degree_evals(deg: usize, n: usize, seed: u64) -> Vec<Fp2> {
        let mut coeffs = vec![Felt::ZERO; n];
        let mut s = seed;
        for c in coeffs.iter_mut().take(deg) {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = Felt::new(s);
        }
        coset_ntt(&coeffs, coset_offset())
            .into_iter()
            .map(Fp2::from_base)
            .collect()
    }

    #[test]
    fn accepts_low_degree() {
        let n = 256;
        let d = 64;
        let evals = low_degree_evals(d, n, 42);
        let mut ch = Channel::new(b"fri-test");
        let proof = prove(evals, d, coset_offset(), &mut ch);

        let mut vch = Channel::new(b"fri-test");
        assert!(verify(&proof, d, n, coset_offset(), &mut vch));
    }

    #[test]
    fn rejects_high_degree() {
        let n = 256;
        let d = 64;
        let evals = low_degree_evals(n, n, 7); // grado casi máximo
        let mut ch = Channel::new(b"fri-test");
        let proof = prove(evals, d, coset_offset(), &mut ch);

        let mut vch = Channel::new(b"fri-test");
        assert!(!verify(&proof, d, n, coset_offset(), &mut vch));
    }

    #[test]
    fn rejects_tampered_opening() {
        let n = 128;
        let d = 32;
        let evals = low_degree_evals(d, n, 99);
        let mut ch = Channel::new(b"fri-test");
        let mut proof = prove(evals, d, coset_offset(), &mut ch);

        proof.queries[0].layers[0].left = proof.queries[0].layers[0].left.add(Fp2::ONE);

        let mut vch = Channel::new(b"fri-test");
        assert!(!verify(&proof, d, n, coset_offset(), &mut vch));
    }

    #[test]
    fn query_indices_distinct_without_replacement() {
        // Para n/2 = 128 ≥ NUM_QUERIES, deben salir NUM_QUERIES índices DISTINTOS.
        let mut ch = Channel::new(b"q");
        let idx = derive_query_indices(&mut ch, 256);
        assert_eq!(idx.len(), NUM_QUERIES);
        let set: std::collections::HashSet<usize> = idx.iter().copied().collect();
        assert_eq!(set.len(), idx.len(), "sin reemplazo ⇒ todos distintos");
    }

    #[test]
    fn rejects_wrong_final_value() {
        let n = 128;
        let d = 32;
        let evals = low_degree_evals(d, n, 5);
        let mut ch = Channel::new(b"fri-test");
        let mut proof = prove(evals, d, coset_offset(), &mut ch);
        proof.final_value = proof.final_value.add(Fp2::ONE);

        let mut vch = Channel::new(b"fri-test");
        assert!(!verify(&proof, d, n, coset_offset(), &mut vch));
    }
}
