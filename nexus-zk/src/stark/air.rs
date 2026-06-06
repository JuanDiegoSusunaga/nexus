//! AIR — *Algebraic Intermediate Representation* de una transición de estado,
//! y su reducción a una afirmación de bajo grado verificable con [`super::fri`].
//!
//! ## Qué demuestra
//! El probador convence al verificador de que conoce una ejecución correcta de
//! un autómata determinista que parte de `start` y, tras `steps-1` pasos,
//! produce `output`. El autómata usado es la recurrencia *Fibonacci-cuadrado*
//! `a_{i+2} = a_{i+1}^2 + a_i^2` (con `a_1` como testigo privado), que hace las
//! veces de **función de transición de estado** de la capa de ejecución (L2):
//! `start ↔ pre-state root`, `output ↔ post-state root`.
//!
//! ## Cómo (STARK)
//! 1. Se interpola la *traza* en un polinomio `f` y se evalúa sobre un *coset*
//!    elevado (LDE), comprometido vía Merkle.
//! 2. Las restricciones (frontera + transición) se combinan, con coeficientes
//!    `α` de Fiat–Shamir, en un **polinomio de composición** `CP` que es de
//!    bajo grado *si y solo si* la ejecución es válida.
//! 3. FRI certifica que `CP` es de bajo grado. En cada consulta, el verificador
//!    reabre la traza y **recomputa `CP`**, atándolo al compromiso FRI: así la
//!    prueba de bajo grado se refiere a *esta* traza, no a un polinomio ajeno.
//!
//! ## Coherencia post-cuántica
//! Todas las primitivas son hash (Merkle/Fiat–Shamir) y aritmética de campo
//! (NTT/FRI). No hay emparejamientos ni curvas elípticas: el algoritmo de Shor
//! no aplica. Es el sustituto post-cuántico del andamiaje Groth16/BN254.
//!
//! ## Alcance del prototipo (honestidad)
//! Es un PoC del *motor criptográfico* y de la reducción restricción→bajo-grado.
//! El AIR es ilustrativo (una recurrencia, no la máquina de estado bancaria
//! completa) y los parámetros de soundness (consultas, *rate*) son de
//! demostración. La aritmetización completa de la L2 es trabajo de ingeniería.

use super::channel::{Channel, TAG_FINAL, TAG_FRI_ROOT, TAG_STATEMENT, TAG_TRACE_ROOT};
use super::field::{root_of_unity, Felt, Fp2, GENERATOR};
use super::fri::{self, QueryProof};
use super::merkle::{self, MerkleProof, MerkleTree};
use super::ntt::{coset_ntt, intt};
use super::params::POW_BITS_RUNTIME;
use nexus_core::Hash256;
use serde::{Deserialize, Serialize};

/// Factor de elevación (LDE): `N = steps · BLOWUP`.
pub const BLOWUP: usize = 8;

/// Enunciado público de la transición de estado.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionStatement {
    /// Valor inicial (codificación del pre-state root).
    pub start: Felt,
    /// Valor final reclamado (codificación del post-state root).
    pub output: Felt,
    /// Número de filas de la traza (potencia de dos, ≥ 4).
    pub steps: usize,
}

/// Apertura de la traza en un punto del LDE.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracePoint {
    pub value: Felt,
    pub proof: MerkleProof,
}

/// Pruebas de una consulta: FRI (sobre `CP`) + aperturas de la traza.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AirQuery {
    pub fri: QueryProof,
    /// 6 aperturas: `f(x), f(gx), f(g²x)` para `x` y para `-x`.
    pub trace: Vec<TracePoint>,
}

/// Prueba STARK de una transición de estado.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof {
    /// Compromiso de Merkle a la traza elevada (LDE).
    pub trace_root: Hash256,
    /// Raíces de las capas FRI.
    pub fri_roots: Vec<Hash256>,
    /// Constante de la última capa FRI (en el campo de extensión).
    pub fri_final: Fp2,
    /// *Nonce* de grinding (proof-of-work de Fiat–Shamir).
    pub pow_nonce: u64,
    /// Una entrada por consulta.
    pub queries: Vec<AirQuery>,
}

/// Parámetros públicos derivados del enunciado (compartidos prover/verifier).
struct Params {
    t: usize,        // filas de la traza
    n: usize,        // tamaño del LDE
    degree_bound: usize,
    offset: Felt,
    omega_n: Felt,   // generador de ⟨ω_N⟩
    g_t1: Felt,      // g^(T-1)
    g_t2: Felt,      // g^(T-2)
}

impl Params {
    fn new(steps: usize) -> Self {
        assert!(steps >= 4 && steps.is_power_of_two(), "steps potencia de dos ≥ 4");
        let t = steps;
        let n = t * BLOWUP;
        let g = root_of_unity(t.trailing_zeros());
        Params {
            t,
            n,
            degree_bound: 2 * t, // deg(CP) ≤ T  ⇒  cota 2T
            offset: Felt::new(GENERATOR),
            omega_n: root_of_unity(n.trailing_zeros()),
            g_t1: g.pow((t - 1) as u64),
            g_t2: g.pow((t - 2) as u64),
        }
    }
}

/// Recurrencia de la composición en un punto `x`, dados `f(x), f(gx), f(g²x)`.
/// Es idéntica en probador y verificador (única fuente de verdad).
#[allow(clippy::too_many_arguments)]
fn compose(
    p: &Params,
    start: Felt,
    output: Felt,
    alphas: &[Fp2; 3],
    x: Felt,
    f0: Felt,
    f1: Felt,
    f2: Felt,
) -> Fp2 {
    // Los cocientes se calculan en el campo BASE y se combinan con α ∈ F_{p^2}.
    // Restricción de transición: a_{i+2} - a_{i+1}^2 - a_i^2.
    let c = f2.sub(f1.mul(f1)).sub(f0.mul(f0));
    // Cociente: divide el vanishing de ⟨g⟩ excepto los dos últimos puntos.
    let vanishing = x.pow(p.t as u64).sub(Felt::ONE); // x^T - 1
    let t_quot = c
        .mul(x.sub(p.g_t2))
        .mul(x.sub(p.g_t1))
        .mul(vanishing.inv());
    // Frontera inicial: (f(x) - start)/(x - 1).
    let b0 = f0.sub(start).mul(x.sub(Felt::ONE).inv());
    // Frontera final: (f(x) - output)/(x - g^(T-1)).
    let bt = f0.sub(output).mul(x.sub(p.g_t1).inv());

    // CP = α0·b0 + α1·bt + α2·t_quot  (α en F_{p^2}, cocientes en F_p promovidos).
    alphas[0]
        .mul_base(b0)
        .add(alphas[1].mul_base(bt))
        .add(alphas[2].mul_base(t_quot))
}

fn absorb_statement(channel: &mut Channel, stmt: &TransitionStatement) {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(&stmt.start.to_bytes());
    buf.extend_from_slice(&stmt.output.to_bytes());
    buf.extend_from_slice(&(stmt.steps as u64).to_le_bytes());
    channel.absorb_tagged(TAG_STATEMENT, &buf);
}

/// Construye la traza Fibonacci-cuadrado de longitud `T`.
fn build_trace(start: Felt, witness: Felt, t: usize) -> Vec<Felt> {
    let mut a = Vec::with_capacity(t);
    a.push(start);
    a.push(witness);
    for i in 2..t {
        a.push(a[i - 1].mul(a[i - 1]).add(a[i - 2].mul(a[i - 2])));
    }
    a
}

/// Genera una prueba STARK de la transición `start --(steps)--> output`,
/// con `witness = a_1`. Devuelve el enunciado (con el `output` calculado) y la prueba.
pub fn prove_state_transition(
    start: Felt,
    witness: Felt,
    steps: usize,
) -> (TransitionStatement, StarkProof) {
    let p = Params::new(steps);
    let trace = build_trace(start, witness, p.t);
    let output = trace[p.t - 1];
    let stmt = TransitionStatement { start, output, steps };

    // Interpolación de la traza y elevación al coset (LDE).
    let mut coeffs = intt(&trace); // grado < T
    coeffs.resize(p.n, Felt::ZERO);
    let trace_lde = coset_ntt(&coeffs, p.offset);
    let trace_tree = MerkleTree::commit(&trace_lde);
    let trace_root = trace_tree.root();

    // Transcripción: enlaza enunciado y compromiso a la traza.
    let mut channel = Channel::new(b"NEXUS-STARK-v2");
    absorb_statement(&mut channel, &stmt);
    channel.absorb_tagged(TAG_TRACE_ROOT, trace_root.as_bytes());
    let alphas = [
        channel.challenge_ext(),
        channel.challenge_ext(),
        channel.challenge_ext(),
    ];

    // Polinomio de composición sobre todo el LDE.
    let b = BLOWUP;
    let cp: Vec<Fp2> = (0..p.n)
        .map(|j| {
            let x = p.offset.mul(p.omega_n.pow(j as u64));
            let f0 = trace_lde[j];
            let f1 = trace_lde[(j + b) % p.n];
            let f2 = trace_lde[(j + 2 * b) % p.n];
            compose(&p, start, output, &alphas, x, f0, f1, f2)
        })
        .collect();

    // FRI sobre CP.
    let (fri_data, fri_roots, fri_final, _betas) =
        fri::commit(cp, p.degree_bound, p.offset, &mut channel);
    // Grinding (proof-of-work) antes de fijar los índices de consulta.
    let pow_nonce = channel.grind(POW_BITS_RUNTIME);
    let indices = fri::derive_query_indices(&mut channel, p.n);

    // Aperturas por consulta: FRI + traza (en x y en -x).
    let half = p.n / 2;
    let queries = indices
        .iter()
        .map(|&idx| {
            let trace_idx = [
                idx,
                (idx + b) % p.n,
                (idx + 2 * b) % p.n,
                (idx + half) % p.n,
                (idx + half + b) % p.n,
                (idx + half + 2 * b) % p.n,
            ];
            let trace = trace_idx
                .iter()
                .map(|&ti| TracePoint {
                    value: trace_lde[ti],
                    proof: trace_tree.open(ti),
                })
                .collect();
            AirQuery {
                fri: fri::open(&fri_data, idx, p.n),
                trace,
            }
        })
        .collect();

    (
        stmt,
        StarkProof {
            trace_root,
            fri_roots,
            fri_final,
            pow_nonce,
            queries,
        },
    )
}

/// Verifica una prueba STARK de transición de estado.
pub fn verify_state_transition(stmt: &TransitionStatement, proof: &StarkProof) -> bool {
    if stmt.steps < 4 || !stmt.steps.is_power_of_two() {
        return false;
    }
    let p = Params::new(stmt.steps);
    let b = BLOWUP;
    let half = p.n / 2;

    // Re-derivación de la transcripción (idéntica al probador).
    let mut channel = Channel::new(b"NEXUS-STARK-v2");
    absorb_statement(&mut channel, stmt);
    channel.absorb_tagged(TAG_TRACE_ROOT, proof.trace_root.as_bytes());
    let alphas = [
        channel.challenge_ext(),
        channel.challenge_ext(),
        channel.challenge_ext(),
    ];

    // Re-derivación de β (orden: por capa, absorber raíz y extraer reto) y final.
    if proof.fri_roots.len() != p.degree_bound.trailing_zeros() as usize {
        return false;
    }
    let mut betas = Vec::with_capacity(proof.fri_roots.len());
    for root in &proof.fri_roots {
        channel.absorb_tagged(TAG_FRI_ROOT, root.as_bytes());
        betas.push(channel.challenge_ext());
    }
    channel.absorb_tagged(TAG_FINAL, &proof.fri_final.to_bytes());
    // Verifica el grinding ANTES de derivar los índices (mismo punto que el probador).
    if !channel.check_grinding(proof.pow_nonce, POW_BITS_RUNTIME) {
        return false;
    }
    let indices = fri::derive_query_indices(&mut channel, p.n);

    if proof.queries.len() != indices.len() {
        return false;
    }

    for (query, &idx) in proof.queries.iter().zip(indices.iter()) {
        if query.trace.len() != 6 {
            return false;
        }
        let trace_idx = [
            idx,
            (idx + b) % p.n,
            (idx + 2 * b) % p.n,
            (idx + half) % p.n,
            (idx + half + b) % p.n,
            (idx + half + 2 * b) % p.n,
        ];
        // (a) aperturas de Merkle de la traza
        for (k, &ti) in trace_idx.iter().enumerate() {
            if !merkle::verify(&proof.trace_root, p.n, ti, query.trace[k].value, &query.trace[k].proof)
            {
                return false;
            }
        }

        // (b) recomputar CP en x y en -x a partir de la traza
        let x = p.offset.mul(p.omega_n.pow(idx as u64));
        let cp_left = compose(
            &p,
            stmt.start,
            stmt.output,
            &alphas,
            x,
            query.trace[0].value,
            query.trace[1].value,
            query.trace[2].value,
        );
        let xp = p.offset.mul(p.omega_n.pow((idx + half) as u64));
        let cp_right = compose(
            &p,
            stmt.start,
            stmt.output,
            &alphas,
            xp,
            query.trace[3].value,
            query.trace[4].value,
            query.trace[5].value,
        );

        // (c) enlace traza ↔ compromiso FRI: la capa 0 de FRI debe ser ese CP
        // Robustez: nunca indexar una capa vacía ante una prueba maliciosa.
        if query.fri.layers.is_empty() {
            return false;
        }
        let layer0 = &query.fri.layers[0];
        if cp_left != layer0.left || cp_right != layer0.right {
            return false;
        }

        // (d) FRI: Merkle + plegado + constante final
        if !fri::verify_query(&query.fri, &proof.fri_roots, &betas, proof.fri_final, idx, p.n, p.offset)
        {
            return false;
        }
    }

    true
}

/// Tamaño serializado de la prueba en bytes (para *benchmarks*).
pub fn proof_size_bytes(proof: &StarkProof) -> usize {
    bincode::serialize(proof).map(|v| v.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transition_accepts() {
        let (stmt, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        assert!(verify_state_transition(&stmt, &proof));
    }

    #[test]
    fn multiple_sizes() {
        for &steps in &[8usize, 16, 32, 64] {
            let (stmt, proof) = prove_state_transition(Felt::new(2), Felt::new(7), steps);
            assert!(verify_state_transition(&stmt, &proof), "steps={}", steps);
        }
    }

    #[test]
    fn tampered_output_rejects() {
        let (mut stmt, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        stmt.output = stmt.output.add(Felt::ONE); // resultado falso
        assert!(!verify_state_transition(&stmt, &proof));
    }

    #[test]
    fn tampered_start_rejects() {
        let (mut stmt, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        stmt.start = stmt.start.add(Felt::ONE);
        assert!(!verify_state_transition(&stmt, &proof));
    }

    #[test]
    fn tampered_trace_value_rejects() {
        let (stmt, mut proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        proof.queries[0].trace[0].value = proof.queries[0].trace[0].value.add(Felt::ONE);
        assert!(!verify_state_transition(&stmt, &proof));
    }

    #[test]
    fn wrong_steps_rejects() {
        let (stmt, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        let bad = TransitionStatement {
            start: stmt.start,
            output: stmt.output,
            steps: 32, // tamaño que no corresponde a la prueba
        };
        assert!(!verify_state_transition(&bad, &proof));
    }

    // ===================== Batería adversarial =====================
    //
    // Construye pruebas con un PROBADOR potencialmente malicioso a partir de una
    // traza y un modo de composición arbitrarios, para atacar el verificador en
    // sus dos defensas: (i) el enlace traza↔CP y (ii) la prueba de bajo grado FRI.

    enum CpMode {
        Honest,
        ForceZero,
    }

    /// Pipeline del probador parametrizado (traza explícita + modo de CP).
    fn prove_pipeline(
        trace: &[Felt],
        output: Felt,
        steps: usize,
        mode: CpMode,
    ) -> (TransitionStatement, StarkProof) {
        let p = Params::new(steps);
        let start = trace[0];
        let stmt = TransitionStatement { start, output, steps };

        let mut coeffs = intt(trace);
        coeffs.resize(p.n, Felt::ZERO);
        let trace_lde = coset_ntt(&coeffs, p.offset);
        let trace_tree = MerkleTree::commit(&trace_lde);
        let trace_root = trace_tree.root();

        let mut channel = Channel::new(b"NEXUS-STARK-v2");
        absorb_statement(&mut channel, &stmt);
        channel.absorb_tagged(TAG_TRACE_ROOT, trace_root.as_bytes());
        let alphas = [
            channel.challenge_ext(),
            channel.challenge_ext(),
            channel.challenge_ext(),
        ];

        let b = BLOWUP;
        let cp: Vec<Fp2> = match mode {
            CpMode::Honest => (0..p.n)
                .map(|j| {
                    let x = p.offset.mul(p.omega_n.pow(j as u64));
                    compose(
                        &p,
                        start,
                        output,
                        &alphas,
                        x,
                        trace_lde[j],
                        trace_lde[(j + b) % p.n],
                        trace_lde[(j + 2 * b) % p.n],
                    )
                })
                .collect(),
            // Malicioso: compromete un CP de grado 0 (constante) desligado de la traza.
            CpMode::ForceZero => vec![Fp2::ZERO; p.n],
        };

        let (fri_data, fri_roots, fri_final, _betas) =
            fri::commit(cp, p.degree_bound, p.offset, &mut channel);
        let pow_nonce = channel.grind(POW_BITS_RUNTIME);
        let indices = fri::derive_query_indices(&mut channel, p.n);

        let half = p.n / 2;
        let queries = indices
            .iter()
            .map(|&idx| {
                let trace_idx = [
                    idx,
                    (idx + b) % p.n,
                    (idx + 2 * b) % p.n,
                    (idx + half) % p.n,
                    (idx + half + b) % p.n,
                    (idx + half + 2 * b) % p.n,
                ];
                let trace = trace_idx
                    .iter()
                    .map(|&ti| TracePoint {
                        value: trace_lde[ti],
                        proof: trace_tree.open(ti),
                    })
                    .collect();
                AirQuery {
                    fri: fri::open(&fri_data, idx, p.n),
                    trace,
                }
            })
            .collect();

        (
            stmt,
            StarkProof {
                trace_root,
                fri_roots,
                fri_final,
                pow_nonce,
                queries,
            },
        )
    }

    #[test]
    fn pipeline_honest_is_faithful() {
        // El pipeline de test (modo honesto) debe producir pruebas válidas,
        // equivalentes a `prove_state_transition`.
        let trace = build_trace(Felt::new(3), Felt::new(5), 16);
        let output = trace[15];
        let (stmt, proof) = prove_pipeline(&trace, output, 16, CpMode::Honest);
        assert!(verify_state_transition(&stmt, &proof));
    }

    #[test]
    fn adversarial_unrelated_low_degree_cp_rejected() {
        // (A) Prover malicioso: compromete un CP de bajo grado (constante 0) pero
        // NO ligado a la traza. FRI lo aceptaría como bajo grado; el verificador
        // lo rechaza en el ENLACE traza↔CP (CP recomputado ≠ capa-0 FRI).
        let trace = build_trace(Felt::new(3), Felt::new(5), 16);
        let output = trace[15];
        let (stmt, forged) = prove_pipeline(&trace, output, 16, CpMode::ForceZero);
        assert!(
            !verify_state_transition(&stmt, &forged),
            "un CP de bajo grado desligado de la traza debe rechazarse"
        );
    }

    #[test]
    fn adversarial_transition_violation_rejected() {
        // (B) Traza que viola la recurrencia en una fila intermedia (boundary
        // intacto): el cociente de transición no es polinómico ⇒ CP de grado alto
        // ⇒ FRI rechaza.
        let mut trace = build_trace(Felt::new(3), Felt::new(5), 16);
        trace[8] = trace[8].add(Felt::ONE); // rompe a_{10} = a_9^2 + a_8^2
        let output = trace[15]; // boundary final consistente
        let (stmt, bad) = prove_pipeline(&trace, output, 16, CpMode::Honest);
        assert!(
            !verify_state_transition(&stmt, &bad),
            "una violación de transición debe producir CP de grado alto y rechazarse"
        );
    }

    #[test]
    fn adversarial_per_element_tamper_rejected() {
        // (D) Manipular CUALQUIER apertura (cada punto de traza, cada capa FRI) de
        // una consulta rompe Merkle o el plegado ⇒ rechazo individual.
        let (stmt, base) = prove_state_transition(Felt::new(3), Felt::new(5), 16);

        for k in 0..6 {
            let mut p = base.clone();
            p.queries[0].trace[k].value = p.queries[0].trace[k].value.add(Felt::ONE);
            assert!(!verify_state_transition(&stmt, &p), "traza[{}] manipulada", k);
        }
        let layers = base.queries[0].fri.layers.len();
        for i in 0..layers {
            let mut p = base.clone();
            p.queries[0].fri.layers[i].left = p.queries[0].fri.layers[i].left.add(Fp2::ONE);
            assert!(!verify_state_transition(&stmt, &p), "capa FRI[{}] manipulada", i);
        }
    }

    #[test]
    fn adversarial_property_valid_accept_flips_reject() {
        // (E) Muchas trazas válidas (semillas distintas) aceptan; un solo cambio
        // en la prueba (constante final FRI) rechaza. PRNG determinista (sin dep).
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Felt::new(s)
        };
        for _ in 0..12 {
            let (start, witness) = (next(), next());
            let (stmt, proof) = prove_state_transition(start, witness, 16);
            assert!(verify_state_transition(&stmt, &proof), "traza válida aceptada");

            let mut flipped = proof.clone();
            flipped.fri_final = flipped.fri_final.add(Fp2::ONE);
            assert!(!verify_state_transition(&stmt, &flipped), "prueba alterada rechazada");
        }
    }

    #[test]
    fn verifier_total_on_empty_queries() {
        // Robustez: una prueba con vectores vacíos no debe paniquear.
        let (stmt, mut proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
        proof.queries.clear();
        assert!(!verify_state_transition(&stmt, &proof));
    }

}
