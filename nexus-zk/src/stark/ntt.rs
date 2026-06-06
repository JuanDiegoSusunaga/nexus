//! Transformada Numérica Teórica (NTT) radix-2 sobre Goldilocks.
//!
//! Es el motor de la codificación Reed–Solomon que sustenta FRI:
//! interpola/evalúa polinomios sobre subgrupos multiplicativos `⟨ω⟩` de orden
//! `2^k` en `O(n log n)`. Toda la maquinaria es aritmética de campo + hashes
//! (vía Merkle/Fiat-Shamir, en otros módulos): **ninguna operación de
//! emparejamiento ni de curva elíptica**, de ahí la coherencia post-cuántica.

use super::field::{root_of_unity, Felt};

/// Permutación bit-reversal in situ (longitud potencia de dos).
fn bit_reverse(a: &mut [Felt]) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// NTT in situ. Si `inverse`, aplica la NTT inversa (incluye el `1/n`).
/// `a.len()` debe ser potencia de dos (`= 2^k`, `k ≤ 32`).
fn ntt_inplace(a: &mut [Felt], inverse: bool) {
    let n = a.len();
    if n == 1 {
        return;
    }
    debug_assert!(n.is_power_of_two());
    let k = n.trailing_zeros();
    bit_reverse(a);

    let mut len = 2usize;
    while len <= n {
        // raíz de orden `len`
        let w_len = {
            let w = root_of_unity(len.trailing_zeros());
            if inverse {
                w.inv()
            } else {
                w
            }
        };
        let half = len / 2;
        let mut i = 0;
        while i < n {
            let mut w = Felt::ONE;
            for j in 0..half {
                let u = a[i + j];
                let v = a[i + j + half].mul(w);
                a[i + j] = u.add(v);
                a[i + j + half] = u.sub(v);
                w = w.mul(w_len);
            }
            i += len;
        }
        len <<= 1;
    }

    if inverse {
        let n_inv = Felt::new(n as u64).inv();
        for x in a.iter_mut() {
            *x = x.mul(n_inv);
        }
    }
    let _ = k;
}

/// Evalúa el polinomio `coeffs` (potencia de dos) sobre `⟨ω_n⟩`, devolviendo
/// `[f(ω^0), …, f(ω^{n-1})]`.
pub fn ntt(coeffs: &[Felt]) -> Vec<Felt> {
    let mut a = coeffs.to_vec();
    ntt_inplace(&mut a, false);
    a
}

/// Interpola: dados `[f(ω^0), …, f(ω^{n-1})]`, recupera los coeficientes de `f`.
pub fn intt(evals: &[Felt]) -> Vec<Felt> {
    let mut a = evals.to_vec();
    ntt_inplace(&mut a, true);
    a
}

/// Evalúa `coeffs` sobre el *coset* `offset · ⟨ω_n⟩`.
///
/// `f(offset·ω^j) = Σ_i (coeffs_i · offset^i) · ω^{ij}`, es decir, una NTT de
/// los coeficientes escalados por potencias de `offset`.
pub fn coset_ntt(coeffs: &[Felt], offset: Felt) -> Vec<Felt> {
    let mut scaled = Vec::with_capacity(coeffs.len());
    let mut pow = Felt::ONE;
    for c in coeffs {
        scaled.push(c.mul(pow));
        pow = pow.mul(offset);
    }
    ntt(&scaled)
}

/// Evalúa el polinomio `coeffs` en un punto arbitrario `x` (Horner, `O(n)`).
pub fn eval_at(coeffs: &[Felt], x: Felt) -> Felt {
    let mut acc = Felt::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc.mul(x).add(*c);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field::root_of_unity;

    #[test]
    fn ntt_intt_roundtrip() {
        let coeffs: Vec<Felt> = (0..16).map(|i| Felt::new(i * 3 + 1)).collect();
        let evals = ntt(&coeffs);
        let back = intt(&evals);
        assert_eq!(coeffs, back);
    }

    #[test]
    fn ntt_matches_naive_eval() {
        let coeffs: Vec<Felt> = (0..8).map(|i| Felt::new(i * 7 + 2)).collect();
        let evals = ntt(&coeffs);
        let w = root_of_unity(3); // orden 8
        for (j, e) in evals.iter().enumerate() {
            let x = w.pow(j as u64);
            assert_eq!(*e, eval_at(&coeffs, x), "j={}", j);
        }
    }

    #[test]
    fn coset_ntt_matches_naive_eval() {
        let coeffs: Vec<Felt> = (0..8).map(|i| Felt::new(i + 5)).collect();
        let offset = Felt::new(super::super::field::GENERATOR);
        let evals = coset_ntt(&coeffs, offset);
        let w = root_of_unity(3);
        for (j, e) in evals.iter().enumerate() {
            let x = offset.mul(w.pow(j as u64));
            assert_eq!(*e, eval_at(&coeffs, x), "j={}", j);
        }
    }
}
