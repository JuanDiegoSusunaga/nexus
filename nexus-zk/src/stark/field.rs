//! Campo finito de Goldilocks `p = 2^64 - 2^32 + 1`.
//!
//! Se elige este primo porque `p - 1 = 2^32 · (2^32 - 1)` tiene 2-adicidad 32:
//! existen raíces de la unidad de orden `2^k` para todo `k ≤ 32`, lo que habilita
//! la NTT radix-2 (y por tanto la codificación Reed–Solomon que sustenta FRI).
//!
//! Toda la aritmética usa `u128` como acumulador y reduce módulo `p`. Es la
//! variante *simple y verificable* (no la reducción rápida específica de
//! Goldilocks): suficiente para un prototipo de referencia.

use serde::{Deserialize, Serialize};

/// Primo de Goldilocks.
pub const P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1
const P128: u128 = P as u128;

/// Generador del grupo multiplicativo `F_p^*` (orden `p-1`).
/// `7` es raíz primitiva de Goldilocks (uso estándar en Plonky2/Polygon).
pub const GENERATOR: u64 = 7;

/// Elemento del campo, representado por su residuo canónico en `[0, p)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Felt(u64);

impl Felt {
    pub const ZERO: Felt = Felt(0);
    pub const ONE: Felt = Felt(1);

    /// Construye un elemento reduciendo módulo `p`.
    #[inline]
    pub fn new(x: u64) -> Self {
        Felt(if x >= P { x - P } else { x })
    }

    /// Construye desde un `u128` arbitrario (reduce módulo `p`).
    #[inline]
    pub fn from_u128(x: u128) -> Self {
        Felt((x % P128) as u64)
    }

    #[inline]
    pub fn value(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn add(self, other: Felt) -> Felt {
        Felt(((self.0 as u128 + other.0 as u128) % P128) as u64)
    }

    #[inline]
    pub fn sub(self, other: Felt) -> Felt {
        // self + (p - other), evitando subdesbordamiento.
        Felt(((self.0 as u128 + P128 - other.0 as u128) % P128) as u64)
    }

    #[inline]
    pub fn neg(self) -> Felt {
        if self.0 == 0 {
            Felt(0)
        } else {
            Felt(P - self.0)
        }
    }

    #[inline]
    pub fn mul(self, other: Felt) -> Felt {
        Felt(((self.0 as u128 * other.0 as u128) % P128) as u64)
    }

    /// Exponenciación rápida `self^exp`.
    pub fn pow(self, mut exp: u64) -> Felt {
        let mut base = self;
        let mut acc = Felt::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    /// Inverso multiplicativo vía el pequeño teorema de Fermat: `a^(p-2)`.
    /// Pánico si `self == 0` (cero no es invertible).
    pub fn inv(self) -> Felt {
        assert!(self.0 != 0, "inverso de cero");
        self.pow(P - 2)
    }

    /// Serializa a 8 bytes little-endian del residuo canónico.
    #[inline]
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Deserializa desde 8 bytes little-endian (reduce módulo `p`).
    #[inline]
    pub fn from_bytes(b: [u8; 8]) -> Felt {
        Felt::new(u64::from_le_bytes(b))
    }
}

/// Raíz primitiva de la unidad de orden `2^k`, con `k ≤ 32`.
///
/// `omega = g^((p-1)/2^k)`. Como `p-1 = 0xFFFFFFFF_00000000` tiene 32 ceros
/// de orden bajo, el desplazamiento `(p-1) >> k` es exacto para `k ≤ 32`.
pub fn root_of_unity(k: u32) -> Felt {
    assert!(k <= 32, "Goldilocks solo admite 2-adicidad hasta 32");
    let exp = (P - 1) >> k; // (p-1)/2^k, exacto
    Felt::new(GENERATOR).pow(exp)
}

impl std::fmt::Debug for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Felt({})", self.0)
    }
}

/// Constante del campo de extensión: `F_{p^2} = F_p[X]/(X^2 - W)` con `W = 7`.
/// `7` es no-residuo cuadrático en Goldilocks (verificado en los tests), por lo
/// que `X^2 - 7` es irreducible. Es la elección estándar de Plonky2.
pub const FP2_W: u64 = 7;

/// Elemento del campo de extensión cuadrático `F_{p^2}`, representado como
/// `c0 + c1·X` con `X^2 = 7`.
///
/// Se usa para **todos los desafíos del verificador** (coeficientes de
/// combinación `α`, de plegado `β`): al vivir en un campo de ≈`2^128`, los
/// términos de soundness `~deg/|F|` de la combinación de restricciones y del
/// plegado FRI bajan por debajo de `2^{-100}`, lo que el campo base (`2^64`) no
/// permite. La traza, el dominio y la NTT permanecen en `F_p`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fp2 {
    pub c0: Felt,
    pub c1: Felt,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Felt::ZERO, c1: Felt::ZERO };
    pub const ONE: Fp2 = Fp2 { c0: Felt::ONE, c1: Felt::ZERO };

    #[inline]
    pub fn new(c0: Felt, c1: Felt) -> Self {
        Fp2 { c0, c1 }
    }

    /// Inmersión del campo base `a ↦ a + 0·X`.
    #[inline]
    pub fn from_base(a: Felt) -> Self {
        Fp2 { c0: a, c1: Felt::ZERO }
    }

    #[inline]
    pub fn add(self, o: Fp2) -> Fp2 {
        Fp2 { c0: self.c0.add(o.c0), c1: self.c1.add(o.c1) }
    }

    #[inline]
    pub fn sub(self, o: Fp2) -> Fp2 {
        Fp2 { c0: self.c0.sub(o.c0), c1: self.c1.sub(o.c1) }
    }

    /// `(a0+a1·X)(b0+b1·X) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·X`.
    #[inline]
    pub fn mul(self, o: Fp2) -> Fp2 {
        let w = Felt::new(FP2_W);
        let c0 = self.c0.mul(o.c0).add(w.mul(self.c1.mul(o.c1)));
        let c1 = self.c0.mul(o.c1).add(self.c1.mul(o.c0));
        Fp2 { c0, c1 }
    }

    /// Multiplicación por un escalar del campo base (más barata que `mul`).
    #[inline]
    pub fn mul_base(self, b: Felt) -> Fp2 {
        Fp2 { c0: self.c0.mul(b), c1: self.c1.mul(b) }
    }

    /// Inverso vía la norma `N = c0^2 - W·c1^2 ∈ F_p`: `inv = (c0 - c1·X)/N`.
    pub fn inv(self) -> Fp2 {
        let w = Felt::new(FP2_W);
        let n = self.c0.mul(self.c0).sub(w.mul(self.c1.mul(self.c1)));
        let ninv = n.inv();
        Fp2 { c0: self.c0.mul(ninv), c1: self.c1.neg().mul(ninv) }
    }

    /// Serializa a 16 bytes (`c0 || c1`, cada uno 8 bytes LE).
    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.c0.to_bytes());
        b[8..].copy_from_slice(&self.c1.to_bytes());
        b
    }
}

impl std::fmt::Debug for Fp2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fp2({}, {})", self.c0.0, self.c1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        let a = Felt::new(12345);
        let b = Felt::new(99999);
        assert_eq!(a.add(b).sub(b), a);
        assert_eq!(a.sub(a), Felt::ZERO);
        assert_eq!(a.add(a.neg()), Felt::ZERO);
    }

    #[test]
    fn mul_inv_roundtrip() {
        for x in [1u64, 2, 7, 1000, P - 1, 0x1234_5678_9abc_def0] {
            let a = Felt::new(x);
            assert_eq!(a.mul(a.inv()), Felt::ONE, "x={}", x);
        }
    }

    #[test]
    fn near_modulus_arithmetic() {
        let a = Felt::new(P - 1); // = -1
        assert_eq!(a.add(Felt::ONE), Felt::ZERO);
        assert_eq!(a.mul(a), Felt::ONE); // (-1)^2 = 1
    }

    #[test]
    fn root_of_unity_has_correct_order() {
        for k in 1u32..=12 {
            let w = root_of_unity(k);
            let n = 1u64 << k;
            // orden divide 2^k: w^(2^k) = 1
            assert_eq!(w.pow(n), Felt::ONE, "k={}", k);
            // primitiva: w^(2^(k-1)) = -1 (no 1)
            assert_eq!(w.pow(n / 2), Felt::new(P - 1), "k={}", k);
        }
    }

    #[test]
    fn legendre_seven_is_non_residue() {
        // X^2 - 7 es irreducible sii 7 es no-residuo cuadrático: 7^((p-1)/2) = -1.
        let seven = Felt::new(FP2_W);
        assert_eq!(seven.pow((P - 1) / 2), Felt::new(P - 1), "7 debe ser no-residuo");
    }

    #[test]
    fn fp2_is_field() {
        let a = Fp2::new(Felt::new(3), Felt::new(5));
        let b = Fp2::new(Felt::new(7), Felt::new(11));
        // anillo conmutativo con unidad
        assert_eq!(a.mul(b), b.mul(a));
        assert_eq!(a.mul(Fp2::ONE), a);
        assert_eq!(a.add(Fp2::ZERO), a);
        assert_eq!(a.sub(a), Fp2::ZERO);
        // inverso multiplicativo
        assert_eq!(a.mul(a.inv()), Fp2::ONE);
        assert_eq!(b.mul(b.inv()), Fp2::ONE);
        // inmersión del campo base y mul_base coherentes
        let s = Felt::new(9);
        assert_eq!(a.mul_base(s), a.mul(Fp2::from_base(s)));
        // distributividad
        assert_eq!(a.mul(b.add(Fp2::ONE)), a.mul(b).add(a));
    }
}
