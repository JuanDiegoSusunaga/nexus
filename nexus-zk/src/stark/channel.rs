//! Canal de Fiat–Shamir (transcripción) sobre `Hash256`.
//!
//! Convierte el protocolo FRI interactivo en **no interactivo**: los desafíos
//! del verificador (coeficientes de combinación `α`, de plegado `β`, índices de
//! consulta) se derivan determinísticamente hasheando la transcripción de los
//! compromisos del probador. Al ser la fuente de aleatoriedad un hash, el
//! argumento es **simétrico** y resistente a Shor (heurística del oráculo
//! aleatorio).
//!
//! **Endurecimiento:**
//! - *Binding con separación de dominio.* Cada absorción lleva una **etiqueta de
//!   fase** y la **longitud** del dato (`absorb_tagged`), de modo que dos
//!   transcripciones con segmentos distintos nunca colisionen por concatenación
//!   ambigua. Los *squeeze* se etiquetan por tipo de reto (`"F"`, `"I"`, `"E"`).
//! - *Grinding (proof-of-work).* [`Channel::grind`] obliga al probador a hallar
//!   un *nonce* que haga la transcripción tener `bits` ceros de orden alto,
//!   añadiendo `bits` de soundness a la fase de consulta y anulando el ataque de
//!   re-muestreo de Fiat–Shamir.

use super::field::{Felt, Fp2};
use nexus_core::Hash256;

/// Etiquetas de fase (separación de dominio en la transcripción).
pub const TAG_TRACE_ROOT: u8 = 1;
pub const TAG_FRI_ROOT: u8 = 2;
pub const TAG_FINAL: u8 = 3;
pub const TAG_STATEMENT: u8 = 4;
pub const TAG_GRIND: u8 = 5;

/// Transcripción append-only. El estado es el hash acumulado.
#[derive(Clone)]
pub struct Channel {
    state: Hash256,
}

/// Cuenta los bits cero de orden alto (desde el byte 0, MSB) de un digest.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Digest de proof-of-work `SHA3(state || TAG_GRIND || nonce)` sobre un buffer
/// en pila (sin asignación), para que el bucle de grinding sea rápido.
fn pow_digest(state: &Hash256, nonce: u64) -> Hash256 {
    let mut buf = [0u8; 41];
    buf[..32].copy_from_slice(state.as_bytes());
    buf[32] = TAG_GRIND;
    buf[33..41].copy_from_slice(&nonce.to_le_bytes());
    Hash256::hash(&buf)
}

impl Channel {
    /// Inicializa con una etiqueta de separación de dominio.
    pub fn new(domain_sep: &[u8]) -> Self {
        Channel {
            state: Hash256::hash(domain_sep),
        }
    }

    /// Absorbe `data` bajo la etiqueta de fase `tag`, ligando también su longitud.
    /// `state ← SHA3(state || tag || len64(data) || data)`. La longitud es de 64
    /// bits (no 32) para que el prefijo sea inyectivo sin cota de tamaño.
    pub fn absorb_tagged(&mut self, tag: u8, data: &[u8]) {
        let mut buf = Vec::with_capacity(32 + 1 + 8 + data.len());
        buf.extend_from_slice(self.state.as_bytes());
        buf.push(tag);
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
        self.state = Hash256::hash(&buf);
    }

    /// Avanza el estado y devuelve sus bytes, etiquetando el *squeeze* por tipo.
    fn squeeze(&mut self, kind: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + kind.len());
        buf.extend_from_slice(self.state.as_bytes());
        buf.extend_from_slice(kind);
        self.state = Hash256::hash(&buf);
        *self.state.as_bytes()
    }

    /// Desafío de campo base. Toma 16 bytes y reduce módulo `p` (sesgo ≈ `p/2^128`).
    pub fn challenge_felt(&mut self) -> Felt {
        let bytes = self.squeeze(b"F");
        let mut le = [0u8; 16];
        le.copy_from_slice(&bytes[..16]);
        Felt::from_u128(u128::from_le_bytes(le))
    }

    /// Desafío del **campo de extensión** `F_{p^2}`: toma 32 bytes y produce las
    /// dos coordenadas (16 bytes cada una; sesgo ≈ `p/2^128` despreciable).
    pub fn challenge_ext(&mut self) -> Fp2 {
        let bytes = self.squeeze(b"E");
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&bytes[..16]);
        hi.copy_from_slice(&bytes[16..32]);
        Fp2::new(
            Felt::from_u128(u128::from_le_bytes(lo)),
            Felt::from_u128(u128::from_le_bytes(hi)),
        )
    }

    /// Índice de consulta uniforme en `[0, n)` (`n` potencia de dos).
    pub fn challenge_index(&mut self, n: usize) -> usize {
        let bytes = self.squeeze(b"I");
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[..8]);
        (u64::from_le_bytes(le) as usize) & (n - 1)
    }

    /// **Grinding (probador).** Halla el menor *nonce* tal que, tras absorberlo
    /// bajo `TAG_GRIND`, el estado tenga `>= bits` ceros de orden alto. Compromete
    /// el estado ganador (avanza la transcripción) y devuelve el *nonce*.
    pub fn grind(&mut self, bits: u32) -> u64 {
        let mut nonce = 0u64;
        loop {
            if leading_zero_bits(pow_digest(&self.state, nonce).as_bytes()) >= bits {
                // Compromete el nonce en la transcripción (igual que el verificador).
                self.absorb_tagged(TAG_GRIND, &nonce.to_le_bytes());
                return nonce;
            }
            nonce += 1;
        }
    }

    /// **Grinding (verificador).** Acepta el *nonce* si reproduce los `bits` de
    /// trabajo; en tal caso compromete el estado idéntico al del probador.
    pub fn check_grinding(&mut self, nonce: u64, bits: u32) -> bool {
        if leading_zero_bits(pow_digest(&self.state, nonce).as_bytes()) < bits {
            return false;
        }
        self.absorb_tagged(TAG_GRIND, &nonce.to_le_bytes());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic_and_order_sensitive() {
        let mut a = Channel::new(b"test");
        a.absorb_tagged(TAG_STATEMENT, b"x");
        let ca = a.challenge_felt();

        let mut b = Channel::new(b"test");
        b.absorb_tagged(TAG_STATEMENT, b"x");
        let cb = b.challenge_felt();
        assert_eq!(ca, cb, "misma transcripción ⇒ mismo desafío");

        let mut c = Channel::new(b"test");
        c.absorb_tagged(TAG_STATEMENT, b"y");
        assert_ne!(ca, c.challenge_felt(), "distinta entrada ⇒ distinto desafío");
    }

    #[test]
    fn tag_injectivity() {
        // Absorber el mismo blob bajo etiquetas distintas produce estados distintos.
        let mut a = Channel::new(b"t");
        a.absorb_tagged(TAG_TRACE_ROOT, b"abcdefgh");
        let mut b = Channel::new(b"t");
        b.absorb_tagged(TAG_FRI_ROOT, b"abcdefgh");
        assert_ne!(a.challenge_felt(), b.challenge_felt());
    }

    #[test]
    fn indices_in_range() {
        let mut ch = Channel::new(b"idx");
        for _ in 0..100 {
            let i = ch.challenge_index(64);
            assert!(i < 64);
        }
    }

    #[test]
    fn grinding_roundtrip() {
        let bits = 8; // bajo, para velocidad
        let mut prover = Channel::new(b"pow");
        prover.absorb_tagged(TAG_FINAL, b"data");
        let nonce = prover.grind(bits);

        let mut verifier = Channel::new(b"pow");
        verifier.absorb_tagged(TAG_FINAL, b"data");
        assert!(verifier.check_grinding(nonce, bits), "nonce válido aceptado");

        // nonce alterado ⇒ rechazo
        let mut v2 = Channel::new(b"pow");
        v2.absorb_tagged(TAG_FINAL, b"data");
        assert!(!v2.check_grinding(nonce.wrapping_add(1), bits));
    }
}
