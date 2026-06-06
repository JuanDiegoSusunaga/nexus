//! # STARK hash-based (PoC del Nitro Verifier)
//!
//! Prototipo de referencia de un sistema de pruebas de validez **post-cuántico**
//! para la capa de anclaje (L1) de NEXUS. A diferencia del andamiaje Groth16/BN254
//! (basado en emparejamientos, que el algoritmo de Shor rompería), este módulo
//! materializa la afirmación central del Cap. 3: un argumento de integridad cuya
//! seguridad reposa **solo** en funciones hash (Merkle + Fiat–Shamir) y en
//! aritmética de campo (NTT/FRI), sin curvas elípticas ni emparejamientos.
//!
//! Componentes:
//! - [`field`]: campo de Goldilocks `p = 2^64 - 2^32 + 1`.
//! - [`ntt`]: NTT radix-2 (codificación Reed–Solomon).
//! - [`merkle`]: compromiso de Merkle sobre SHA3-256.
//! - [`channel`]: transcripción de Fiat–Shamir (no interactividad).
//! - [`fri`]: prueba de bajo grado (FRI).
//! - [`air`]: aritmetización de una transición de estado y su composición.

pub mod air;
pub mod channel;
pub mod field;
pub mod fri;
pub mod merkle;
pub mod ntt;
pub mod params;

pub use air::{prove_state_transition, verify_state_transition, StarkProof, TransitionStatement};
