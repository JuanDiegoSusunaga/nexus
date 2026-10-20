//! Perfiles de trabajo y cálculo histórico del PoC.
//!
//! `budget()` conserva una estimación idealizada para reproducir los ensayos;
//! NO implementa la cota ROM de Lean ni acredita 100 bits del protocolo.
//! No basta sumar consultas, tamaño de campo y trabajo: la cota formalizada
//! depende del presupuesto adversario, de excepciones y del acoplamiento.
//! La ruta `linked` usa únicamente los perfiles explícitos de 12 o 20 bits,
//! y no consulta esta estimación para autorizar certificados.

use super::air::BLOWUP;
use super::fri::NUM_QUERIES;

/// Objetivo histórico, no garantía demostrada del protocolo.
pub const SECURITY_BITS_TARGET: u32 = 100;
/// Perfil de trabajo del binario release del prototipo; no acredita 100 bits.
pub const POW_BITS: u32 = 20;

/// Bits de proof-of-work **usados en tiempo de ejecución**. En `release`
/// coincide con [`POW_BITS`] (20). En `debug` se reduce para que la batería de
/// tests no pague `2^20` hashes por prueba. `budget()` no certifica este perfil.
pub const POW_BITS_RUNTIME: u32 = if cfg!(debug_assertions) { 12 } else { POW_BITS };

/// Invariante en tiempo de compilación: un binario `release`
/// sin `debug_assertions`) usa siempre el grinding completo de [`POW_BITS`], de
/// modo que el perfil ejecutado no dependa de los bytes recibidos.
#[cfg(not(debug_assertions))]
const _: () = assert!(
    POW_BITS_RUNTIME == POW_BITS,
    "release debe usar el grinding completo POW_BITS"
);
/// Grado del campo de extensión de desafíos (`F_{p^2}`).
pub const FIELD_EXT_DEGREE: u32 = 2;

/// Estimación histórica idealizada; no representa la cota conservadora de Lean.
#[derive(Debug, Clone, Copy)]
pub struct SoundnessBudget {
    pub rate_inv: f64,
    pub num_queries: usize,
    pub pow_bits: u32,
    /// Bits de la fase de consulta bajo *proximity gaps* (conjetural).
    pub bits_query_pg: f64,
    /// Bits de la fase de consulta bajo decodificación única (provable).
    pub bits_query_udr: f64,
    pub bits_total_pg: f64,
    pub bits_total_udr: f64,
}

/// Reproduce la estimación histórica; no se usa como condición de aceptación.
pub fn budget() -> SoundnessBudget {
    // CP tiene grado ≤ T y N = BLOWUP·T, degree_bound = 2T ⇒ ρ = 2/BLOWUP.
    let rho = 2.0 / BLOWUP as f64;
    let rate_inv = 1.0 / rho;
    let q = NUM_QUERIES as f64;
    let bits_query_pg = q * rate_inv.log2();
    let bits_query_udr = q * (-(((1.0 + rho) / 2.0).log2()));
    SoundnessBudget {
        rate_inv,
        num_queries: NUM_QUERIES,
        pow_bits: POW_BITS,
        bits_query_pg,
        bits_query_udr,
        bits_total_pg: bits_query_pg + POW_BITS as f64,
        bits_total_udr: bits_query_udr + POW_BITS as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soundness_budget_print() {
        let b = budget();
        eprintln!("=== Presupuesto de soundness del STARK ===");
        eprintln!("rate ρ = 1/{:.0}, consultas = {}, grinding = {} bits", b.rate_inv, b.num_queries, b.pow_bits);
        eprintln!("Fase de consulta (proximity-gaps, conjetural): {:.1} bits", b.bits_query_pg);
        eprintln!("Fase de consulta (decodificación única, provable): {:.1} bits", b.bits_query_udr);
        eprintln!("TOTAL query+grind (proximity-gaps): {:.1} bits", b.bits_total_pg);
        eprintln!("TOTAL query+grind (decod. única):   {:.1} bits", b.bits_total_udr);
        eprintln!("ε_α, ε_β (combinación/plegado en F_p^2): > 100 bits (techo del campo de extensión)");
        // A ρ=1/4 y 40 consultas: proximity-gaps da 80+20=100 bits.
        assert!(b.bits_total_pg >= 100.0, "objetivo proximity-gaps ≥ 100 bits");
    }
}
