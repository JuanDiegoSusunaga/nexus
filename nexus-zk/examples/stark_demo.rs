//! Medición del STARK hash-based (PoC del Nitro Verifier).
//!
//! Ejecuta `cargo run -p nexus-zk --example stark_demo --release` para obtener
//! tamaño de prueba y tiempos de generación/verificación por tamaño de traza.

use std::time::Instant;

use nexus_zk::stark::field::Felt;
use nexus_zk::stark::{
    air::proof_size_bytes, prove_state_transition, verify_state_transition,
};

fn main() {
    println!("STARK hash-based (Goldilocks + NTT + Merkle/SHA3 + FRI), desafíos en F_p^2,");
    println!("blowup=8, 40 consultas, grinding 2^20 (~100 bits de soundness)");
    println!(
        "{:>8} | {:>10} | {:>12} | {:>12} | {:>10}",
        "pasos", "prueba", "generar", "verificar", "verif/s"
    );
    println!("{}", "-".repeat(64));

    for &steps in &[16usize, 64, 256, 1024, 4096] {
        // Generación.
        let t0 = Instant::now();
        let (stmt, proof) = prove_state_transition(Felt::new(3), Felt::new(5), steps);
        let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

        // Verificación (promedio de varias iteraciones para estabilidad).
        let iters = 20;
        let t1 = Instant::now();
        let mut ok = true;
        for _ in 0..iters {
            ok &= verify_state_transition(&stmt, &proof);
        }
        let verify_ms = t1.elapsed().as_secs_f64() * 1e3 / iters as f64;
        assert!(ok, "la prueba debe verificar");

        let size = proof_size_bytes(&proof);
        let vps = 1000.0 / verify_ms;

        println!(
            "{:>8} | {:>8} B | {:>9.2} ms | {:>9.3} ms | {:>10.0}",
            steps, size, prove_ms, verify_ms, vps
        );
    }
}
