//! Repeticiones independientes de la recurrencia ilustrativa; no son transacciones.
use nexus_core::NexusError;
use nexus_zk::stark::{field::Felt, params::POW_BITS_RUNTIME,
    prove_state_transition, verify_state_transition};
use std::{fs::File, io::Write, time::Instant};

fn main() -> Result<(), NexusError> {
    let path = std::env::args().nth(1).ok_or_else(||
        NexusError::ConfigError("Uso: tg2_stark_measure <archivo CSV>".into()))?;
    let mut output = File::create(path)?;
    writeln!(output, "repetition,steps,proof_bytes,prove_ns,verify_iterations,verify_total_ns,queries,pow_bits_runtime")?;
    // Calentamiento separado de las muestras reportadas.
    let (statement, proof) = prove_state_transition(Felt::new(3), Felt::new(5), 16);
    if !verify_state_transition(&statement, &proof) { return Err(NexusError::ProofVerificationFailed); }
    for repetition in 1..=5 {
        for steps in [16, 64, 256, 1024, 4096, 16384, 65536, 262144] {
            let start = Instant::now();
            let (statement, proof) = prove_state_transition(Felt::new(3), Felt::new(5 + repetition), steps);
            let prove_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            let iterations = 20;
            for _ in 0..iterations {
                if !std::hint::black_box(verify_state_transition(&statement, &proof)) {
                    return Err(NexusError::ProofVerificationFailed);
                }
            }
            let verify_total_ns = start.elapsed().as_nanos();
            let size = bincode::serialized_size(&proof)?;
            writeln!(output, "{repetition},{steps},{size},{prove_ns},{iterations},{verify_total_ns},{},{POW_BITS_RUNTIME}", proof.queries.len())?;
            output.flush()?;
            println!("repeticion={repetition}; filas={steps}; prueba_bytes={size}; generar_ms={:.3}; verificar_ms={:.3}",
                prove_ns as f64 / 1e6, verify_total_ns as f64 / iterations as f64 / 1e6);
        }
    }
    Ok(())
}
