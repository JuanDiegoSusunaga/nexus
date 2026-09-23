//! Throughput de **verificación** de firmas ML-DSA en paralelo (Act. 4.2):
//! la métrica de capacidad de un sequencer/validador L2, medida por número
//! de hilos.
//!
//! Ejecutar: `cargo run -p nexus-crypto --example throughput_tps --release`
//!
//! Prepara un lote de transacciones firmadas (claves y mensajes distintos,
//! deterministas) y mide cuántas verificaciones por segundo sostiene la
//! máquina con 1..N hilos verificando en paralelo durante ~2 s por punto.

use nexus_core::SignatureScheme;
use nexus_crypto::dilithium::{DilithiumKeypair, DilithiumSignature};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const SCHEME: SignatureScheme = SignatureScheme::Dilithium3;
const BATCH: usize = 4096;
const SECONDS_PER_POINT: f64 = 2.0;

fn main() {
    let max_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    println!("Throughput de verificación {:?} — lote de {} firmas, ~{}s por punto", SCHEME, BATCH, SECONDS_PER_POINT);

    // Lote determinista: una identidad y un mensaje distintos por transacción.
    let t0 = Instant::now();
    let batch: Vec<(DilithiumKeypair, Vec<u8>, DilithiumSignature)> = (0..BATCH)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            seed[8] = 0x5E;
            let keypair = DilithiumKeypair::from_seed(&seed, SCHEME).unwrap();
            let msg = format!("NEXUS L2 tx #{i}: transfer 100 QN").into_bytes();
            let sig = keypair.sign(&msg).unwrap();
            (keypair, msg, sig)
        })
        .collect();
    // Sanidad: todas las firmas verifican.
    assert!(batch.iter().all(|(kp, m, s)| kp.verify(m, s).unwrap()));
    println!("lote preparado y verificado en {:.1} s\n", t0.elapsed().as_secs_f64());

    println!("{:>6} | {:>12} | {:>12} | {:>10}", "hilos", "verif/s", "µs/verif", "escalado");
    println!("{}", "-".repeat(50));
    let mut tps_1 = 0.0f64;
    for threads in [1usize, 2, 4, 8, 12, 16, 20, max_threads] {
        if threads > max_threads {
            break;
        }
        let stop = AtomicBool::new(false);
        let batch_ref = &batch;
        let stop_ref = &stop;
        let (total, elapsed) = thread::scope(|s| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut count = 0u64;
                        let mut i = t; // arranque escalonado para no compartir cachés
                        while !stop_ref.load(Ordering::Relaxed) {
                            let (kp, m, sig) = &batch_ref[i % BATCH];
                            assert!(kp.verify(m, sig).unwrap());
                            count += 1;
                            i += threads;
                        }
                        count
                    })
                })
                .collect();
            let start = Instant::now();
            thread::sleep(Duration::from_secs_f64(SECONDS_PER_POINT));
            stop.store(true, Ordering::Relaxed);
            let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
            (total, start.elapsed().as_secs_f64())
        });
        let tps = total as f64 / elapsed;
        if threads == 1 {
            tps_1 = tps;
        }
        println!(
            "{:>6} | {:>12.0} | {:>12.1} | {:>9.2}x",
            threads,
            tps,
            1e6 * elapsed * threads as f64 / total as f64,
            tps / tps_1,
        );
    }

    println!(
        "\n(|pk| = {} B, |firma| = {} B; verificación con clave pública, mensajes de ~30 B)",
        batch[0].0.public_key().as_bytes().len(),
        batch[0].2.as_bytes().len()
    );
}
