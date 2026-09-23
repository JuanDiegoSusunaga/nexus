//! Medición TG2 con arranque coordinado e intervalo que incluye todo lo contado.
use nexus_core::{NexusError, SignatureScheme};
use nexus_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use std::{sync::Barrier, thread, time::{Duration, Instant}};
use zeroize::Zeroizing;

pub type PublicSample = (DilithiumPublicKey, Vec<u8>, DilithiumSignature);

pub fn prepare_batch(size: usize) -> Result<Vec<PublicSample>, NexusError> {
    if size == 0 { return Err(NexusError::ConfigError("Lote vacío".into())); }
    let mut batch = Vec::with_capacity(size);
    for index in 0..size {
        let mut seed = Zeroizing::new([0; 32]);
        seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
        seed[8] = 0x5E;
        let pair = DilithiumKeypair::from_seed(&seed, SignatureScheme::Dilithium3)?;
        let message = format!("NEXUS TG2: operacion de prueba #{index}").into_bytes();
        let signature = pair.sign(&message)?;
        if !pair.verify(&message, &signature)? {
            return Err(NexusError::CryptoError("Firma del corpus inválida".into()));
        }
        batch.push((pair.public_key().clone(), message, signature));
    }
    Ok(batch)
}

#[derive(Debug)]
pub struct Trial {
    pub count: u64,
    pub elapsed_ns: u128,
    pub worker_counts: Vec<u64>,
}

impl Trial {
    pub fn verifications_per_second(&self) -> f64 {
        self.count as f64 * 1e9 / self.elapsed_ns as f64
    }
}

pub fn measure(batch: &[PublicSample], workers: usize, duration: Duration) -> Result<Trial, NexusError> {
    if batch.is_empty() || workers == 0 || workers > 256 || duration.is_zero() {
        return Err(NexusError::ConfigError("Parámetros de medición inválidos".into()));
    }
    let barrier = Barrier::new(workers + 1);
    let start = std::sync::OnceLock::<Instant>::new();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..workers).map(|worker| {
            let barrier = &barrier;
            let start = &start;
            scope.spawn(move || -> Result<u64, NexusError> {
                // Primera barrera: todos los trabajadores existen y están listos.
                barrier.wait();
                // Segunda barrera: el reloj común ya está publicado antes de contar.
                barrier.wait();
                let started = start.get().ok_or_else(|| NexusError::Internal("Reloj no publicado".into()))?;
                let mut count = 0;
                let mut index = worker % batch.len();
                while started.elapsed() < duration {
                    let (public, message, signature) = &batch[index];
                    if !public.verify(message, signature)? {
                        return Err(NexusError::CryptoError("Verificación inválida en el ensayo".into()));
                    }
                    count += 1;
                    index = (index + workers) % batch.len();
                }
                Ok(count)
            })
        }).collect();
        barrier.wait();
        let started = Instant::now();
        let published = start.set(started);
        // La barrera se libera incluso si fallara la publicación, para poder unir los hilos.
        barrier.wait();
        let mut worker_counts = Vec::new();
        for handle in handles {
            worker_counts.push(handle.join().map_err(|_| NexusError::Internal("Falló un trabajador".into()))??);
        }
        let elapsed_ns = started.elapsed().as_nanos();
        published.map_err(|_| NexusError::Internal("El reloj ya estaba publicado".into()))?;
        Ok(Trial { count: worker_counts.iter().sum(), elapsed_ns, worker_counts })
    })
}
