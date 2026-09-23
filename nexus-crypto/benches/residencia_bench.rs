//! Benchmark de la **política de residencia efímera** (KeyGen-por-firma) —
//! Cap. 5 §5.6, contribución C1. Hace reproducible la "medición dedicada"
//! citada en el manuscrito.
//!
//! Compara, por nivel de seguridad:
//! - `firma_cacheada`: la clave expandida vive en memoria y solo se firma
//!   (política que recomienda draft-connolly).
//! - `firma_efimera`: por cada firma se re-expande la semilla de 32 B
//!   (`from_seed`, FIPS 204 §3.6.3), se firma y se zeroiza la clave expandida
//!   (drop → `ZeroizeOnDrop`). El sobrecosto de la política es la diferencia
//!   entre ambas medianas.
//! - `keygen_desde_semilla`: el componente de expansión aislado.
//!
//! Estos tiempos no miden la residencia de todas las copias del secreto.
//! La semilla pública de prueba permanece disponible: reexpandirla no es rotar.
//! R5 separa clave codificada, objetos del backend y material público; no estima
//! bytes secretos sumando |pk|+|sk| ni convierte la latencia en riesgo de compromiso.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nexus_core::SignatureScheme;
use nexus_crypto::dilithium::DilithiumKeypair;

const MESSAGE: &[u8] = b"NEXUS Post-Quantum Blockchain Test Message for Benchmarking";
const SEED: [u8; 32] = [42u8; 32];

const SCHEMES: [SignatureScheme; 3] = [
    SignatureScheme::Dilithium2,
    SignatureScheme::Dilithium3,
    SignatureScheme::Dilithium5,
];

fn bench_firma_cacheada(c: &mut Criterion) {
    let mut group = c.benchmark_group("firma_cacheada");
    for scheme in SCHEMES {
        let keypair = DilithiumKeypair::from_seed(&SEED, scheme).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &keypair,
            |b, keypair| {
                b.iter(|| black_box(keypair.sign(MESSAGE).unwrap()));
            },
        );
    }
    group.finish();
}

fn bench_firma_efimera(c: &mut Criterion) {
    let mut group = c.benchmark_group("firma_efimera");
    for scheme in SCHEMES {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &scheme,
            |b, &scheme| {
                b.iter(|| {
                    // Expandir → firmar → zeroizar (el drop del keypair al
                    // salir del closure zeroiza la clave secreta expandida).
                    let keypair = DilithiumKeypair::from_seed(&SEED, scheme).unwrap();
                    black_box(keypair.sign(MESSAGE).unwrap())
                });
            },
        );
    }
    group.finish();
}

fn bench_keygen_desde_semilla(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen_desde_semilla");
    for scheme in SCHEMES {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &scheme,
            |b, &scheme| {
                b.iter(|| black_box(DilithiumKeypair::from_seed(&SEED, scheme).unwrap()));
            },
        );
    }
    group.finish();
}

criterion_group!(
    residencia,
    bench_firma_cacheada,
    bench_firma_efimera,
    bench_keygen_desde_semilla,
);

criterion_main!(residencia);
