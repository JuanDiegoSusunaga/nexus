//! Benchmarks for Dilithium signature operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use nexus_crypto::dilithium::DilithiumKeypair;
use nexus_core::SignatureScheme;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    for scheme in [
        SignatureScheme::Dilithium2,
        SignatureScheme::Dilithium3,
        SignatureScheme::Dilithium5,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &scheme,
            |b, &scheme| {
                b.iter(|| {
                    black_box(DilithiumKeypair::generate(scheme).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let message = b"NEXUS Post-Quantum Blockchain Test Message for Benchmarking";

    for scheme in [
        SignatureScheme::Dilithium2,
        SignatureScheme::Dilithium3,
        SignatureScheme::Dilithium5,
    ] {
        let keypair = DilithiumKeypair::generate(scheme).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &keypair,
            |b, keypair| {
                b.iter(|| {
                    black_box(keypair.sign(message).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");
    let message = b"NEXUS Post-Quantum Blockchain Test Message for Benchmarking";

    for scheme in [
        SignatureScheme::Dilithium2,
        SignatureScheme::Dilithium3,
        SignatureScheme::Dilithium5,
    ] {
        let keypair = DilithiumKeypair::generate(scheme).unwrap();
        let signature = keypair.sign(message).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &(keypair, signature),
            |b, (keypair, signature)| {
                b.iter(|| {
                    black_box(keypair.verify(message, signature).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_sign_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_and_verify");
    let message = b"NEXUS Post-Quantum Blockchain Test Message for Benchmarking";

    for scheme in [
        SignatureScheme::Dilithium2,
        SignatureScheme::Dilithium3,
        SignatureScheme::Dilithium5,
    ] {
        let keypair = DilithiumKeypair::generate(scheme).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", scheme)),
            &keypair,
            |b, keypair| {
                b.iter(|| {
                    let sig = keypair.sign(message).unwrap();
                    black_box(keypair.verify(message, &sig).unwrap())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_sign_and_verify,
);

criterion_main!(benches);
