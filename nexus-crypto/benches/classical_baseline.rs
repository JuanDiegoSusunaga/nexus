//! Classical-cryptography baselines (ECDSA P-256, RSA) for comparison
//! against the post-quantum Dilithium benchmarks (`dilithium_bench.rs`).
//!
//! These schemes are the incumbent signatures in banking infrastructure and
//! are exactly the ones broken by Shor's algorithm; they are benchmarked here
//! only as a performance baseline for the thesis (Objective 4, Act 4.2).
//!
//! RSA-3072 key generation is intentionally not benchmarked: it takes seconds
//! per key, is not on any hot path, and would dominate the suite's runtime.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use p256::ecdsa::{SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use rsa::RsaPrivateKey;

const MESSAGE: &[u8] = b"NEXUS Post-Quantum Blockchain Test Message for Benchmarking";

fn bench_classical_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("classical_key_generation");

    group.bench_function("EcdsaP256", |b| {
        b.iter(|| black_box(EcdsaSigningKey::random(&mut rand::thread_rng())));
    });

    // RSA keygen is orders of magnitude slower than everything else in the
    // suite; 10 samples keep the total runtime bounded.
    group.sample_size(10);
    group.bench_function("Rsa2048", |b| {
        b.iter(|| black_box(RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap()));
    });

    group.finish();
}

fn bench_classical_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("classical_signing");

    let ecdsa_key = EcdsaSigningKey::random(&mut rand::thread_rng());
    group.bench_function("EcdsaP256", |b| {
        b.iter(|| {
            let sig: p256::ecdsa::Signature = ecdsa_key.sign(MESSAGE);
            black_box(sig)
        });
    });

    for bits in [2048usize, 3072] {
        let rsa_key = RsaSigningKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap(),
        );
        group.bench_function(format!("Rsa{bits}"), |b| {
            b.iter(|| black_box(rsa_key.sign(MESSAGE).to_bytes()));
        });
    }

    group.finish();
}

fn bench_classical_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("classical_verification");

    let ecdsa_key = EcdsaSigningKey::random(&mut rand::thread_rng());
    let ecdsa_pub = EcdsaVerifyingKey::from(&ecdsa_key);
    let ecdsa_sig: p256::ecdsa::Signature = ecdsa_key.sign(MESSAGE);
    group.bench_function("EcdsaP256", |b| {
        b.iter(|| black_box(ecdsa_pub.verify(MESSAGE, &ecdsa_sig).unwrap()));
    });

    for bits in [2048usize, 3072] {
        let rsa_key = RsaSigningKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap(),
        );
        let rsa_pub: RsaVerifyingKey<Sha256> = rsa_key.verifying_key();
        let rsa_sig = rsa_key.sign(MESSAGE);
        group.bench_function(format!("Rsa{bits}"), |b| {
            b.iter(|| black_box(rsa_pub.verify(MESSAGE, &rsa_sig).unwrap()));
        });
    }

    group.finish();
}

criterion_group!(
    classical,
    bench_classical_key_generation,
    bench_classical_signing,
    bench_classical_verification,
);

criterion_main!(classical);
