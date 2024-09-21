use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use rust_elgamal::{Commitment, DecryptionKey, RistrettoPoint, Scalar};

const TEST_SEED: [u8; 32] = [
    1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,
];

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(TEST_SEED);

    let dk = DecryptionKey::new(&mut rng);
    let ek = dk.encryption_key();
    let m = RistrettoPoint::random(&mut rng);
    let r = Scalar::random(&mut rng);

    c.bench_function("bench_encrypt", |b| {
        b.iter(|| {
            std::hint::black_box(ek.encrypt_with(m, r));
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(TEST_SEED);

    let dk = DecryptionKey::new(&mut rng);
    let ek = dk.encryption_key();
    let m = RistrettoPoint::random(&mut rng);
    let r = Scalar::random(&mut rng);
    let ct = ek.encrypt_with(m, r);

    c.bench_function("bench_decrypt", |b| {
        b.iter(|| {
            std::hint::black_box(dk.decrypt(ct));
        })
    });
}

fn bench_commitment(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(TEST_SEED);

    let dk = DecryptionKey::new(&mut rng);
    let y = dk.encryption_key();
    let m = Scalar::random(&mut rng);
    let r = Scalar::from(8u32);

    c.bench_function("bench_commitment", |b| {
        b.iter(|| {
            std::hint::black_box(Commitment::commit_with(m, r, y));
        })
    });
}
fn bench_verify_commitment(c: &mut Criterion) {
    let mut rng = StdRng::from_seed(TEST_SEED);

    let dk = DecryptionKey::new(&mut rng);
    let y = dk.encryption_key();
    let m = Scalar::random(&mut rng);
    let r = Scalar::from(8u32);
    let (open, commitment) = Commitment::commit_with(m, r, y);

    c.bench_function("bench_verify_commitment", |b| {
        b.iter(|| {
            std::hint::black_box(commitment.verify(&open));
        })
    });
}

criterion_group! {
    name = commitment;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets =
        bench_commitment,
        bench_verify_commitment
}

criterion_group! {
    name = encrypt_decrypt;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets =
        bench_encrypt,
        bench_decrypt
}
criterion_main!(encrypt_decrypt, commitment,);
