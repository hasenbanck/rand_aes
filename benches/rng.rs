use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand_aes::{
    rand_fill_bytes, rand_seed_tls_from_entropy, rand_u64,
    seeds::{Aes128Ctr128Seed, Aes128Ctr64Seed, Aes256Ctr128Seed, Aes256Ctr64Seed},
    Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64,
};
use rand_core::{RngCore, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut aes128_64 = Aes128Ctr64::from_seed(Aes128Ctr64Seed::from_entropy());
    let mut aes128_128: Aes128Ctr128 = Aes128Ctr128::from_seed(Aes128Ctr128Seed::from_entropy());
    let mut aes256_64: Aes256Ctr64 = Aes256Ctr64::from_seed(Aes256Ctr64Seed::from_entropy());
    let mut aes256_128: Aes256Ctr128 = Aes256Ctr128::from_seed(Aes256Ctr128Seed::from_entropy());
    rand_seed_tls_from_entropy();

    let mut group = c.benchmark_group("Latency (unrealistic)");
    group.bench_function("Aes128Ctr64", |b| {
        b.iter(|| {
            black_box(aes128_64.next_u64());
        })
    });
    group.bench_function("Aes128Ctr128", |b| {
        b.iter(|| {
            black_box(aes128_128.next_u64());
        })
    });
    group.bench_function("Aes256Ctr64", |b| {
        b.iter(|| {
            black_box(aes256_64.next_u64());
        })
    });
    group.bench_function("Aes256Ctr128", |b| {
        b.iter(|| {
            black_box(aes256_128.next_u64());
        })
    });
    group.bench_function("TLS", |b| {
        b.iter(|| {
            black_box(rand_u64());
        })
    });
    group.finish();

    let mut x: u64 = 0;

    let mut group = c.benchmark_group("Latency (tight)");
    group.bench_function("Aes128Ctr64", |b| {
        b.iter(|| {
            x = x.wrapping_add(aes128_64.next_u64());
            black_box(x);
        })
    });
    group.bench_function("Aes128Ctr128", |b| {
        b.iter(|| {
            x = x.wrapping_add(aes128_128.next_u64());
            black_box(x);
        })
    });
    group.bench_function("Aes256Ctr64", |b| {
        b.iter(|| {
            x = x.wrapping_add(aes256_64.next_u64());
            black_box(x);
        })
    });
    group.bench_function("Aes256Ctr128", |b| {
        b.iter(|| {
            x = x.wrapping_add(aes256_128.next_u64());
            black_box(x);
        })
    });
    group.bench_function("TLS", |b| {
        b.iter(|| {
            x = x.wrapping_add(rand_u64());
            black_box(x);
        })
    });
    group.finish();

    const SIZE: usize = 1014 * 1014;
    let mut buffer = vec![0u8; SIZE];

    let mut group = c.benchmark_group("Throughput");
    group.throughput(Throughput::Bytes(SIZE as u64));
    group.bench_function("Aes128Ctr64", |b| {
        b.iter(|| aes128_64.fill_bytes(&mut buffer))
    });
    group.bench_function("Aes128Ct128", |b| {
        b.iter(|| aes128_128.fill_bytes(&mut buffer))
    });
    group.bench_function("Aes256Ctr64", |b| {
        b.iter(|| aes256_64.fill_bytes(&mut buffer))
    });
    group.bench_function("Aes256Ct128", |b| {
        b.iter(|| aes256_128.fill_bytes(&mut buffer))
    });
    group.bench_function("TLS", |b| b.iter(|| rand_fill_bytes(&mut buffer)));
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
