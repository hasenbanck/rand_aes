use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand_aes::tls::{rand_fill_bytes, rand_seed_from_entropy, rand_u64};
use rand_aes::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};
use rand_core::{RngCore, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut seed = [0u8; 8];
    getrandom::getrandom(&mut seed).expect("Can't get OS entropy");
    let seed = u64::from_ne_bytes(seed);

    let mut aes128_64 = Aes128Ctr64::seed_from_u64(seed);
    let mut aes128_128: Aes128Ctr128 = Aes128Ctr128::seed_from_u64(seed);
    let mut aes256_64: Aes256Ctr64 = Aes256Ctr64::seed_from_u64(seed);
    let mut aes256_128: Aes256Ctr128 = Aes256Ctr128::seed_from_u64(seed);
    rand_seed_from_entropy();

    let mut cha_cha8 = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    let mut cha_cha12 = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
    let mut cha_cha20 = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    let mut lcg128_xsl64 = rand_pcg::Lcg128Xsl64::seed_from_u64(seed);
    let mut mcg128_xsl64 = rand_pcg::Mcg128Xsl64::seed_from_u64(seed);

    let mut x: u64 = 0;

    let mut group = c.benchmark_group("Latency");
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
    group.bench_function("ChaCha8", |b| {
        b.iter(|| {
            x = x.wrapping_add(cha_cha8.next_u64());
            black_box(x);
        })
    });
    group.bench_function("ChaCha12", |b| {
        b.iter(|| {
            x = x.wrapping_add(cha_cha12.next_u64());
            black_box(x);
        })
    });
    group.bench_function("ChaCha20", |b| {
        b.iter(|| {
            x = x.wrapping_add(cha_cha20.next_u64());
            black_box(x);
        })
    });
    group.bench_function("Lcg128Xsl64", |b| {
        b.iter(|| {
            x = x.wrapping_add(lcg128_xsl64.next_u64());
            black_box(x);
        })
    });
    group.bench_function("Mcg128Xsl64", |b| {
        b.iter(|| {
            x = x.wrapping_add(mcg128_xsl64.next_u64());
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
    group.bench_function("ChaCha8", |b| b.iter(|| cha_cha8.fill_bytes(&mut buffer)));
    group.bench_function("ChaCha12", |b| b.iter(|| cha_cha12.fill_bytes(&mut buffer)));
    group.bench_function("ChaCha20", |b| b.iter(|| cha_cha20.fill_bytes(&mut buffer)));
    group.bench_function("Lcg128Xsl64", |b| {
        b.iter(|| lcg128_xsl64.fill_bytes(&mut buffer))
    });
    group.bench_function("Mcg128Xsl64", |b| {
        b.iter(|| mcg128_xsl64.fill_bytes(&mut buffer))
    });
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
