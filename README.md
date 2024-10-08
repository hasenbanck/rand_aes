# AES based pseudo-random number generator

[![CI](https://github.com/hasenbanck/rand_aes/actions/workflows/ci.yml/badge.svg)](https://github.com/hasenbanck/rand_aes/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/rand_aes.svg)](https://crates.io/crates/rand_aes)
[![API](https://docs.rs/rand_aes/badge.svg)](https://docs.rs/rand_aes)

This crate implements pseudo-random number generators (PRNG) using the AES block cipher in counter (CTR) mode.

## Features

- Based on well-established cryptographic principles.
- Optimized for low latency and high throughput.
- Passes rigorous statistic tests (`practrand` and `TESTu01`'s Big Crush).
- Provides the `Random` and `Jump` traits for common functionality.
- Supports the traits provided by the [`rand_core`](https://crates.io/crates/rand_core) crate.
- Support for secure initialization is provided by the [`getrandom`](https://crates.io/crates/getrandom) crate.
- Support for no_std.

## Crate features

- `getrandom`: Provides secure seeding functionality based on the [`getrandom`](https://crates.io/crates/getrandom)
  crate.
- `rand_core`: Implements the traits provided by the [`rand_core`](https://crates.io/crates/rand_core) crate.
- `tls`: Provides thread local based utility functions for easy random number generation.

This crate is `no_std` compatible when disabling the default features.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rand_aes = "0.1"
```

Then you can use it like this:

```rust
use rand_aes::{Random, Aes128Ctr64};

fn main() {
    let prng = Aes128Ctr64::from_entropy();
    let random_u64 = prng.u64;
}
```

## Counter implementation details

Uses either a 64-bit or 128-bit counter, which can be randomly seeded at initialization.
In case of the 64-bit counter we use a 128-bit variable and will seed the whole variable at initialization.
The higher 64-bit acts as a nonce in this case. The counter wraps on overflow, ensuring continuous operation.

## Security Note

While based on well-established cryptographic primitives, this PRNG is not intended for cryptographic key generation
or other sensitive cryptographic operations, simply because safe, automatic re-seeding is not provided. We tested its
statistical qualities by running versions with reduced rounds against `practrand` and `TESTu01`'s Big Crush.
A version with just 3 rounds of AES encryption rounds passes the `practrand` tests with at least 16 TB.
`TESTu01`'s Big Crush requires at least 5 rounds to be successfully cleared. AES-128 uses 10 rounds, whereas
AES-256 uses 14 rounds.

## Supported Architectures

We provide a software implementation of AES in case there is no hardware accelerated AES provided. We provide hardware
accelerated versions for the following architectures:

- aarch64: Support since Cortex-A53 (2012).
- riscv64: Experimental using the vector crypto extension.
- x86_64, x86: Support since Intel's Westmere (2010) and AMD's Bulldozer (2011).

## Experimental RISC-V support

There are two AES extensions for RISC-V, the scalar (zkn) and the vector crypto extensions (zvkn). Currently, there
are no hardware based CPUs that support either of them. It's also not clear which platform will favor which. Since
this crate mainly targets application class architectures (opposed to embedded), we think that providing a vector
crypto implementation is the safest bet. Since there are no intrinsics for the vector crypto extension, we provide
a handwritten ASM implementation. Since there is currently no way to discover the support for the vector crypto
extension (August 2024), you need to select the needed target features and an experimental create feature at compile
time. The generated executable will only run on systems with a vector crypto extension.

Activate the target features vor the vector extension and the vector crypto extension. This can be done for example
inside the `.cargo/config.toml`:

```toml
[target.'cfg(target_arch="riscv64")']
rustflags = ["-C", "target-feature=+v,+zvkn"]
```

You also need to select the `experimental_riscv` create feature. This feature is experimental and will
most likely become absolute in the future (once intrinsics and runtime discovery are available).

## Optimal Performance

We provide runtime detection for the hardware accelerated AES instruction set for all supported
platforms. Should the executing CPU not support hardware accelerated AES, a software fallback
is provided. But we highly recommend to enable the specific target feature on compile time,
since the AES instruction sets are available on modern desktop CPU for at least 10 years.
Enabling the target feature enables the compiler to more aggressively inline and provides
much better performance. The runtime detection is not supported in `no_std`.

Use the following target features for optimal performance:

- aarch64: "aes" (using the cryptographic extension)
- riscv64: "v" and "zvkn" (using the vector and vector crypto extension)
- x86: "sse2" and "aes" (using AES-NI)
- x86_64: "aes" (using AES-NI)

Example in `.cargo/config.toml`:

```toml
[target.'cfg(target_arch="aarch64")']
rustflags = ["-C", "target-feature=+aes"]

[target.'cfg(target_arch="riscv64")']
rustflags = ["-C", "target-feature=+v,+zvkn"]

[target.'cfg(target_arch="x86")']
rustflags = ["-C", "target-feature=+sse2,+aes"]

[target.'cfg(target_arch="x86_64")']
rustflags = ["-C", "target-feature=+aes"]
```

## Benchmark

Following benchmarks were made with version v0.1.0 and enabled hardware AES target features.

For aarch64 Laptop: M1 Pro (14' MacBook Pro, 2021)

```
Latency/TLS             time:   [1.1510 ns 1.1522 ns 1.1536 ns]
Latency/Aes128Ctr64     time:   [1.1830 ns 1.1895 ns 1.1964 ns]
Latency/Aes128Ctr128    time:   [1.3711 ns 1.3747 ns 1.3792 ns]
Latency/Aes256Ctr64     time:   [1.8304 ns 1.8478 ns 1.8678 ns]
Latency/Aes256Ctr128    time:   [2.0468 ns 2.0474 ns 2.0480 ns]
Latency/ChaCha8         time:   [5.9017 ns 5.9146 ns 5.9327 ns]
Latency/ChaCha12        time:   [8.3993 ns 8.4023 ns 8.4063 ns]
Latency/ChaCha20        time:   [13.577 ns 13.721 ns 13.917 ns]
Latency/Lcg128Xsl64     time:   [1.6307 ns 1.6323 ns 1.6344 ns]
Latency/Mcg128Xsl64     time:   [1.2409 ns 1.2417 ns 1.2427 ns]

Throughput/TLS          thrpt:  [12.655 GiB/s 12.657 GiB/s 12.659 GiB/s]
Throughput/Aes128Ctr64  thrpt:  [12.601 GiB/s 12.625 GiB/s 12.644 GiB/s]
Throughput/Aes128Ct128  thrpt:  [11.315 GiB/s 11.349 GiB/s 11.380 GiB/s]
Throughput/Aes256Ctr64  thrpt:  [8.4748 GiB/s 8.4896 GiB/s 8.5014 GiB/s]
Throughput/Aes256Ct128  thrpt:  [7.4943 GiB/s 7.5061 GiB/s 7.5158 GiB/s]
Throughput/ChaCha8      thrpt:  [1.3391 GiB/s 1.3402 GiB/s 1.3410 GiB/s]
Throughput/ChaCha12     thrpt:  [935.03 MiB/s 938.98 MiB/s 942.22 MiB/s]
Throughput/ChaCha20     thrpt:  [578.33 MiB/s 580.03 MiB/s 581.44 MiB/s]
Throughput/Lcg128Xsl64  thrpt:  [4.5148 GiB/s 4.5335 GiB/s 4.5529 GiB/s]
Throughput/Mcg128Xsl64  thrpt:  [5.9140 GiB/s 5.9424 GiB/s 5.9664 GiB/s]
```

For x86_64 Desktop: AMD Ryzen 9 5950X

```
Latency/TLS             time:   [1.0577 ns 1.0592 ns 1.0616 ns]
Latency/Aes128Ctr64     time:   [1.0680 ns 1.0695 ns 1.0712 ns]
Latency/Aes128Ctr128    time:   [1.1573 ns 1.1582 ns 1.1592 ns]
Latency/Aes256Ctr64     time:   [1.6956 ns 1.7074 ns 1.7252 ns]
Latency/Aes256Ctr128    time:   [1.7394 ns 1.7410 ns 1.7427 ns]
Latency/ChaCha8         time:   [1.4317 ns 1.4338 ns 1.4363 ns]
Latency/ChaCha12        time:   [1.9144 ns 1.9162 ns 1.9182 ns]
Latency/ChaCha20        time:   [2.9326 ns 2.9349 ns 2.9375 ns]
Latency/Lcg128Xsl64     time:   [1.1708 ns 1.1717 ns 1.1727 ns]
Latency/Mcg128Xsl64     time:   [863.11 ps 863.58 ps 864.11 ps]

Throughput/TLS          thrpt:  [14.118 GiB/s 14.130 GiB/s 14.141 GiB/s]
Throughput/Aes128Ctr64  thrpt:  [14.012 GiB/s 14.034 GiB/s 14.054 GiB/s]
Throughput/Aes128Ct128  thrpt:  [13.347 GiB/s 13.357 GiB/s 13.367 GiB/s]
Throughput/Aes256Ctr64  thrpt:  [8.8344 GiB/s 8.8416 GiB/s 8.8483 GiB/s]
Throughput/Aes256Ct128  thrpt:  [7.7617 GiB/s 7.7838 GiB/s 7.8044 GiB/s]
Throughput/ChaCha8      thrpt:  [6.6074 GiB/s 6.6142 GiB/s 6.6203 GiB/s]
Throughput/ChaCha12     thrpt:  [4.5944 GiB/s 4.5981 GiB/s 4.6015 GiB/s]
Throughput/ChaCha20     thrpt:  [2.8697 GiB/s 2.8727 GiB/s 2.8753 GiB/s]
Throughput/Lcg128Xsl64  thrpt:  [5.2476 GiB/s 5.3558 GiB/s 5.4613 GiB/s]
Throughput/Mcg128Xsl64  thrpt:  [7.6245 GiB/s 7.7582 GiB/s 7.8882 GiB/s]
```

For a aarch64 SBC: ARM Cortex-A73 (Odroid N2+):

```
Latency/TLS             time:   [7.0580 ns 7.0992 ns 7.1399 ns]
Latency/Aes128Ctr64     time:   [7.4022 ns 7.4125 ns 7.4233 ns]
Latency/Aes128Ctr128    time:   [6.3027 ns 6.3144 ns 6.3275 ns]
Latency/Aes256Ctr64     time:   [10.006 ns 10.007 ns 10.007 ns]
Latency/Aes256Ctr128    time:   [9.1727 ns 9.1730 ns 9.1735 ns]
Latency/ChaCha8         time:   [25.923 ns 25.928 ns 25.934 ns]
Latency/ChaCha12        time:   [36.375 ns 36.379 ns 36.384 ns]
Latency/ChaCha20        time:   [57.162 ns 57.168 ns 57.174 ns]
Latency/Lcg128Xsl64     time:   [6.2690 ns 6.2725 ns 6.2765 ns]
Latency/Mcg128Xsl64     time:   [6.2628 ns 6.2649 ns 6.2674 ns]

Throughput/TLS          thrpt:  [2.1681 GiB/s 2.1689 GiB/s 2.1697 GiB/s]
Throughput/Aes128Ctr64  thrpt:  [2.1290 GiB/s 2.1365 GiB/s 2.1440 GiB/s]
Throughput/Aes128Ct128  thrpt:  [2.3520 GiB/s 2.3621 GiB/s 2.3720 GiB/s]
Throughput/Aes256Ctr64  thrpt:  [1.5376 GiB/s 1.5402 GiB/s 1.5427 GiB/s]
Throughput/Aes256Ct128  thrpt:  [1.7468 GiB/s 1.7499 GiB/s 1.7530 GiB/s]
Throughput/ChaCha8      thrpt:  [315.66 MiB/s 315.77 MiB/s 315.88 MiB/s]
Throughput/ChaCha12     thrpt:  [220.51 MiB/s 220.58 MiB/s 220.65 MiB/s]
Throughput/ChaCha20     thrpt:  [137.55 MiB/s 137.59 MiB/s 137.64 MiB/s]
Throughput/Lcg128Xsl64  thrpt:  [1.1512 GiB/s 1.1512 GiB/s 1.1513 GiB/s]
Throughput/Mcg128Xsl64  thrpt:  [1.1766 GiB/s 1.1766 GiB/s 1.1767 GiB/s]
```

## Acknowledgement

The software based fixsliced implementations of AES-128 and AES-256 is a copy of the
[`aes` crate](https://crates.io/crates/aes) written by the RustCrypto team. Author of the original C implementation
is Alexandre Adomnicai.

We don't use the `AES` crate directly, simply because it doesn't inline very well, and we can provide also better inner
mutability this way (since we optimize the fast path, when hardware based AES is available at compile time).

## Licence

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
