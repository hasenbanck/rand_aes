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
- `getrandom`: Implements the traits provided by the [`rand_core`](https://crates.io/crates/rand_core) crate.
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
    let random_u64 = prng::u64;
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
- riscv64: Must support the scalar based cryptography extension (zk).
- x86_64: Support since Intel's Westmere (2010) and AMD's Bulldozer (2011).

riscv64 needs nightly Rust, since the AES intrinsics are not marked as stable yet.

## Optimal performance

We provide runtime detection for the hardware accelerated AES instruction set for all supported
platforms. Should the executing CPU not support hardware accelerated AES, a software fallback
is provided. But we highly recommend to enable the specific target feature on compile time,
since the AES instruction sets is available on modern desktop CPU for at least 10 years.
Enabling the target feature enables the compiler to more aggressively inline and provides
much better performance. The runtime detection is not supported in `no_std`.

Use the following target features for optimal performance:

- aarch64: "aes" (using the cryptographic extension)
- riscv64: "zkne" (using the scalar based cryptography extension)
- x86_64: "aes" (using AES-NI)

Example in `.cargo/config.toml`:

```toml
[target.'cfg(target_arch="aarch64")']
rustflags = ["-C", "target-feature=+aes"]

[target.'cfg(target_arch="riscv64")']
rustflags = ["-C", "target-feature=+zkne"]

[target.'cfg(target_arch="x86_64")']
rustflags = ["-C", "target-feature=+aes"]
```

## Acknowledgement

The software based fixsliced implementations of AES-128 and AES-256 (64-bit) is a copy of the
[`aes` crate](https://crates.io/crates/aes) written by the RustCrypto team. Author of the original C implementation
is Alexandre Adomnicai.

We don't use the `AES` crate directly, simply because it doesn't inline very well, and we can provide also better inner
mutability this way (since we optimize the fast path, when hardware based AES is available at compile time).

## Licence

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
