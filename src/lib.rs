//! # AES based pseudo-random number generator
//!
//! This crate implements a pseudo-random number generator (PRNG) using the AES block cipher in
//! counter (CTR) mode. It provides four variants:
//!
//!  1. [`Aes128Ctr64`]: Utilizes AES-128 encryption with a 64-bit counter.
//!  2. [`Aes128Ctr128`]: Utilizes AES-128 encryption with a 128-bit counter.
//!  3. [`Aes256Ctr64`]: Utilizes AES-256 encryption with a 64-bit counter.
//!  4. [`Aes256Ctr128`]: Utilizes AES-256 encryption with a 128-bit counter.
//!
//! Common functionality is provided using the [`Random`] trait or the optionally provided
//! [`rand_core::RngCore`] and [`rand_core::SeedableRng`] traits.
//!
//! ## Optimal Performance
//!
//! We provide runtime detection for the hardware accelerated AES instruction set for all supported
//! platforms. Should the executing CPU not support hardware accelerated AES, a software fallback
//! is provided. But we highly recommend to enable the specific target feature on compile time,
//! since the AES instruction sets is available on modern desktop CPU for at least 10 years.
//! Enabling the target feature enables the compiler to more aggressively inline and provides
//! much better performance. The runtime detection is not supported in `no_std`.
//!
//! Use the following target features for optimal performance:
//!
//! - aarch64: `aes` (using the cryptographic extension)
//! - riscv64: `zkne` (using the scalar based cryptography extension)
//! - x86_64: `aes` (using AES-NI)
//!
//! ## Security Note
//!
//! While based on well-established cryptographic primitives, this PRNG is not intended for cryptographic key generation
//! or other sensitive cryptographic operations, simply because safe, automatic re-seeding is not provided. We tested its
//! statistical qualities by running versions with reduced rounds against `practrand` and `TESTu01`'s Big Crush.
//! A version with just 3 rounds of AES encryption rounds passes the `practrand` tests with at least 16 TB.
//! `TESTu01`'s Big Crush requires at least 5 rounds to be successfully cleared. AES-128 uses 10 rounds, whereas
//! AES-256 uses 14 rounds.
//!
//! ## Parallel Stream Generation
//!
//! The 128-bit counter PRNG support efficient parallel stream generation through the [`Jump`] trait.
//! The provided functions allow you to create multiple independent streams of random numbers, which
//! is particularly useful for parallel or distributed computations. The API is designed to easily
//! create new random number generators for child threads / tasks from a base instance.
//!
//! ### Jump Function
//!
//! The [`Jump::jump()`] function advances the PRNG counter by 2^64 steps. It can be used to create
//! up to 2^64 non-overlapping subsequences.
//!
//! ### Long Jump Function
//!
//! The [`Jump::long_jump()`] function advances the PRNG counter by 2^96 steps. This allows for even
//! larger separations between subsequences, useful for creating up to 2^32 independent streams.
//!
//! These functions are particularly useful in scenarios requiring multiple independent PRNG streams,
//! such as parallel Monte Carlo simulations or distributed computing tasks.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "verification", allow(unused))]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(target_arch = "riscv64", feature(riscv_ext_intrinsics))]

pub mod seeds;
#[cfg(all(feature = "tls", not(feature = "verification")))]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub mod tls;
mod traits;

#[cfg(any(feature = "force_fallback", feature = "verification"))]
pub(crate) mod fallback;

#[cfg(all(feature = "force_fallback", not(feature = "verification")))]
pub use fallback::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(not(feature = "force_fallback"), not(feature = "verification")))]
pub use hardware::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(any(
    not(all(feature = "force_fallback", feature = "force_no_runtime_detection")),
    feature = "verification"
))]
mod hardware;

#[cfg(not(feature = "verification"))]
mod implementation;

#[cfg(feature = "verification")]
#[doc(hidden)]
pub mod verification;

pub use traits::{Jump, Random};

#[allow(unused)]
pub(crate) mod constants {
    pub(crate) const AES_RCON: [u32; 10] =
        [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    pub(crate) const AES_BLOCK_WORDS: usize = 4;
    pub(crate) const AES_WORD_SIZE: usize = 4;
    pub(crate) const AES_BLOCK_SIZE: usize = AES_WORD_SIZE * AES_BLOCK_WORDS;
    pub(crate) const AES128_KEY_SIZE: usize = 16;
    pub(crate) const AES256_KEY_SIZE: usize = 32;
    pub(crate) const AES128_KEY_COUNT: usize = 11;
    pub(crate) const AES256_KEY_COUNT: usize = 15;
}

#[cfg(feature = "getrandom")]
pub(crate) fn secure_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("Can't get random bytes from OS");
    bytes
}
