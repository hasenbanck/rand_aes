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
//! - x86: `sse2` and `aes` (using AES-NI)
//! - x86_64: `aes` (using AES-NI)
//!
//! There is experimental support for the RISC-V vector crypto extension. Please read the README.md
//! for more information how to use it.
//!
//! ## Security Note
//!
//! While based on well-established cryptographic primitives, this PRNG is not intended for
//! cryptographic key generation or other sensitive cryptographic operations, simply because safe,
//! automatic re-seeding is not provided. We tested its statistical qualities by running versions
//! with reduced rounds against `practrand` and `TESTu01`'s Big Crush. A version with just 3 rounds
//! of AES encryption rounds passes the `practrand` tests with at least 16 TB. `TESTu01`'s Big Crush
//! requires at least 5 rounds to be successfully cleared. AES-128 uses 10 rounds, whereas
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

pub mod seeds;

#[cfg(all(feature = "tls", not(feature = "verification")))]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub mod tls;

mod traits;

mod backend;

#[cfg(all(
    feature = "std",
    not(target_arch = "riscv64"),
    any(
        not(any(
            all(
                any(target_arch = "x86_64", target_arch = "x86"),
                target_feature = "sse2",
                target_feature = "aes",
            ),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "aes",
            ),
        )),
        feature = "force_runtime_detection",
    ),
))]
pub(crate) mod runtime;

#[cfg(all(
    feature = "std",
    not(target_arch = "riscv64"),
    any(
        not(any(
            all(
                any(target_arch = "x86_64", target_arch = "x86"),
                target_feature = "sse2",
                target_feature = "aes",
            ),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "aes",
            ),
        )),
        feature = "force_runtime_detection",
    ),
))]
pub use runtime::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_feature = "aes",
    not(feature = "force_runtime_detection"),
    not(feature = "force_software"),
    not(feature = "verification"),
))]
pub use backend::aarch64::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    target_arch = "riscv64",
    feature = "experimental_riscv",
    not(feature = "force_runtime_detection"),
    not(feature = "force_software"),
    not(feature = "verification"),
))]
pub use backend::riscv64::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    target_feature = "sse2",
    target_feature = "aes",
    not(feature = "force_runtime_detection"),
    not(feature = "force_software"),
    not(feature = "verification"),
))]
pub use backend::x86::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    any(
        not(any(
            target_arch = "aarch64",
            all(target_arch = "riscv64", feature = "experimental_riscv"),
            any(target_arch = "x86_64", target_arch = "x86"),
        )),
        feature = "force_software",
    ),
    not(feature = "force_runtime_detection"),
    not(feature = "verification"),
))]
pub use backend::soft::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

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

#[cfg(all(test, not(feature = "verification")))]
#[allow(unused)]
mod tests {
    use super::*;
    use crate::constants::{
        AES128_KEY_COUNT, AES128_KEY_SIZE, AES256_KEY_COUNT, AES256_KEY_SIZE, AES_BLOCK_SIZE,
    };
    use hex_literal::hex;

    // From NIST FIPS 197
    const TV_AES128_KEY: [u8; AES128_KEY_SIZE] = hex!("000102030405060708090a0b0c0d0e0f");
    const TV_AES128_IV: [u8; AES_BLOCK_SIZE] = hex!("00112233445566778899aabbccddeeff");
    const TV_AES128_ROUND_KEYS: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = [
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("d6aa74fdd2af72fadaa678f1d6ab76fe"),
        hex!("b692cf0b643dbdf1be9bc5006830b3fe"),
        hex!("b6ff744ed2c2c9bf6c590cbf0469bf41"),
        hex!("47f7f7bc95353e03f96c32bcfd058dfd"),
        hex!("3caaa3e8a99f9deb50f3af57adf622aa"),
        hex!("5e390f7df7a69296a7553dc10aa31f6b"),
        hex!("14f9701ae35fe28c440adf4d4ea9c026"),
        hex!("47438735a41c65b9e016baf4aebf7ad2"),
        hex!("549932d1f08557681093ed9cbe2c974e"),
        hex!("13111d7fe3944a17f307a78b4d2b30c5"),
    ];
    const TV_AES128_NEXT_0: [u8; AES_BLOCK_SIZE] = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
    const TV_AES128_NEXT_1: [u8; AES_BLOCK_SIZE] = hex!("a556156c72876577f67f95a9d9e640a7");

    // From NIST FIPS 197
    const TV_AES256_KEY: [u8; AES256_KEY_SIZE] =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const TV_AES256_IV: [u8; AES_BLOCK_SIZE] = hex!("00112233445566778899aabbccddeeff");
    const TV_AES256_ROUND_KEYS: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = [
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("101112131415161718191a1b1c1d1e1f"),
        hex!("a573c29fa176c498a97fce93a572c09c"),
        hex!("1651a8cd0244beda1a5da4c10640bade"),
        hex!("ae87dff00ff11b68a68ed5fb03fc1567"),
        hex!("6de1f1486fa54f9275f8eb5373b8518d"),
        hex!("c656827fc9a799176f294cec6cd5598b"),
        hex!("3de23a75524775e727bf9eb45407cf39"),
        hex!("0bdc905fc27b0948ad5245a4c1871c2f"),
        hex!("45f5a66017b2d387300d4d33640a820a"),
        hex!("7ccff71cbeb4fe5413e6bbf0d261a7df"),
        hex!("f01afafee7a82979d7a5644ab3afe640"),
        hex!("2541fe719bf500258813bbd55a721c0a"),
        hex!("4e5a6699a9f24fe07e572baacdf8cdea"),
        hex!("24fc79ccbf0979e9371ac23c6d68de36"),
    ];
    const TV_AES256_NEXT_0: [u8; AES_BLOCK_SIZE] = hex!("8ea2b7ca516745bfeafc49904b496089");
    const TV_AES256_NEXT_1: [u8; AES_BLOCK_SIZE] = hex!("81ae7d5e4138bf730d2a8871fec2cd0c");

    pub(crate) fn aes128_key_expansion_test<F>(expansion: F)
    where
        F: FnOnce([u8; AES128_KEY_SIZE]) -> [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
    {
        let expanded = expansion(TV_AES128_KEY);

        for (exp, act) in TV_AES128_ROUND_KEYS.iter().zip(expanded.iter()) {
            assert_eq!(exp, act);
        }
    }

    pub(crate) fn aes256_key_expansion_test<F>(expansion: F)
    where
        F: FnOnce([u8; AES256_KEY_SIZE]) -> [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
    {
        let expanded = expansion(TV_AES256_KEY);

        for (exp, act) in TV_AES256_ROUND_KEYS.iter().zip(expanded.iter()) {
            assert_eq!(exp, act);
        }
    }

    #[test]
    fn test_aes128_64_ctr() {
        let mut ctr = [0u8; 8];
        let mut nonce = [0u8; 8];
        ctr.copy_from_slice(&TV_AES128_IV[0..8]);
        nonce.copy_from_slice(&TV_AES128_IV[8..16]);

        let prng = unsafe { Aes128Ctr64::from_seed_impl(TV_AES128_KEY, nonce, ctr) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_1);
    }

    #[test]
    fn test_aes128_128_ctr() {
        let prng = unsafe { Aes128Ctr128::from_seed_impl(TV_AES128_KEY, TV_AES128_IV) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_1);
    }

    #[test]
    fn test_aes256_64_ctr() {
        let mut ctr = [0u8; 8];
        let mut nonce = [0u8; 8];
        ctr.copy_from_slice(&TV_AES256_IV[0..8]);
        nonce.copy_from_slice(&TV_AES256_IV[8..16]);

        let prng = unsafe { Aes256Ctr64::from_seed_impl(TV_AES256_KEY, nonce, ctr) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_1);
    }

    #[test]
    fn test_aes256_128_ctr() {
        let prng = unsafe { Aes256Ctr128::from_seed_impl(TV_AES256_KEY, TV_AES256_IV) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_1);
    }
}
