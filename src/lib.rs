//! # AES based pseudo-random number generator
//!
//! This crate implements a pseudo-random number generator (PRNG) using the AES block cipher in
//! Counter (CTR) mode. It provides four variants:
//!
//!  1. [`Aes128Ctr64`]: Utilizes AES-128 encryption with a 64-bit counter.
//!  2. [`Aes128Ctr128`]: Utilizes AES-128 encryption with a 128-bit counter.
//!  3. [`Aes256Ctr64`]: Utilizes AES-256 encryption with a 64-bit counter.
//!  4. [`Aes256Ctr128`]: Utilizes AES-256 encryption with a 128-bit counter.
//!
//! ## Features
//!
//! - Based on well-established cryptographic principles.
//! - Passes rigorous statistic tests (practrand and TESTu01 Big Crush).
//! - Provides the [`Random`] and [`Jump`] traits for common functionality.
//! - Uses the default secure RNG of the OS for initialization.
//! - Optional support for rand_core.
//! - Support for no_std.
//!
//! ## Counter implementation details
//!
//! * Uses either a 64-bit counter or 128-bit counter, randomly seeded at initialization.
//!            In case of the 64-bit counter we use a 128-bit variable and will seed the whole
//!            variable at initialization. The higher 64-bit acts as a nonce in this case.
//! * The counter wraps on overflow, ensuring continuous operation.
//!
//! ## Security Note
//!
//! While based on cryptographic sound primitives, this PRNG is not intended for cryptographic key
//! generation or other sensitive cryptographic operations. We tested its statistical qualities by
//! running versions with reduced rounds against `practrand` and `TESTu01` Big Crush. A version with
//! just 3 rounds of AES encryption rounds passes the `practrand` tests with at least 16 TB.
//! `TESTu01` Big Crush requires at least 5 rounds to be successfully cleared.
//! AES-128 uses 10 rounds, whereas AES-256 uses 14 rounds.
//!
//! ## Supported Architectures
//!
//! - x86_64
//! - aarch64 (ARM64)
//! - riscv64
//!
//! riscv64 needs nightly Rust, since the AES intrinsics are not marked as stable yet.
//!
//! ## Optimal performance
//!
//! We provide runtime detection for the hardware accelerated AES instruction set for all supported
//! platforms. Should the executing CPU not support hardware accelerated AES, a software fallback
//! is provided. But we highly recommend to enable the specific target feature on compile time,
//! since the AES instruction sets is available on modern desktop CPU for at least 10 years.
//! Enabling the target feature enables the compiler to more aggressively inline and provides
//! much better performance. The runtime detection is not supported in `no_std`. Not enabling
//! compile time target features will always result in the software AES fallback backend.
//!
//! Use the following target features:
//!
//! - Enable the "aes" target feature when compiling for x86_64 or aarch64.
//! - Enable the "zkne" target feature when compiling for riscv64.
//!
//! Example in `.cargo/config.toml`:
//!
//! ```toml
//! [target.'cfg(target_arch="aarch64")']
//! rustflags = ["-C", "target-feature=+aes"]
//!
//! [target.'cfg(target_arch="riscv64")']
//! rustflags = ["-C", "target-feature=+zkne"]
//!
//! [target.'cfg(target_arch="x86_64")']
//! rustflags = ["-C", "target-feature=+aes"]
//! ```
//!
//! ## Parallel Stream Generation
//!
//! The 128-bit counter RNG support efficient parallel stream generation through the [`Jump`] trait.
//! The provided functions allow you to create multiple independent streams of random numbers, which
//! is particularly useful for parallel or distributed computations.
//!
//! ### Jump Function
//!
//! The [`Jump::jump()`] function advances the RNG state by 2^64 steps. This is equivalent to
//! generating 2^64 random numbers. It can be used to create up to 2^64 non-overlapping
//! subsequences.
//!
//! ```ignore
//! use rand_aes::*;
//!
//! let mut rng1 = Aes256Ctr128::from_entropy();
//! let mut rng2 = rng1.clone();
//!
//! rng2.jump(); // Advance rng2 by 2^64 steps
//!
//! // Now rng1 and rng2 will generate different, non-overlapping sequences
//! ```
//!
//! ### Long Jump Function
//!
//! The [`Jump::long_jump()`] function advances the RNG state by 2^96 steps. This allows for even
//! larger separations between subsequences, useful for creating up to 2^32 independent streams.
//!
//! ```ignore
//! use rand_aes::*;
//!
//! let mut rng1 = Aes128Ctr128::from_entropy();
//! let mut rng2 = rng1.clone();
//!
//! rng2.long_jump(); // Advance rng2 by 2^96 steps
//!
//! // rng1 and rng2 now have an extremely large separation in their sequences
//! ```
//!
//! These functions are particularly useful in scenarios requiring multiple independent RNG streams,
//! such as parallel Monte Carlo simulations or distributed computing tasks.
//!
//! ## General usage examples
//!
//! ```ignore
//! use rand_aes::*;
//!
//! let rng = Aes128Ctr128::from_entropy();
//!
//! // Generate random integers
//! let random_u8 = rng.u8();
//! let random_u32 = rng.u32();
//!
//! // Generate random numbers within a range
//! let random_in_range = rng.range_u32(10..100);
//!
//! // Generate random boolean
//! let random_bool = rng.bool();
//!
//! // Shuffle a slice
//! let mut values = [1, 2, 3, 4, 5];
//! rng.shuffle(&mut values);
//!
//! // You should seed the thread local RNG before using it
//! rand_seed_tls();
//!
//! // Now you can use the thread local RNG
//! let random_isize = rand_isize();
//! let random_u64 = rand_mod_u64(2423);
//! ```

// TODO write acknowledgement and reason why a new crate was needed
// TODO improve benchmarks
// TODO consider 32-bit versions?

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(target_arch = "riscv64", feature(riscv_ext_intrinsics))]
extern crate core;

pub mod seeds;
#[cfg(feature = "tls")]
mod tls;
mod traits;

#[cfg(any(feature = "force_fallback", feature = "verification"))]
pub(crate) mod fallback;

#[cfg(feature = "force_fallback")]
pub use fallback::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(not(feature = "force_fallback"))]
pub use hardware::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(any(
    not(all(feature = "force_fallback", feature = "force_no_runtime_detection")),
    feature = "verification"
))]
mod hardware;

#[cfg(feature = "verification")]
#[doc(hidden)]
pub mod verification;

#[cfg(feature = "tls")]
pub use tls::*;

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

macro_rules! safely_call {
    ($what:expr) => {
        #[cfg(not(feature = "force_fallback"))]
        unsafe {
            $what
        }

        #[cfg(feature = "force_fallback")]
        $what
    };
}

#[cfg(feature = "getrandom")]
pub(crate) fn secure_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("Can't get random bytes from OS");
    bytes
}

impl core::fmt::Debug for Aes128Ctr64 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes128Ctr64").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes128Ctr128 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes128Ctr128").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes256Ctr64 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes256Ctr64").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes256Ctr128 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes256Ctr128").finish_non_exhaustive()
    }
}

impl Random for Aes128Ctr64 {
    type Seed = seeds::Aes128Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[16..24]);
        counter_bytes.copy_from_slice(&seed.as_ref()[24..32]);

        safely_call! { Aes128Ctr64::from_seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[16..24]);
        counter_bytes.copy_from_slice(&seed.as_ref()[24..32]);

        safely_call! { self.seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 32] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes128Ctr64::next_impl(self) }
    }
}

impl Random for Aes128Ctr128 {
    type Seed = seeds::Aes128Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 16];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        counter_bytes.copy_from_slice(&seed.as_ref()[16..32]);

        safely_call! { Aes128Ctr128::from_seed_impl(seed_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 16];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        counter_bytes.copy_from_slice(&seed.as_ref()[16..32]);

        safely_call! { self.seed_impl(seed_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 32] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes128Ctr128::next_impl(self) }
    }
}

impl Random for Aes256Ctr64 {
    type Seed = seeds::Aes256Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[32..40]);
        counter_bytes.copy_from_slice(&seed.as_ref()[40..48]);

        safely_call! { Aes256Ctr64::from_seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[32..40]);
        counter_bytes.copy_from_slice(&seed.as_ref()[40..48]);

        safely_call! { self.seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 48] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes256Ctr64::next_impl(self) }
    }
}

impl Random for Aes256Ctr128 {
    type Seed = seeds::Aes256Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 32];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        counter_bytes.copy_from_slice(&seed.as_ref()[32..48]);

        safely_call! { Aes256Ctr128::from_seed_impl(seed_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 32];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        counter_bytes.copy_from_slice(&seed.as_ref()[32..48]);

        safely_call! { self.seed_impl(seed_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 48] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes256Ctr128::next_impl(self) }
    }
}

impl Jump for Aes128Ctr128 {
    fn jump(&self) -> Self {
        self.jump_impl()
    }

    fn long_jump(&self) -> Self {
        self.long_jump_impl()
    }
}

impl Jump for Aes256Ctr128 {
    fn jump(&self) -> Self {
        self.jump_impl()
    }

    fn long_jump(&self) -> Self {
        self.long_jump_impl()
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes128Ctr64 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes128Ctr128 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes256Ctr64 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes256Ctr128 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes128Ctr64 {
    type Seed = seeds::Aes128Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes128Ctr128 {
    type Seed = seeds::Aes128Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes256Ctr64 {
    type Seed = seeds::Aes256Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes256Ctr128 {
    type Seed = seeds::Aes256Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}
