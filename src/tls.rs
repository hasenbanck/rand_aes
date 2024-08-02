use core::ops::RangeBounds;

use crate::Random;

#[cfg(not(feature = "force_fallback"))]
thread_local! {
    pub(super) static RNG: crate::Aes128Ctr64 = const { crate::Aes128Ctr64::zeroed() };
}

#[cfg(feature = "force_fallback")]
thread_local! {
    pub(super) static RNG: core::cell::LazyCell<crate::Aes128Ctr64> = core::cell::LazyCell::new(crate::Aes128Ctr64::zeroed);
}

/// Seeds the thread local instance using the OS entropy source.
///
/// The TLS uses the [`crate::Aes128Ctr64`] PRN internally.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_seed_tls_from_entropy() {
    RNG.with(|rng| rng.seed_from_entropy())
}

/// Generates a random `u8` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_u8() -> u8 {
    RNG.with(|rng| rng.u8())
}

/// Generates a random `u16` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_u16() -> u16 {
    RNG.with(|rng| rng.u16())
}

/// Generates a random `u32` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_u32() -> u32 {
    RNG.with(|rng| rng.u32())
}

/// Generates a random `u64` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_u64() -> u64 {
    RNG.with(|rng| rng.u64())
}

/// Generates a random `usize` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_usize() -> usize {
    RNG.with(|rng| rng.usize())
}

/// Generates a random `i8` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_i8() -> i8 {
    RNG.with(|rng| rng.i8())
}

/// Generates a random `i16` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_i16() -> i16 {
    RNG.with(|rng| rng.i16())
}

/// Generates a random `i32` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_i32() -> i32 {
    RNG.with(|rng| rng.i32())
}

/// Generates a random `i64` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_i64() -> i64 {
    RNG.with(|rng| rng.i64())
}

/// Generates a random `isize` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_isize() -> isize {
    RNG.with(|rng| rng.isize())
}

/// Generates a random `f32` value in the range of 0..1.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_f32() -> f32 {
    RNG.with(|rng| rng.f32())
}

/// Generates a random `f64` value in the range  of 0..1.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_f64() -> f64 {
    RNG.with(|rng| rng.f64())
}

/// Generates a random `bool` value.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_bool() -> bool {
    RNG.with(|rng| rng.bool())
}

/// Randomly shuffles a slice.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_shuffle<T>(slice: &mut [T]) {
    RNG.with(|rng| rng.shuffle(slice))
}

/// Fills a mutable `[u8]` slice with random bytes.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_fill_bytes(slice: &mut [u8]) {
    RNG.with(|rng| rng.fill_bytes(slice))
}

/// Generates a random `u8` value in the range of 0..n.
///
/// # Notice
/// This has a very slight bias. Use [`crate::range_u8()`] instead for no bias.
///
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_mod_u8(n: u8) -> u8 {
    RNG.with(|rng| rng.mod_u8(n))
}

/// Generates a random `u16` value in the range of 0..n.
///
/// # Notice
/// This has a very slight bias. Use [`crate::rand_range_u16()`] instead for no bias.
///
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_mod_u16(n: u16) -> u16 {
    RNG.with(|rng| rng.mod_u16(n))
}

/// Generates a random `u32` value in the range of 0..n.
///
/// # Notice
/// This has a very slight bias. Use [`crate::rand_range_u32()`] instead for no bias.
///
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_mod_u32(n: u32) -> u32 {
    RNG.with(|rng| rng.mod_u32(n))
}

/// Generates a random `u64` value in the range of 0..n.
///
/// # Notice
/// This has a very slight bias. Use [`crate::rand_range_u64()`] instead for no bias.
///
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_mod_u64(n: u64) -> u64 {
    RNG.with(|rng| rng.mod_u64(n))
}

/// Generates a random `usize` value in the range of 0..n.
///
/// # Notice
/// This has a very slight bias. Use [`crate::rand_range_usize()`] instead for no bias.
///
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_mod_usize(n: usize) -> usize {
    RNG.with(|rng| rng.mod_usize(n))
}

/// Generates a random `u8` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_u8<T: RangeBounds<u8>>(range: T) -> u8 {
    RNG.with(|rng| rng.range_u8(range))
}

/// Generates a random `u16` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_u16<T: RangeBounds<u16>>(range: T) -> u16 {
    RNG.with(|rng| rng.range_u16(range))
}

/// Generates a random `u32` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_u32<T: RangeBounds<u32>>(range: T) -> u32 {
    RNG.with(|rng| rng.range_u32(range))
}

/// Generates a random `u64` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_u64<T: RangeBounds<u64>>(range: T) -> u64 {
    RNG.with(|rng| rng.range_u64(range))
}

/// Generates a random `usize` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_usize<T: RangeBounds<usize>>(range: T) -> usize {
    RNG.with(|rng| rng.range_usize(range))
}

/// Generates a random `i8` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_i8<T: RangeBounds<i8>>(range: T) -> i8 {
    RNG.with(|rng| rng.range_i8(range))
}

/// Generates a random `i16` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_i16<T: RangeBounds<i16>>(range: T) -> i16 {
    RNG.with(|rng| rng.range_i16(range))
}

/// Generates a random `i32` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_i32<T: RangeBounds<i32>>(range: T) -> i32 {
    RNG.with(|rng| rng.range_i32(range))
}

/// Generates a random `i64` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_i64<T: RangeBounds<i64>>(range: T) -> i64 {
    RNG.with(|rng| rng.range_i64(range))
}

/// Generates a random `isize` value in the given range.
///
/// # Notice
/// The caller must call [`crate::rand_seed_tls_from_entropy()`] for each thread from this function is called
/// before calling this function to properly seed the TLS instance.
#[cfg_attr(doc_cfg, doc(cfg(feature = "tls")))]
pub fn rand_range_isize<T: RangeBounds<isize>>(range: T) -> isize {
    RNG.with(|rng| rng.range_isize(range))
}
