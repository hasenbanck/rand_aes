use core::cell::Cell;

use core::arch::x86_64::*;

use crate::constants::{AES128_KEY_COUNT, AES128_KEY_SIZE, AES256_KEY_COUNT, AES256_KEY_SIZE};

// Compile-time checks to verify that some casts are sound.
const _: () = assert!(size_of::<__m128i>() == size_of::<u128>());
const _: () = assert!(align_of::<__m128i>() == align_of::<u128>());

/// A random number generator based on the AES-128 block cipher thar runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64 {
    counter: Cell<__m128i>,
    round_keys: Cell<[__m128i; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr64 {
    fn drop(&mut self) {
        self.counter.set(unsafe { core::mem::zeroed() });
        self.round_keys.set(unsafe { core::mem::zeroed() });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr64 {
    #[cfg(feature = "tls")]
    pub(crate) const fn zeroed() -> Self {
        Self {
            counter: Cell::new(unsafe { core::mem::zeroed() }),
            round_keys: Cell::new(unsafe { core::mem::zeroed() }),
        }
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = unsafe { _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast()) };
        let round_keys: [__m128i; AES128_KEY_COUNT] = aes128_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = unsafe { _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast()) };
        let round_keys: [__m128i; AES128_KEY_COUNT] = aes128_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "sse2", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        // Increment the lower 64 bits using SIMD.
        let increment = _mm_set_epi64x(0, 1);
        let new_counter = _mm_add_epi64(counter, increment);
        self.counter.set(new_counter);

        // Whitening the counter.
        let mut state = _mm_xor_si128(counter, round_keys[0]);

        // We apply the AES encryption on the whitened counter.
        state = _mm_aesenc_si128(state, round_keys[1]);
        state = _mm_aesenc_si128(state, round_keys[2]);
        state = _mm_aesenc_si128(state, round_keys[3]);
        state = _mm_aesenc_si128(state, round_keys[4]);
        state = _mm_aesenc_si128(state, round_keys[5]);
        state = _mm_aesenc_si128(state, round_keys[6]);
        state = _mm_aesenc_si128(state, round_keys[7]);
        state = _mm_aesenc_si128(state, round_keys[8]);
        state = _mm_aesenc_si128(state, round_keys[9]);
        state = _mm_aesenclast_si128(state, round_keys[10]);

        // Return the encrypted counter as u128.
        u128::from_le_bytes(*(&state as *const __m128i as *const _))
    }
}

/// A random number generator based on the AES-128 block cipher thar runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[__m128i; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        self.round_keys.set(unsafe { core::mem::zeroed() });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() << 64);
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() << 96);
        clone
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [__m128i; AES128_KEY_COUNT] = aes128_key_expansion(key);
        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [__m128i; AES128_KEY_COUNT] = aes128_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "sse2", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        self.counter.set(counter.wrapping_add(1));

        // Whitening the counter.
        let counter = _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast());
        let mut state = _mm_xor_si128(counter, round_keys[0]);

        // We apply the AES encryption on the whitened counter.
        state = _mm_aesenc_si128(state, round_keys[1]);
        state = _mm_aesenc_si128(state, round_keys[2]);
        state = _mm_aesenc_si128(state, round_keys[3]);
        state = _mm_aesenc_si128(state, round_keys[4]);
        state = _mm_aesenc_si128(state, round_keys[5]);
        state = _mm_aesenc_si128(state, round_keys[6]);
        state = _mm_aesenc_si128(state, round_keys[7]);
        state = _mm_aesenc_si128(state, round_keys[8]);
        state = _mm_aesenc_si128(state, round_keys[9]);
        state = _mm_aesenclast_si128(state, round_keys[10]);

        // Return the encrypted counter as u128.
        u128::from_le_bytes(*(&state as *const __m128i as *const _))
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64 {
    counter: Cell<__m128i>,
    round_keys: Cell<[__m128i; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr64 {
    fn drop(&mut self) {
        self.counter.set(unsafe { core::mem::zeroed() });
        self.round_keys.set(unsafe { core::mem::zeroed() });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr64 {
    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = unsafe { _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast()) };
        let round_keys: [__m128i; AES256_KEY_COUNT] = aes256_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = unsafe { _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast()) };
        let round_keys: [__m128i; AES256_KEY_COUNT] = aes256_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "sse2", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        // Increment the lower 64 bits using SIMD.
        let increment = _mm_set_epi64x(0, 1);
        let new_counter = _mm_add_epi64(counter, increment);
        self.counter.set(new_counter);

        // Whitening the counter.
        let mut state = _mm_xor_si128(counter, round_keys[0]);

        // We apply the AES encryption on the whitened counter.
        state = _mm_aesenc_si128(state, round_keys[1]);
        state = _mm_aesenc_si128(state, round_keys[2]);
        state = _mm_aesenc_si128(state, round_keys[3]);
        state = _mm_aesenc_si128(state, round_keys[4]);
        state = _mm_aesenc_si128(state, round_keys[5]);
        state = _mm_aesenc_si128(state, round_keys[6]);
        state = _mm_aesenc_si128(state, round_keys[7]);
        state = _mm_aesenc_si128(state, round_keys[8]);
        state = _mm_aesenc_si128(state, round_keys[9]);
        state = _mm_aesenc_si128(state, round_keys[10]);
        state = _mm_aesenc_si128(state, round_keys[11]);
        state = _mm_aesenc_si128(state, round_keys[12]);
        state = _mm_aesenc_si128(state, round_keys[13]);
        state = _mm_aesenclast_si128(state, round_keys[14]);

        // Return the encrypted counter as u128.
        u128::from_le_bytes(*(&state as *const __m128i as *const _))
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[__m128i; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        self.round_keys.set(unsafe { core::mem::zeroed() });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() << 64);
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() << 96);
        clone
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [__m128i; 15] = aes256_key_expansion(key);
        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [__m128i; 15] = aes256_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "sse2", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        self.counter.set(counter.wrapping_add(1));

        // Whitening the counter.
        let counter = _mm_loadu_si128(counter.to_le_bytes().as_ptr().cast());
        let mut state = _mm_xor_si128(counter, round_keys[0]);

        // We apply the AES encryption on the whitened counter.
        state = _mm_aesenc_si128(state, round_keys[1]);
        state = _mm_aesenc_si128(state, round_keys[2]);
        state = _mm_aesenc_si128(state, round_keys[3]);
        state = _mm_aesenc_si128(state, round_keys[4]);
        state = _mm_aesenc_si128(state, round_keys[5]);
        state = _mm_aesenc_si128(state, round_keys[6]);
        state = _mm_aesenc_si128(state, round_keys[7]);
        state = _mm_aesenc_si128(state, round_keys[8]);
        state = _mm_aesenc_si128(state, round_keys[9]);
        state = _mm_aesenc_si128(state, round_keys[10]);
        state = _mm_aesenc_si128(state, round_keys[11]);
        state = _mm_aesenc_si128(state, round_keys[12]);
        state = _mm_aesenc_si128(state, round_keys[13]);
        state = _mm_aesenclast_si128(state, round_keys[14]);

        // Return the encrypted counter as u128.
        u128::from_le_bytes(*(&state as *const __m128i as *const _))
    }
}

#[target_feature(enable = "aes")]
pub unsafe fn aes128_key_expansion(key: [u8; AES128_KEY_SIZE]) -> [__m128i; AES128_KEY_COUNT] {
    unsafe fn generate_round_key<const RCON: i32, const ROUND: usize>(
        expanded_keys: &mut [__m128i; AES128_KEY_COUNT],
    ) {
        let prev_key = expanded_keys[ROUND - 1];

        let mut temp = _mm_aeskeygenassist_si128::<RCON>(prev_key);
        temp = _mm_shuffle_epi32::<0xFF>(temp);

        let mut key = _mm_xor_si128(prev_key, _mm_slli_si128::<0x4>(prev_key));
        key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
        key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
        expanded_keys[ROUND] = _mm_xor_si128(key, temp);
    }
    let mut expanded_keys: [__m128i; AES128_KEY_COUNT] = core::mem::zeroed();

    expanded_keys[0] = _mm_loadu_si128(key.as_ptr().cast());

    generate_round_key::<0x01, 1>(&mut expanded_keys);
    generate_round_key::<0x02, 2>(&mut expanded_keys);
    generate_round_key::<0x04, 3>(&mut expanded_keys);
    generate_round_key::<0x08, 4>(&mut expanded_keys);
    generate_round_key::<0x10, 5>(&mut expanded_keys);
    generate_round_key::<0x20, 6>(&mut expanded_keys);
    generate_round_key::<0x40, 7>(&mut expanded_keys);
    generate_round_key::<0x80, 8>(&mut expanded_keys);
    generate_round_key::<0x1B, 9>(&mut expanded_keys);
    generate_round_key::<0x36, 10>(&mut expanded_keys);

    expanded_keys
}

#[cfg_attr(not(target_feature = "sse2"), target_feature(enable = "sse2"))]
#[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
pub unsafe fn aes256_key_expansion(key: [u8; AES256_KEY_SIZE]) -> [__m128i; AES256_KEY_COUNT] {
    unsafe fn generate_round_keys<const RCON: i32, const RNUM: usize>(
        expanded_keys: &mut [__m128i; AES256_KEY_COUNT],
    ) {
        let prev_key_0 = expanded_keys[RNUM * 2];
        let prev_key_1 = expanded_keys[(RNUM * 2) + 1];

        let mut temp = _mm_aeskeygenassist_si128::<RCON>(prev_key_1);
        temp = _mm_shuffle_epi32::<0xFF>(temp);

        let mut key = _mm_xor_si128(prev_key_0, _mm_slli_si128::<0x4>(prev_key_0));
        key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
        key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
        key = _mm_xor_si128(temp, key);

        expanded_keys[(RNUM * 2) + 2] = key;

        if RNUM < 6 {
            let mut temp = _mm_aeskeygenassist_si128::<0x00>(key);
            temp = _mm_shuffle_epi32::<0xAA>(temp);

            let mut key = _mm_xor_si128(prev_key_1, _mm_slli_si128::<4>(prev_key_1));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(key, _mm_slli_si128::<0x4>(key));
            key = _mm_xor_si128(temp, key);

            expanded_keys[(RNUM * 2) + 3] = key;
        }
    }
    let mut expanded_keys: [__m128i; AES256_KEY_COUNT] = core::mem::zeroed();

    // Load the initial key.
    expanded_keys[0] = _mm_loadu_si128(key.as_ptr().cast());
    expanded_keys[1] = _mm_loadu_si128(key[16..].as_ptr().cast());

    // The actual key expansion.
    generate_round_keys::<0x01, 0>(&mut expanded_keys);
    generate_round_keys::<0x02, 1>(&mut expanded_keys);
    generate_round_keys::<0x04, 2>(&mut expanded_keys);
    generate_round_keys::<0x08, 3>(&mut expanded_keys);
    generate_round_keys::<0x10, 4>(&mut expanded_keys);
    generate_round_keys::<0x20, 5>(&mut expanded_keys);
    generate_round_keys::<0x40, 6>(&mut expanded_keys);

    expanded_keys
}

#[cfg(all(test, not(feature = "force_fallback")))]
mod tests {
    use super::*;
    use crate::constants::AES_BLOCK_SIZE;
    use crate::hardware::tests::{aes128_key_expansion_test, aes256_key_expansion_test};

    #[test]
    fn test_aes128_key_expansion() {
        aes128_key_expansion_test(|key| {
            let expanded = unsafe { aes128_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [__m128i; AES128_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }

    #[test]
    fn test_aes256_key_expansion() {
        aes256_key_expansion_test(|key| {
            let expanded = unsafe { aes256_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [__m128i; AES256_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }
}
