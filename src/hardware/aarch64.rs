use core::{arch::aarch64::*, cell::Cell};

use crate::constants::{
    AES128_KEY_COUNT, AES128_KEY_SIZE, AES256_KEY_COUNT, AES256_KEY_SIZE, AES_BLOCK_WORDS,
    AES_RCON, AES_WORD_SIZE,
};

// Compile-time checks to verify that some casts are sound.
const _: () = assert!(size_of::<uint8x16_t>() == size_of::<u128>());
const _: () = assert!(align_of::<uint8x16_t>() == align_of::<u128>());
const _: () = assert!(align_of::<uint8x16_t>() >= align_of::<u32>());

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64 {
    counter: Cell<uint64x2_t>,
    round_keys: Cell<[uint8x16_t; AES128_KEY_COUNT]>,
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

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = vreinterpretq_u64_u8(vld1q_u8(counter.to_le_bytes().as_ptr().cast()));
        let round_keys: [uint8x16_t; AES128_KEY_COUNT] =
            aes_key_expansion::<AES128_KEY_SIZE, AES128_KEY_COUNT>(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = vreinterpretq_u64_u8(vld1q_u8(counter.to_le_bytes().as_ptr().cast()));

        let round_keys: [uint8x16_t; AES128_KEY_COUNT] =
            aes_key_expansion::<AES128_KEY_SIZE, AES128_KEY_COUNT>(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "neon", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        // Increment the lower 64 bits using SIMD.
        let increment = vsetq_lane_u64::<0>(1, vmovq_n_u64(0));
        let new_counter = vaddq_u64(counter, increment);
        self.counter.set(new_counter);

        // We apply the AES encryption on the counter.
        let mut state = vreinterpretq_u8_u64(counter);
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[0]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[1]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[2]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[3]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[4]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[5]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[6]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[7]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[8]));
        state = vaeseq_u8(state, round_keys[9]);
        state = veorq_u8(state, round_keys[10]);

        // Return the encrypted counter as u128.
        *(&state as *const uint8x16_t as *const u128)
    }
}

/// A random number generator based on the AES-128 block cipher thar runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[uint8x16_t; AES128_KEY_COUNT]>,
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

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [uint8x16_t; AES128_KEY_COUNT] =
            aes_key_expansion::<AES128_KEY_SIZE, AES128_KEY_COUNT>(key);
        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [uint8x16_t; AES128_KEY_COUNT] =
            aes_key_expansion::<AES128_KEY_SIZE, AES128_KEY_COUNT>(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "neon", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        let round_keys = self.round_keys.get();

        // We apply the AES encryption on the whitened counter.
        let mut state = vld1q_u8(counter.to_le_bytes().as_ptr().cast());
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[0]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[1]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[2]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[3]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[4]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[5]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[6]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[7]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[8]));
        state = vaeseq_u8(state, round_keys[9]);
        state = veorq_u8(state, round_keys[10]);

        // Return the encrypted counter as u128.
        *(&state as *const uint8x16_t as *const u128)
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64 {
    counter: Cell<uint64x2_t>,
    round_keys: Cell<[uint8x16_t; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr64 {
    fn drop(&mut self) {
        self.counter.set(unsafe { core::mem::zeroed() });
        self.round_keys.set(unsafe { core::mem::zeroed() });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr64 {
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = vreinterpretq_u64_u8(vld1q_u8(counter.to_le_bytes().as_ptr().cast()));
        let round_keys: [uint8x16_t; AES256_KEY_COUNT] =
            aes_key_expansion::<AES256_KEY_SIZE, AES256_KEY_COUNT>(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        let counter =
            ((u64::from_le_bytes(nonce) as u128) << 64) + u64::from_le_bytes(counter) as u128;
        let counter = vreinterpretq_u64_u8(vld1q_u8(counter.to_le_bytes().as_ptr().cast()));
        let round_keys: [uint8x16_t; AES256_KEY_COUNT] =
            aes_key_expansion::<AES256_KEY_SIZE, AES256_KEY_COUNT>(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "neon", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        let round_keys = self.round_keys.get();

        // Increment the lower 64 bits using SIMD.
        let increment = vcombine_u64(vdup_n_u64(1), vdup_n_u64(0));
        let new_counter = vaddq_u64(counter, increment);
        self.counter.set(new_counter);

        // We apply the AES encryption on the counter.
        let mut state = vreinterpretq_u8_u64(counter);
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[0]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[1]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[2]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[3]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[4]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[5]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[6]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[7]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[8]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[9]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[10]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[11]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[12]));
        state = vaeseq_u8(state, round_keys[13]);
        state = veorq_u8(state, round_keys[14]);

        // Return the encrypted counter as u128.
        *(&state as *const uint8x16_t as *const u128)
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[uint8x16_t; AES256_KEY_COUNT]>,
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

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [uint8x16_t; AES256_KEY_COUNT] =
            aes_key_expansion::<AES256_KEY_SIZE, AES256_KEY_COUNT>(key);
        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        let counter = u128::from_le_bytes(counter);
        let round_keys: [uint8x16_t; AES256_KEY_COUNT] =
            aes_key_expansion::<AES256_KEY_SIZE, AES256_KEY_COUNT>(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(all(target_feature = "neon", target_feature = "aes"), inline(always))]
    #[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
    #[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        let round_keys = self.round_keys.get();

        // We apply the AES encryption on the counter.
        let mut state = vld1q_u8(counter.to_le_bytes().as_ptr().cast());
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[0]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[1]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[2]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[3]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[4]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[5]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[6]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[7]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[8]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[9]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[10]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[11]));
        state = vaesmcq_u8(vaeseq_u8(state, round_keys[12]));
        state = vaeseq_u8(state, round_keys[13]);
        state = veorq_u8(state, round_keys[14]);

        // Return the encrypted counter as u128.
        *(&state as *const uint8x16_t as *const u128)
    }
}

#[cfg_attr(not(target_feature = "aes"), target_feature(enable = "aes"))]
#[cfg_attr(not(target_feature = "neon"), target_feature(enable = "neon"))]
pub unsafe fn aes_key_expansion<const L: usize, const N: usize>(key: [u8; L]) -> [uint8x16_t; N] {
    let mut expanded_keys: [uint8x16_t; N] = core::mem::zeroed();

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let keys_in_words = core::slice::from_raw_parts_mut(keys_ptr, N * AES_BLOCK_WORDS);

    for (i, chunk) in key.chunks_exact(AES_WORD_SIZE).enumerate() {
        keys_in_words[i] =
            u32::from_ne_bytes(chunk.try_into().expect("Invalid chunk size for u32"));
    }

    unsafe fn sub_word(input: u32) -> u32 {
        let input = vreinterpretq_u8_u32(vdupq_n_u32(input));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(vaeseq_u8(input, vdupq_n_u8(0))))
    }

    let nk = L / AES_WORD_SIZE;
    for i in nk..(N * AES_BLOCK_WORDS) {
        let mut word = keys_in_words[i - 1];

        if i % nk == 0 {
            word = sub_word(word).rotate_right(8) ^ AES_RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            word = sub_word(word);
        }

        keys_in_words[i] = keys_in_words[i - nk] ^ word;
    }

    expanded_keys
}

#[cfg(all(test, not(feature = "force_fallback")))]
mod tests {
    use super::*;
    use crate::constants::{AES128_KEY_COUNT, AES128_KEY_SIZE, AES_BLOCK_SIZE};
    use crate::hardware::tests::{aes128_key_expansion_test, aes256_key_expansion_test};

    #[test]
    fn test_aes128_key_expansion() {
        aes128_key_expansion_test(|key| {
            let expanded = unsafe { aes_key_expansion::<AES128_KEY_SIZE, AES128_KEY_COUNT>(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [uint8x16_t; AES128_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }

    #[test]
    fn test_aes256_key_expansion() {
        aes256_key_expansion_test(|key| {
            let expanded = unsafe { aes_key_expansion::<AES256_KEY_SIZE, AES256_KEY_COUNT>(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [uint8x16_t; AES256_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }
}
