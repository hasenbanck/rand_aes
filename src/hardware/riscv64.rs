use core::{arch::riscv64::*, cell::Cell};

use crate::constants::{AES128_KEY_COUNT, AES256_KEY_COUNT};

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64 {
    counter: Cell<[u64; 2]>,
    round_keys: Cell<[[u64; 2]; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr64 {
    fn drop(&mut self) {
        self.counter.set([0, 0]);
        self.round_keys.set([[0; 2]; AES128_KEY_COUNT]);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr64 {
    #[cfg(feature = "tls")]
    pub(crate) const fn zeroed() -> Self {
        Self {
            counter: Cell::new([0; 2]),
            round_keys: Cell::new([[0; 2]; AES128_KEY_COUNT]),
        }
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let mut key_lo = [0u8; 8];
        let mut key_hi = [0u8; 8];

        key_lo.copy_from_slice(&key[0..8]);
        key_hi.copy_from_slice(&key[8..16]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [u64::from_le_bytes(key_lo), u64::from_le_bytes(key_hi)];

        let round_keys = aes128_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        let mut key_lo = [0u8; 8];
        let mut key_hi = [0u8; 8];

        key_lo.copy_from_slice(&key[0..8]);
        key_hi.copy_from_slice(&key[8..16]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [u64::from_le_bytes(key_lo), u64::from_le_bytes(key_hi)];

        let round_keys = aes128_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.counter.get()[0]
    }

    #[cfg_attr(target_feature = "zkne", inline(always))]
    #[cfg_attr(not(target_feature = "zkne"), target_feature(enable = "zkne"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the lower 64 bits.
        let counter = self.counter.get();
        let mut new_counter = counter;
        new_counter[0] = counter[0].wrapping_add(1);
        self.counter.set(new_counter);

        let round_keys = self.round_keys.get();

        // We apply the AES encryption on the counter.
        let mut state = [counter[0] ^ round_keys[0][0], counter[1] ^ round_keys[0][1]];

        let mut temp0 = aes64esm(state[0], state[1]);
        let mut temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[1][0], temp1 ^ round_keys[1][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[2][0], temp1 ^ round_keys[2][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[3][0], temp1 ^ round_keys[3][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[4][0], temp1 ^ round_keys[4][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[5][0], temp1 ^ round_keys[5][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[6][0], temp1 ^ round_keys[6][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[7][0], temp1 ^ round_keys[7][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[8][0], temp1 ^ round_keys[8][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[9][0], temp1 ^ round_keys[9][1]];

        temp0 = aes64es(state[0], state[1]);
        temp1 = aes64es(state[1], state[0]);
        state = [temp0 ^ round_keys[10][0], temp1 ^ round_keys[10][1]];

        // Return the encrypted counter as u128.
        u128::from(state[0]) | (u128::from(state[1]) << 64)
    }
}

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[[u64; 2]; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        self.round_keys.set([[0; 2]; AES128_KEY_COUNT]);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() + (1 << 64));
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() + (1 << 96));
        clone
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let mut key_lo = [0u8; 8];
        let mut key_hi = [0u8; 8];

        key_lo.copy_from_slice(&key[0..8]);
        key_hi.copy_from_slice(&key[8..16]);

        let counter = u128::from_le_bytes(counter);
        let key = [u64::from_le_bytes(key_lo), u64::from_le_bytes(key_hi)];

        let round_keys = aes128_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        let mut key_lo = [0u8; 8];
        let mut key_hi = [0u8; 8];

        key_lo.copy_from_slice(&key[0..8]);
        key_hi.copy_from_slice(&key[8..16]);

        let counter = u128::from_le_bytes(counter);
        let key = [u64::from_le_bytes(key_lo), u64::from_le_bytes(key_hi)];

        let round_keys = aes128_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.counter.get()
    }

    #[cfg_attr(target_feature = "zkne", inline(always))]
    #[cfg_attr(not(target_feature = "zkne"), target_feature(enable = "zkne"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the counter.
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        let round_keys = self.round_keys.get();
        let counter_low = counter as u64;
        let counter_high = (counter >> 64) as u64;

        // We apply the AES encryption on the counter.
        let mut state = [
            counter_low ^ round_keys[0][0],
            counter_high ^ round_keys[0][1],
        ];

        let mut temp0 = aes64esm(state[0], state[1]);
        let mut temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[1][0], temp1 ^ round_keys[1][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[2][0], temp1 ^ round_keys[2][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[3][0], temp1 ^ round_keys[3][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[4][0], temp1 ^ round_keys[4][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[5][0], temp1 ^ round_keys[5][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[6][0], temp1 ^ round_keys[6][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[7][0], temp1 ^ round_keys[7][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[8][0], temp1 ^ round_keys[8][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[9][0], temp1 ^ round_keys[9][1]];

        temp0 = aes64es(state[0], state[1]);
        temp1 = aes64es(state[1], state[0]);
        state = [temp0 ^ round_keys[10][0], temp1 ^ round_keys[10][1]];

        // Return the encrypted counter as u128.
        u128::from(state[0]) | (u128::from(state[1]) << 64)
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64 {
    counter: Cell<[u64; 2]>,
    round_keys: Cell<[[u64; 2]; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr64 {
    fn drop(&mut self) {
        self.counter.set([0, 0]);
        self.round_keys.set([[0; 2]; AES256_KEY_COUNT]);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr64 {
    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let mut key_0 = [0u8; 8];
        let mut key_1 = [0u8; 8];
        let mut key_2 = [0u8; 8];
        let mut key_3 = [0u8; 8];

        key_0.copy_from_slice(&key[0..8]);
        key_1.copy_from_slice(&key[8..16]);
        key_2.copy_from_slice(&key[16..24]);
        key_3.copy_from_slice(&key[24..32]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [
            u64::from_le_bytes(key_0),
            u64::from_le_bytes(key_1),
            u64::from_le_bytes(key_2),
            u64::from_le_bytes(key_3),
        ];

        let round_keys = aes256_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        let mut key_0 = [0u8; 8];
        let mut key_1 = [0u8; 8];
        let mut key_2 = [0u8; 8];
        let mut key_3 = [0u8; 8];

        key_0.copy_from_slice(&key[0..8]);
        key_1.copy_from_slice(&key[8..16]);
        key_2.copy_from_slice(&key[16..24]);
        key_3.copy_from_slice(&key[24..32]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [
            u64::from_le_bytes(key_0),
            u64::from_le_bytes(key_1),
            u64::from_le_bytes(key_2),
            u64::from_le_bytes(key_3),
        ];

        let round_keys = aes256_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.counter.get()[0]
    }

    #[cfg_attr(target_feature = "zkne", inline(always))]
    #[cfg_attr(not(target_feature = "zkne"), target_feature(enable = "zkne"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the lower 64 bits.
        let counter = self.counter.get();
        let mut new_counter = counter;
        new_counter[0] = counter[0].wrapping_add(1);
        self.counter.set(new_counter);

        let round_keys = self.round_keys.get();

        // We apply the AES encryption on the counter.
        let mut state = [counter[0] ^ round_keys[0][0], counter[1] ^ round_keys[0][1]];

        let mut temp0 = aes64esm(state[0], state[1]);
        let mut temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[1][0], temp1 ^ round_keys[1][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[2][0], temp1 ^ round_keys[2][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[3][0], temp1 ^ round_keys[3][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[4][0], temp1 ^ round_keys[4][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[5][0], temp1 ^ round_keys[5][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[6][0], temp1 ^ round_keys[6][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[7][0], temp1 ^ round_keys[7][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[8][0], temp1 ^ round_keys[8][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[9][0], temp1 ^ round_keys[9][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[10][0], temp1 ^ round_keys[10][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[11][0], temp1 ^ round_keys[11][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[12][0], temp1 ^ round_keys[12][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[13][0], temp1 ^ round_keys[13][1]];

        temp0 = aes64es(state[0], state[1]);
        temp1 = aes64es(state[1], state[0]);
        state = [temp0 ^ round_keys[14][0], temp1 ^ round_keys[14][1]];

        // Return the encrypted counter as u128.
        u128::from(state[0]) | (u128::from(state[1]) << 64)
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr128 {
    counter: Cell<u128>,
    round_keys: Cell<[[u64; 2]; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        self.round_keys.set([[0; 2]; AES256_KEY_COUNT]);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() + (1 << 64));
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        self.counter.set(self.counter.get() + (1 << 96));
        clone
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let mut key_0 = [0u8; 8];
        let mut key_1 = [0u8; 8];
        let mut key_2 = [0u8; 8];
        let mut key_3 = [0u8; 8];

        key_0.copy_from_slice(&key[0..8]);
        key_1.copy_from_slice(&key[8..16]);
        key_2.copy_from_slice(&key[16..24]);
        key_3.copy_from_slice(&key[24..32]);

        let counter = u128::from_le_bytes(counter);
        let key = [
            u64::from_le_bytes(key_0),
            u64::from_le_bytes(key_1),
            u64::from_le_bytes(key_2),
            u64::from_le_bytes(key_3),
        ];

        let round_keys = aes256_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: Cell::new(round_keys),
        }
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.counter.get()
    }

    #[target_feature(enable = "zkne")]
    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        let mut key_0 = [0u8; 8];
        let mut key_1 = [0u8; 8];
        let mut key_2 = [0u8; 8];
        let mut key_3 = [0u8; 8];

        key_0.copy_from_slice(&key[0..8]);
        key_1.copy_from_slice(&key[8..16]);
        key_2.copy_from_slice(&key[16..24]);
        key_3.copy_from_slice(&key[24..32]);

        let counter = u128::from_le_bytes(counter);
        let key = [
            u64::from_le_bytes(key_0),
            u64::from_le_bytes(key_1),
            u64::from_le_bytes(key_2),
            u64::from_le_bytes(key_3),
        ];

        let round_keys = aes256_key_expansion(key);

        self.counter.set(counter);
        self.round_keys.set(round_keys)
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[cfg_attr(target_feature = "zkne", inline(always))]
    #[cfg_attr(not(target_feature = "zkne"), target_feature(enable = "zkne"))]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the counter.
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        let round_keys = self.round_keys.get();
        let counter_low = counter as u64;
        let counter_high = (counter >> 64) as u64;

        // We apply the AES encryption on the counter.
        let mut state = [
            counter_low ^ round_keys[0][0],
            counter_high ^ round_keys[0][1],
        ];

        let mut temp0 = aes64esm(state[0], state[1]);
        let mut temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[1][0], temp1 ^ round_keys[1][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[2][0], temp1 ^ round_keys[2][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[3][0], temp1 ^ round_keys[3][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[4][0], temp1 ^ round_keys[4][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[5][0], temp1 ^ round_keys[5][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[6][0], temp1 ^ round_keys[6][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[7][0], temp1 ^ round_keys[7][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[8][0], temp1 ^ round_keys[8][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[9][0], temp1 ^ round_keys[9][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[10][0], temp1 ^ round_keys[10][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[11][0], temp1 ^ round_keys[11][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[12][0], temp1 ^ round_keys[12][1]];

        temp0 = aes64esm(state[0], state[1]);
        temp1 = aes64esm(state[1], state[0]);
        state = [temp0 ^ round_keys[13][0], temp1 ^ round_keys[13][1]];

        temp0 = aes64es(state[0], state[1]);
        temp1 = aes64es(state[1], state[0]);
        state = [temp0 ^ round_keys[14][0], temp1 ^ round_keys[14][1]];

        // Return the encrypted counter as u128.
        u128::from(state[0]) | (u128::from(state[1]) << 64)
    }
}

#[target_feature(enable = "zkne")]
unsafe fn aes128_key_expansion(key: [u64; 2]) -> [[u64; 2]; AES128_KEY_COUNT] {
    unsafe fn generate_round_key<const RNUM: u8>(expanded_keys: &mut [[u64; 2]]) {
        let prev_key = expanded_keys[RNUM as usize];

        let temp = aes64ks1i::<RNUM>(prev_key[1]);
        let rk0 = aes64ks2(temp, prev_key[0]);
        let rk1 = aes64ks2(rk0, prev_key[1]);

        expanded_keys[RNUM as usize + 1] = [rk0, rk1];
    }
    let mut expanded_keys = [[0u64; 2]; AES128_KEY_COUNT];

    // Load the initial key.
    expanded_keys[0] = [key[0], key[1]];

    // The actual key expansion.
    generate_round_key::<0>(&mut expanded_keys);
    generate_round_key::<1>(&mut expanded_keys);
    generate_round_key::<2>(&mut expanded_keys);
    generate_round_key::<3>(&mut expanded_keys);
    generate_round_key::<4>(&mut expanded_keys);
    generate_round_key::<5>(&mut expanded_keys);
    generate_round_key::<6>(&mut expanded_keys);
    generate_round_key::<7>(&mut expanded_keys);
    generate_round_key::<8>(&mut expanded_keys);
    generate_round_key::<9>(&mut expanded_keys);

    expanded_keys
}

#[target_feature(enable = "zkne")]
unsafe fn aes256_key_expansion(key: [u64; 4]) -> [[u64; 2]; AES256_KEY_COUNT] {
    unsafe fn generate_round_keys<const RNUM: u8>(
        expanded_keys: &mut [[u64; 2]; AES256_KEY_COUNT],
    ) {
        let prev_key_0 = expanded_keys[RNUM as usize * 2];
        let prev_key_1 = expanded_keys[(RNUM as usize * 2) + 1];

        let temp = aes64ks1i::<RNUM>(prev_key_1[1]);

        let rk0 = aes64ks2(temp, prev_key_0[0]);
        let rk1 = aes64ks2(rk0, prev_key_0[1]);

        expanded_keys[(RNUM as usize * 2) + 2] = [rk0, rk1];

        if RNUM < 6 {
            let temp = aes64ks1i::<0xA>(rk1);

            let rk2 = aes64ks2(temp, prev_key_1[0]);
            let rk3 = aes64ks2(rk2, prev_key_1[1]);

            expanded_keys[(RNUM as usize * 2) + 3] = [rk2, rk3];
        }
    }
    let mut expanded_keys = [[0u64; 2]; AES256_KEY_COUNT];

    // Load the initial key.
    expanded_keys[0] = [key[0], key[1]];
    expanded_keys[1] = [key[2], key[3]];

    // The actual key expansion.
    generate_round_keys::<0>(&mut expanded_keys);
    generate_round_keys::<1>(&mut expanded_keys);
    generate_round_keys::<2>(&mut expanded_keys);
    generate_round_keys::<3>(&mut expanded_keys);
    generate_round_keys::<4>(&mut expanded_keys);
    generate_round_keys::<5>(&mut expanded_keys);
    generate_round_keys::<6>(&mut expanded_keys);

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
            let mut key_lo = [0u8; 8];
            let mut key_hi = [0u8; 8];
            key_lo.copy_from_slice(&key[0..8]);
            key_hi.copy_from_slice(&key[8..16]);
            let key = [u64::from_le_bytes(key_lo), u64::from_le_bytes(key_hi)];

            let expanded: [[u64; 2]; AES128_KEY_COUNT] = unsafe { aes128_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [[u64; 2]; AES128_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }

    #[test]
    fn test_aes256_key_expansion() {
        aes256_key_expansion_test(|key| {
            let mut key_0_lo = [0u8; 8];
            let mut key_0_hi = [0u8; 8];
            let mut key_1_lo = [0u8; 8];
            let mut key_1_hi = [0u8; 8];
            key_0_lo.copy_from_slice(&key[0..8]);
            key_0_hi.copy_from_slice(&key[8..16]);
            key_1_lo.copy_from_slice(&key[16..24]);
            key_1_hi.copy_from_slice(&key[24..32]);
            let key = [
                u64::from_le_bytes(key_0_lo),
                u64::from_le_bytes(key_0_hi),
                u64::from_le_bytes(key_1_lo),
                u64::from_le_bytes(key_1_hi),
            ];

            let expanded: [[u64; 2]; AES256_KEY_COUNT] = unsafe { aes256_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [[u64; 2]; AES256_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }
}
