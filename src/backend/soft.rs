//! Software based fixsliced implementations of AES-128 and AES-256 (64-bit) adapted from the C
//! implementation.
//!
//! All implementations are fully bitsliced and do not rely on any Look-Up Table (LUT).
//!
//! See the paper at <https://eprint.iacr.org/2020/1123.pdf> for more details.
//!
//! # Author (original C code)
//!
//! Alexandre Adomnicai, Nanyang Technological University, Singapore
//! <alexandre.adomnicai@ntu.edu.sg>
//!
//! Originally licensed MIT. Re-licensed as Apache 2.0+MIT with permission.
//!
//! # Author (original Rust code)
//!
//! Adapted from the AES crate written by the RustCrypto team.
//!
//! We don't use the `AES` crate directly, simply because it doesn't inline very well, and we can
//! provide also better inner mutability this way (since we want to optimize the fast path, when
//! hardware based AES is found).
//!

use crate::constants::{AES128_KEY_SIZE, AES256_KEY_SIZE, AES_BLOCK_SIZE};

use core::cell::RefCell;

const BLOCK_COUNT: usize = 4;
const FIX_SLICE_128_KEYS_SIZE: usize = 88;
const FIX_SLICE_256_KEYS_SIZE: usize = 120;

/// 128-bit AES block.
type Block = [u8; AES_BLOCK_SIZE];

/// This software implementation calculates 4 blocks at once.
type BatchBlocks = [Block; BLOCK_COUNT];

/// AES-128 round keys.
type FixsliceKeys128 = [u64; FIX_SLICE_128_KEYS_SIZE];

/// AES-256 round keys.
type FixsliceKeys256 = [u64; FIX_SLICE_256_KEYS_SIZE];

/// 512-bit internal state.
type State = [u64; 8];

#[derive(Clone)]
pub struct Aes128Ctr64(RefCell<Aes128Ctr64Inner>);

#[derive(Clone)]
struct Aes128Ctr64Inner {
    counter: [u64; 2],
    round_keys: FixsliceKeys128,
    batch_blocks: BatchBlocks,
    batch_num: usize,
}

impl Drop for Aes128Ctr64 {
    fn drop(&mut self) {
        let mut inner = self.0.borrow_mut();
        inner.counter = [0, 0];
        inner.round_keys = [0; FIX_SLICE_128_KEYS_SIZE];
        inner.batch_blocks = [Block::default(); BLOCK_COUNT];
        inner.batch_num = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr64 {
    #[cfg(feature = "tls")]
    pub(crate) const fn zeroed() -> Self {
        Self(RefCell::new(Aes128Ctr64Inner {
            counter: [0; 2],
            round_keys: [0; FIX_SLICE_128_KEYS_SIZE],
            batch_blocks: [[0; AES_BLOCK_SIZE]; BLOCK_COUNT],
            batch_num: BLOCK_COUNT,
        }))
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let round_keys: FixsliceKeys128 = aes128_key_expansion(key);

        Self(RefCell::new(Aes128Ctr64Inner {
            counter,
            round_keys,
            batch_blocks: [Block::default(); BLOCK_COUNT],
            batch_num: BLOCK_COUNT,
        }))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        let mut inner = self.0.borrow_mut();
        inner.counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        inner.round_keys = aes128_key_expansion(key);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        false
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        let inner = self.0.borrow();
        inner.counter[0]
    }

    #[inline(never)]
    pub(crate) fn next_impl(&self) -> u128 {
        let mut inner = self.0.borrow_mut();

        // We have blocks left that we can return.
        if inner.batch_num < BLOCK_COUNT {
            let block = inner.batch_blocks[inner.batch_num];
            inner.batch_num = inner.batch_num.wrapping_add(1);
            return u128::from_le_bytes(block);
        }

        // Fill all blocks with the correct data.
        let counter_0 = inner.counter[0];
        let counter_1 = inner.counter[0].wrapping_add(1);
        let counter_2 = inner.counter[0].wrapping_add(2);
        let counter_3 = inner.counter[0].wrapping_add(3);
        let nonce = inner.counter[1];

        inner.counter[0] = inner.counter[0].wrapping_add(4);

        inner.batch_blocks[0][..8].copy_from_slice(&counter_0.to_le_bytes());
        inner.batch_blocks[0][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[1][..8].copy_from_slice(&counter_1.to_le_bytes());
        inner.batch_blocks[1][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[2][..8].copy_from_slice(&counter_2.to_le_bytes());
        inner.batch_blocks[2][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[3][..8].copy_from_slice(&counter_3.to_le_bytes());
        inner.batch_blocks[3][8..].copy_from_slice(&nonce.to_le_bytes());

        inner.batch_blocks = aes128_encrypt(&inner.round_keys, &inner.batch_blocks);

        // Return the first encrypted counter as u128
        inner.batch_num = 1;
        u128::from_le_bytes(inner.batch_blocks[0])
    }
}

#[derive(Clone)]
pub struct Aes128Ctr128(RefCell<Aes128Ctr128Inner>);

#[derive(Clone)]
struct Aes128Ctr128Inner {
    counter: u128,
    round_keys: FixsliceKeys128,
    batch_blocks: BatchBlocks,
    batch_num: usize,
}

impl Drop for Aes128Ctr128 {
    fn drop(&mut self) {
        let mut inner = self.0.borrow_mut();
        inner.counter = 0;
        inner.round_keys = [0; FIX_SLICE_128_KEYS_SIZE];
        inner.batch_blocks = [Block::default(); BLOCK_COUNT];
        inner.batch_num = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        let mut inner = self.0.borrow_mut();
        inner.counter += 1 << 64;
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        let mut inner = self.0.borrow_mut();
        inner.counter += 1 << 96;
        clone
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: FixsliceKeys128 = aes128_key_expansion(key);

        Self(RefCell::new(Aes128Ctr128Inner {
            counter,
            round_keys,
            batch_blocks: [Block::default(); BLOCK_COUNT],
            batch_num: BLOCK_COUNT,
        }))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        let mut inner = self.0.borrow_mut();
        inner.counter = u128::from_le_bytes(counter);
        inner.round_keys = aes128_key_expansion(key);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        false
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        let inner = self.0.borrow();
        inner.counter
    }

    #[inline(never)]
    pub(crate) fn next_impl(&self) -> u128 {
        let mut inner = self.0.borrow_mut();

        // We have blocks left that we can return.
        if inner.batch_num < BLOCK_COUNT {
            let block = inner.batch_blocks[inner.batch_num];
            inner.batch_num = inner.batch_num.wrapping_add(1);
            return u128::from_le_bytes(block);
        }

        // Fill all blocks with the correct data.
        let counter_0 = inner.counter;
        let counter_1 = inner.counter.wrapping_add(1);
        let counter_2 = inner.counter.wrapping_add(2);
        let counter_3 = inner.counter.wrapping_add(3);

        inner.counter = inner.counter.wrapping_add(4);

        inner.batch_blocks[0].copy_from_slice(&counter_0.to_le_bytes());
        inner.batch_blocks[1].copy_from_slice(&counter_1.to_le_bytes());
        inner.batch_blocks[2].copy_from_slice(&counter_2.to_le_bytes());
        inner.batch_blocks[3].copy_from_slice(&counter_3.to_le_bytes());

        inner.batch_blocks = aes128_encrypt(&inner.round_keys, &inner.batch_blocks);

        // Return the first encrypted counter as u128
        inner.batch_num = 1;
        u128::from_le_bytes(inner.batch_blocks[0])
    }
}

#[derive(Clone)]
pub struct Aes256Ctr64(RefCell<Aes256Ctr64Inner>);

#[derive(Clone)]
struct Aes256Ctr64Inner {
    counter: [u64; 2],
    round_keys: FixsliceKeys256,
    batch_blocks: BatchBlocks,
    batch_num: usize,
}

impl Drop for Aes256Ctr64 {
    fn drop(&mut self) {
        let mut inner = self.0.borrow_mut();
        inner.counter = [0, 0];
        inner.round_keys = [0; FIX_SLICE_256_KEYS_SIZE];
        inner.batch_blocks = [Block::default(); BLOCK_COUNT];
        inner.batch_num = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr64 {
    pub(crate) fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let round_keys: FixsliceKeys256 = aes256_key_expansion(key);

        Self(RefCell::new(Aes256Ctr64Inner {
            counter,
            round_keys,
            batch_blocks: [Block::default(); BLOCK_COUNT],
            batch_num: BLOCK_COUNT,
        }))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        let mut inner = self.0.borrow_mut();
        inner.counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        inner.round_keys = aes256_key_expansion(key);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        false
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        let inner = self.0.borrow();
        inner.counter[0]
    }

    pub(crate) fn next_impl(&self) -> u128 {
        let mut inner = self.0.borrow_mut();

        // We have blocks left that we can return.
        if inner.batch_num < BLOCK_COUNT {
            let block = inner.batch_blocks[inner.batch_num];
            inner.batch_num = inner.batch_num.wrapping_add(1);
            return u128::from_le_bytes(block);
        }

        // Fill all blocks with the correct data.
        let counter_0 = inner.counter[0];
        let counter_1 = inner.counter[0].wrapping_add(1);
        let counter_2 = inner.counter[0].wrapping_add(2);
        let counter_3 = inner.counter[0].wrapping_add(3);
        let nonce = inner.counter[1];

        inner.counter[0] = inner.counter[0].wrapping_add(4);

        inner.batch_blocks[0][..8].copy_from_slice(&counter_0.to_le_bytes());
        inner.batch_blocks[0][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[1][..8].copy_from_slice(&counter_1.to_le_bytes());
        inner.batch_blocks[1][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[2][..8].copy_from_slice(&counter_2.to_le_bytes());
        inner.batch_blocks[2][8..].copy_from_slice(&nonce.to_le_bytes());
        inner.batch_blocks[3][..8].copy_from_slice(&counter_3.to_le_bytes());
        inner.batch_blocks[3][8..].copy_from_slice(&nonce.to_le_bytes());

        inner.batch_blocks = aes256_encrypt(&inner.round_keys, &inner.batch_blocks);

        // Return the first encrypted counter as u128
        inner.batch_num = 1;
        u128::from_le_bytes(inner.batch_blocks[0])
    }
}

#[derive(Clone)]
pub struct Aes256Ctr128(RefCell<Aes256Ctr128Inner>);

#[derive(Clone)]
struct Aes256Ctr128Inner {
    pub(crate) counter: u128,
    round_keys: FixsliceKeys256,
    batch_blocks: BatchBlocks,
    batch_num: usize,
}

impl Drop for Aes256Ctr128 {
    fn drop(&mut self) {
        let mut inner = self.0.borrow_mut();
        inner.counter = 0;
        inner.round_keys = [0; FIX_SLICE_256_KEYS_SIZE];
        inner.batch_blocks = [Block::default(); BLOCK_COUNT];
        inner.batch_num = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.clone();
        let mut inner = self.0.borrow_mut();
        inner.counter += 1 << 64;
        clone
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.clone();
        let mut inner = self.0.borrow_mut();
        inner.counter += 1 << 96;
        clone
    }

    pub(crate) fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let counter = u128::from_le_bytes(counter);
        let round_keys: FixsliceKeys256 = aes256_key_expansion(key);

        Self(RefCell::new(Aes256Ctr128Inner {
            counter,
            round_keys,
            batch_blocks: [Block::default(); BLOCK_COUNT],
            batch_num: BLOCK_COUNT,
        }))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        let mut inner = self.0.borrow_mut();
        inner.counter = u128::from_le_bytes(counter);
        inner.round_keys = aes256_key_expansion(key);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        false
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        let inner = self.0.borrow();
        inner.counter
    }

    #[inline(never)]
    pub(crate) fn next_impl(&self) -> u128 {
        let mut inner = self.0.borrow_mut();

        // We have blocks left that we can return.
        if inner.batch_num < BLOCK_COUNT {
            let block = inner.batch_blocks[inner.batch_num];
            inner.batch_num = inner.batch_num.wrapping_add(1);
            return u128::from_le_bytes(block);
        }

        // Fill all blocks with the correct data.
        let counter_0 = inner.counter;
        let counter_1 = inner.counter.wrapping_add(1);
        let counter_2 = inner.counter.wrapping_add(2);
        let counter_3 = inner.counter.wrapping_add(3);

        inner.counter = inner.counter.wrapping_add(4);

        inner.batch_blocks[0].copy_from_slice(&counter_0.to_le_bytes());
        inner.batch_blocks[1].copy_from_slice(&counter_1.to_le_bytes());
        inner.batch_blocks[2].copy_from_slice(&counter_2.to_le_bytes());
        inner.batch_blocks[3].copy_from_slice(&counter_3.to_le_bytes());

        inner.batch_blocks = aes256_encrypt(&inner.round_keys, &inner.batch_blocks);

        // Return the first encrypted counter as u128
        inner.batch_num = 1;
        u128::from_le_bytes(inner.batch_blocks[0])
    }
}

fn aes128_key_expansion(key: [u8; AES128_KEY_SIZE]) -> FixsliceKeys128 {
    let mut rkeys = [0u64; FIX_SLICE_128_KEYS_SIZE];

    bitslice(&mut rkeys[..8], &key, &key, &key, &key);

    let mut rk_off = 0;
    for rcon in 0..10 {
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        if rcon < 8 {
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);
        } else {
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 8);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 7);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 5);
            add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 4);
        }

        const DISTANCE: u32 = ror_distance(1, 3);
        xor_columns::<DISTANCE>(&mut rkeys, rk_off, 8);
    }

    // Adjust to match fixslicing format
    for i in (8..72).step_by(32) {
        inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
        inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
    }
    inv_shift_rows_1(&mut rkeys[72..80]);

    // Account for NOTs removed from sub_bytes
    for i in 1..11 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully bitsliced AES-256 key schedule to match the fully-fixsliced representation.
fn aes256_key_expansion(key: [u8; AES256_KEY_SIZE]) -> FixsliceKeys256 {
    let mut rkeys = [0u64; 120];

    let mut low = [0u8; AES_BLOCK_SIZE];
    low.copy_from_slice(&key[..16]);
    let mut high = [0u8; AES_BLOCK_SIZE];
    high.copy_from_slice(&key[16..]);

    bitslice(&mut rkeys[..8], &low, &low, &low, &low);
    bitslice(&mut rkeys[8..16], &high, &high, &high, &high);

    let mut rk_off = 8;

    let mut rcon = 0;
    loop {
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);

        const DISTANCE_0: u32 = ror_distance(1, 3);
        xor_columns::<DISTANCE_0>(&mut rkeys, rk_off, 16);
        rcon += 1;

        if rcon == 7 {
            break;
        }

        memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        const DISTANCE_1: u32 = ror_distance(0, 3);
        xor_columns::<DISTANCE_1>(&mut rkeys, rk_off, 16);
    }

    // Adjust to match fixslicing format
    for i in (8..104).step_by(32) {
        inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
        inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
    }
    inv_shift_rows_1(&mut rkeys[104..112]);

    // Account for NOTs removed from sub_bytes
    for i in 1..15 {
        sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
fn aes128_encrypt(rkeys: &FixsliceKeys128, blocks: &BatchBlocks) -> BatchBlocks {
    let mut state = State::default();

    bitslice(&mut state, &blocks[0], &blocks[1], &blocks[2], &blocks[3]);

    add_round_key(&mut state, &rkeys[..8]);

    let mut rk_off = 8;
    loop {
        sub_bytes(&mut state);
        mix_columns_1(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        if rk_off == 80 {
            break;
        }

        sub_bytes(&mut state);
        mix_columns_2(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        sub_bytes(&mut state);
        mix_columns_3(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        sub_bytes(&mut state);
        mix_columns_0(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    shift_rows_2(&mut state);
    sub_bytes(&mut state);
    add_round_key(&mut state, &rkeys[80..]);

    inv_bitslice(&state)
}

/// Fully-fixsliced AES-256 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
fn aes256_encrypt(rkeys: &FixsliceKeys256, blocks: &BatchBlocks) -> BatchBlocks {
    let mut state = State::default();

    bitslice(&mut state, &blocks[0], &blocks[1], &blocks[2], &blocks[3]);

    add_round_key(&mut state, &rkeys[..8]);

    let mut rk_off = 8;
    loop {
        sub_bytes(&mut state);
        mix_columns_1(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        if rk_off == 112 {
            break;
        }

        sub_bytes(&mut state);
        mix_columns_2(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        sub_bytes(&mut state);
        mix_columns_3(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        sub_bytes(&mut state);
        mix_columns_0(&mut state);
        add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    shift_rows_2(&mut state);
    sub_bytes(&mut state);
    add_round_key(&mut state, &rkeys[112..]);

    inv_bitslice(&state)
}

/// XOR the round key to the internal state. The round keys are expected to be
/// pre-computed and to be packed in the fixsliced representation.
#[inline]
fn add_round_key(state: &mut State, rkey: &[u64]) {
    for (a, b) in state.iter_mut().zip(rkey) {
        *a ^= b;
    }
}

/// Bitsliced implementation of the AES Sbox based on Boyar, Peralta and Calik.
///
/// See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// Note that the 4 bitwise NOT (^= 0xffffffffffffffff) are moved to the key schedule.
fn sub_bytes(state: &mut [u64]) {
    // Scheduled using https://github.com/Ko-/aes-armcortexm/tree/public/scheduler
    // Inline "stack" comments reflect suggested stores and loads (ARM Cortex-M3 and M4)

    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    // y12 -> stack
    let y9 = u0 ^ u3;
    // y20 -> stack
    let y11 = y20 ^ y9;
    // y9 -> stack
    let t12 = y9 & y11;
    // y6 -> stack
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    // y15 -> stack
    let y17 = y10 ^ y11;
    // y14 -> stack
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    // y17 -> stack
    let y19 = y10 ^ y8;
    // y10 -> stack
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    // y11 -> stack
    let y21 = y13 ^ y16;
    // y13 -> stack
    let t7 = y13 & y16;
    // y16 -> stack
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    // u7 -> stack
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    // y6 <- stack
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    // y20 <- stack
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    // y4 -> stack
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    // y16 <- stack
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    // tc12 -> stack
    // y13 <- stack
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    // y10 <- stack
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    // y15 <- stack
    let z0 = t44 & y15;
    // z17 -> stack
    // y12 <- stack
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    // y4 <- stack
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    // y17 <- stack
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    // y14 <- stack
    let z16 = t45 & y14;
    // y11 <- stack
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    // z14 -> stack
    // y9 <- stack
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    // u7 <- stack
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    // z14 <- stack
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    // z17 <- stack
    let s2 = tc26 ^ z17;
    // tc12 <- stack
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
}

/// NOT operations that are omitted in S-box
#[inline]
fn sub_bytes_nots(state: &mut [u64]) {
    state[0] ^= 0xFFFFFFFFFFFFFFFF;
    state[1] ^= 0xFFFFFFFFFFFFFFFF;
    state[5] ^= 0xFFFFFFFFFFFFFFFF;
    state[6] ^= 0xFFFFFFFFFFFFFFFF;
}

#[inline(always)]
fn add_round_constant_bit(state: &mut [u64], bit: usize) {
    state[bit] ^= 0x00000000F0000000;
}

#[inline(always)]
fn ror(x: u64, y: u32) -> u64 {
    x.rotate_right(y)
}

const fn ror_distance(rows: u32, cols: u32) -> u32 {
    (rows << 4) + (cols << 2)
}

#[inline(always)]
fn inv_shift_rows_1(state: &mut [u64]) {
    shift_rows_3(state);
}

#[inline(always)]
fn inv_shift_rows_2(state: &mut [u64]) {
    shift_rows_2(state);
}

#[inline(always)]
fn inv_shift_rows_3(state: &mut [u64]) {
    shift_rows_1(state);
}

/// Applies ShiftRows once on an AES state (or key).
#[inline]
fn shift_rows_1(state: &mut [u64]) {
    for x in state.iter_mut() {
        delta_swap_1(x, 8, 0x00F000FF000F0000);
        delta_swap_1(x, 4, 0x0F0F00000F0F0000);
    }
}

/// Applies ShiftRows twice on an AES state (or key).
#[inline]
fn shift_rows_2(state: &mut [u64]) {
    for x in state.iter_mut() {
        delta_swap_1(x, 8, 0x00FF000000FF0000);
    }
}

/// Applies ShiftRows three times on an AES state (or key).
#[inline]
fn shift_rows_3(state: &mut [u64]) {
    for x in state.iter_mut() {
        delta_swap_1(x, 8, 0x000F00FF00F00000);
        delta_swap_1(x, 4, 0x0F0F00000F0F0000);
    }
}

#[inline]
fn delta_swap_1(a: &mut u64, shift: u32, mask: u64) {
    let t = (*a ^ ((*a) >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
fn delta_swap_2(a: &mut u64, b: &mut u64, shift: u32, mask: u64) {
    let t = (*a ^ ((*b) >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

/// Copy 32-bytes within the provided slice to an 8-byte offset
fn memshift32(buffer: &mut [u64], src_offset: usize) {
    let dst_offset = src_offset + 8;

    for i in (0..8).rev() {
        buffer[dst_offset + i] = buffer[src_offset + i];
    }
}

/// Un-bitslice a 512-bit internal state into four 128-bit blocks of output.
fn inv_bitslice(input: &[u64]) -> BatchBlocks {
    // Unbitslicing is a bit index manipulation. 512 bits of data means each bit is positioned at
    // a 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so the
    // desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b1 b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The initially bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b1 b0

    let mut t0 = input[0];
    let mut t1 = input[1];
    let mut t2 = input[2];
    let mut t3 = input[3];
    let mut t4 = input[4];
    let mut t5 = input[5];
    let mut t6 = input[6];
    let mut t7 = input[7];

    // Bit Index Swap 6 <-> 0:
    //     __ __ p0 __ __ __ __ __ b0 => __ __ b0 __ __ __ __ __ p0
    let m0 = 0x5555555555555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 7 <-> 1:
    //     __ p1 __ __ __ __ __ b1 __ => __ b1 __ __ __ __ __ p1 __
    let m1 = 0x3333333333333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 8 <-> 2:
    //     p2 __ __ __ __ __ c0 __ __ => c0 __ __ __ __ __ p2 __ __
    let m2 = 0x0F0F0F0F0F0F0F0F;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    #[rustfmt::skip]
    fn write_reordered(columns: u64, output: &mut [u8]) {
        output[0x0] = (columns        ) as u8;
        output[0x1] = (columns >> 0x10) as u8;
        output[0x2] = (columns >> 0x20) as u8;
        output[0x3] = (columns >> 0x30) as u8;
        output[0x8] = (columns >> 0x08) as u8;
        output[0x9] = (columns >> 0x18) as u8;
        output[0xa] = (columns >> 0x28) as u8;
        output[0xb] = (columns >> 0x38) as u8;
    }

    let mut output = BatchBlocks::default();
    // Reorder by relabeling (note the order of output)
    //     c0 b1 b0 __ __ __ __ __ __ => b1 b0 c0 __ __ __ __ __ __
    // Reorder each block's bytes on output
    //     __ __ c0 r1 r0 c1 __ __ __ => __ __ c1 c0 r1 r0 __ __ __
    write_reordered(t0, &mut output[0][0x00..0x0C]);
    write_reordered(t4, &mut output[0][0x04..0x10]);
    write_reordered(t1, &mut output[1][0x00..0x0C]);
    write_reordered(t5, &mut output[1][0x04..0x10]);
    write_reordered(t2, &mut output[2][0x00..0x0C]);
    write_reordered(t6, &mut output[2][0x04..0x10]);
    write_reordered(t3, &mut output[3][0x00..0x0C]);
    write_reordered(t7, &mut output[3][0x04..0x10]);

    // Final AES bit index, as desired:
    //     b1 b0 c1 c0 r1 r0 p2 p1 p0
    output
}

/// XOR the columns after the S-box during the key schedule round function.
///
/// The `idx_xor` parameter refers to the index of the previous round key that is
/// involved in the XOR computation (should be 8 and 16 for AES-128 and AES-256,
/// respectively).
///
/// The `idx_ror` parameter refers to the rotation value, which varies between the
/// different key schedules.
fn xor_columns<const IDX_ROR: u32>(rkeys: &mut [u64], offset: usize, idx_xor: usize) {
    for i in 0..8 {
        let off_i = offset + i;
        let rk = rkeys[off_i - idx_xor] ^ (0x000F000F000F000F & ror(rkeys[off_i], IDX_ROR));
        rkeys[off_i] = rk
            ^ (0xFFF0FFF0FFF0FFF0 & (rk << 4))
            ^ (0xFF00FF00FF00FF00 & (rk << 8))
            ^ (0xF000F000F000F000 & (rk << 12));
    }
}

/// Bitslice four 128-bit input blocks input0, input1, input2, input3 into a 512-bit internal state.
fn bitslice(output: &mut [u64], input0: &Block, input1: &Block, input2: &Block, input3: &Block) {
    // Bitslicing is a bit index manipulation. 512 bits of data means each bit is positioned at a
    // 9-bit index. AES data is 4 blocks, each one a 4x4 column-major matrix of bytes, so the
    // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b1 b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The desired bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b1 b0

    #[rustfmt::skip]
    fn read_reordered(input: &[u8]) -> u64 {
        (u64::from(input[0x0])        ) |
            (u64::from(input[0x1]) << 0x10) |
            (u64::from(input[0x2]) << 0x20) |
            (u64::from(input[0x3]) << 0x30) |
            (u64::from(input[0x8]) << 0x08) |
            (u64::from(input[0x9]) << 0x18) |
            (u64::from(input[0xa]) << 0x28) |
            (u64::from(input[0xb]) << 0x38)
    }

    // Reorder each block's bytes on input
    //     __ __ c1 c0 r1 r0 __ __ __ => __ __ c0 r1 r0 c1 __ __ __
    // Reorder by relabeling (note the order of input)
    //     b1 b0 c0 __ __ __ __ __ __ => c0 b1 b0 __ __ __ __ __ __
    let mut t0 = read_reordered(&input0[0x00..0x0C]);
    let mut t4 = read_reordered(&input0[0x04..0x10]);
    let mut t1 = read_reordered(&input1[0x00..0x0C]);
    let mut t5 = read_reordered(&input1[0x04..0x10]);
    let mut t2 = read_reordered(&input2[0x00..0x0C]);
    let mut t6 = read_reordered(&input2[0x04..0x10]);
    let mut t3 = read_reordered(&input3[0x00..0x0C]);
    let mut t7 = read_reordered(&input3[0x04..0x10]);

    // Bit Index Swap 6 <-> 0:
    //     __ __ b0 __ __ __ __ __ p0 => __ __ p0 __ __ __ __ __ b0
    let m0 = 0x5555555555555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 7 <-> 1:
    //     __ b1 __ __ __ __ __ p1 __ => __ p1 __ __ __ __ __ b1 __
    let m1 = 0x3333333333333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 8 <-> 2:
    //     c0 __ __ __ __ __ p2 __ __ => p2 __ __ __ __ __ c0 __ __
    let m2 = 0x0F0F0F0F0F0F0F0F;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    // Final bitsliced bit index, as desired:
    //     p2 p1 p0 r1 r0 c1 c0 b1 b0
    output[0] = t0;
    output[1] = t1;
    output[2] = t2;
    output[3] = t3;
    output[4] = t4;
    output[5] = t5;
    output[6] = t6;
    output[7] = t7;
}

/// Computation of the MixColumns transformation in the fixsliced representation, with different
/// rotations used according to the round number mod 4.
///
/// Based on Käsper-Schwabe, similar to https://github.com/Ko-/aes-armcortexm.
macro_rules! define_mix_columns {
    (
        $name:ident,
        $first_rotate:path,
        $second_rotate:path
    ) => {
        #[rustfmt::skip]
        fn $name(state: &mut State) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0),
                $first_rotate(a1),
                $first_rotate(a2),
                $first_rotate(a3),
                $first_rotate(a4),
                $first_rotate(a5),
                $first_rotate(a6),
                $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                a0 ^ b0,
                a1 ^ b1,
                a2 ^ b2,
                a3 ^ b3,
                a4 ^ b4,
                a5 ^ b5,
                a6 ^ b6,
                a7 ^ b7,
            );
            state[0] = b0      ^ c7 ^ $second_rotate(c0);
            state[1] = b1 ^ c0 ^ c7 ^ $second_rotate(c1);
            state[2] = b2 ^ c1      ^ $second_rotate(c2);
            state[3] = b3 ^ c2 ^ c7 ^ $second_rotate(c3);
            state[4] = b4 ^ c3 ^ c7 ^ $second_rotate(c4);
            state[5] = b5 ^ c4      ^ $second_rotate(c5);
            state[6] = b6 ^ c5      ^ $second_rotate(c6);
            state[7] = b7 ^ c6      ^ $second_rotate(c7);
        }
    }
}

define_mix_columns!(mix_columns_0, rotate_rows_1, rotate_rows_2);

define_mix_columns!(
    mix_columns_1,
    rotate_rows_and_columns_1_1,
    rotate_rows_and_columns_2_2
);

define_mix_columns!(mix_columns_2, rotate_rows_and_columns_1_2, rotate_rows_2);

define_mix_columns!(
    mix_columns_3,
    rotate_rows_and_columns_1_3,
    rotate_rows_and_columns_2_2
);

#[inline(always)]
fn rotate_rows_1(x: u64) -> u64 {
    const DISTANCE: u32 = ror_distance(1, 0);
    ror(x, DISTANCE)
}

#[inline(always)]
fn rotate_rows_2(x: u64) -> u64 {
    const DISTANCE: u32 = ror_distance(2, 0);
    ror(x, DISTANCE)
}

#[inline(always)]
fn rotate_rows_and_columns_1_1(x: u64) -> u64 {
    const DISTANCE_0: u32 = ror_distance(1, 1);
    const DISTANCE_1: u32 = ror_distance(0, 1);
    (ror(x, DISTANCE_0) & 0x0FFF0FFF0FFF0FFF) | (ror(x, DISTANCE_1) & 0xF000F000F000F000)
}

#[inline(always)]
fn rotate_rows_and_columns_1_2(x: u64) -> u64 {
    const DISTANCE_0: u32 = ror_distance(1, 2);
    const DISTANCE_1: u32 = ror_distance(0, 2);
    (ror(x, DISTANCE_0) & 0x00FF00FF00FF00FF) | (ror(x, DISTANCE_1) & 0xFF00FF00FF00FF00)
}

#[inline(always)]
fn rotate_rows_and_columns_1_3(x: u64) -> u64 {
    const DISTANCE_0: u32 = ror_distance(1, 3);
    const DISTANCE_1: u32 = ror_distance(0, 3);
    (ror(x, DISTANCE_0) & 0x000F000F000F000F) | (ror(x, DISTANCE_1) & 0xFFF0FFF0FFF0FFF0)
}

#[inline(always)]
fn rotate_rows_and_columns_2_2(x: u64) -> u64 {
    const DISTANCE_0: u32 = ror_distance(2, 2);
    const DISTANCE_1: u32 = ror_distance(1, 2);
    (ror(x, DISTANCE_0) & 0x00FF00FF00FF00FF) | (ror(x, DISTANCE_1) & 0xFF00FF00FF00FF00)
}
