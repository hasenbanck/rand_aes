use core::{arch::asm, cell::{Cell, RefCell}};

use crate::constants::{AES128_KEY_COUNT, AES128_KEY_SIZE, AES256_KEY_COUNT, AES256_KEY_SIZE};

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64 {
    counter: Cell<[u64; 2]>,
    round_keys: RefCell<[u128; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr64 {
    fn drop(&mut self) {
        self.counter.set([0, 0]);
        *self.round_keys.borrow_mut() = [0; AES128_KEY_COUNT];
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes128Ctr64 {
    #[cfg(feature = "tls")]
    pub(crate) const fn zeroed() -> Self {
        Self {
            counter: Cell::new([0; 2]),
            round_keys: RefCell::new([0; AES128_KEY_COUNT]),
        }
    }

    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let mut key_0 = [0u8; 16];
        key_0.copy_from_slice(&key[0..16]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = u128::from_le_bytes(key_0);

        let round_keys = aes128_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: RefCell::new(round_keys),
        }
    }

    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        let mut key_0 = [0u8; 16];
        key_0.copy_from_slice(&key[0..16]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = u128::from_le_bytes(key_0);

        let round_keys = aes128_key_expansion(key);

        self.counter.set(counter);
        *self.round_keys.borrow_mut() = round_keys;
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.counter.get()[0]
    }

    #[inline(always)]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the lower 64 bits.
        let counter = self.counter.get();
        let mut new_counter = counter;
        new_counter[0] = counter[0].wrapping_add(1);
        self.counter.set(new_counter);
        
        // We know that there can't be any other reference to its data, and it will also not
        // store a reference to it somewhere. So it's safe for the ASM to read from it directly.
        // Once there are intrinsic, we can again use the cell type, since then the compiler is 
        // able to optimize the access to it.
        let mut round_keys_ptr = self.round_keys.as_ptr();

        // Initialize the state with the counter.
        let mut state = counter;
        let state_ptr = (&mut state).as_mut_ptr();

        asm!(
            "vsetivli x0, 4, e32, m1, ta, ma",
            "vle32.v v0, (t0)", // Load counter into a register
            "vle32.v v1, (t1)", // Copy all round keys into the vector registers
            "addi t1, t1, 16",
            "vle32.v v2, (t1)",
            "addi t1, t1, 16",
            "vle32.v v3, (t1)",
            "addi t1, t1, 16",
            "vle32.v v4, (t1)",
            "addi t1, t1, 16",
            "vle32.v v5, (t1)",
            "addi t1, t1, 16",
            "vle32.v v6, (t1)",
            "addi t1, t1, 16",
            "vle32.v v7, (t1)",
            "addi t1, t1, 16",
            "vle32.v v8, (t1)",
            "addi t1, t1, 16",
            "vle32.v v9, (t1)",
            "addi t1, t1, 16",
            "vle32.v v10, (t1)",
            "addi t1, t1, 16",
            "vle32.v v11, (t1)",
            "vaesz.vs v0, v1", // Whiten the counter
            "vaesem.vs v0, v2", // Apply 10 rounds of AES
            "vaesem.vs v0, v3",
            "vaesem.vs v0, v4",
            "vaesem.vs v0, v5",
            "vaesem.vs v0, v6",
            "vaesem.vs v0, v7",
            "vaesem.vs v0, v8",
            "vaesem.vs v0, v9",
            "vaesem.vs v0, v10",
            "vaesef.vs v0, v11",
            "vse32.v v0, (t0)", // Store the state
            options(nostack),
            in("t0") state_ptr,
            inout("t1") round_keys_ptr,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
        );

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
    round_keys: RefCell<[u128; AES128_KEY_COUNT]>,
}

impl Drop for Aes128Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        *self.round_keys.borrow_mut() = [0; AES128_KEY_COUNT];
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

    pub(crate) unsafe fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let mut key_0 = [0u8; 16];
        key_0.copy_from_slice(&key[0..16]);

        let counter = u128::from_le_bytes(counter);
        let key = u128::from_le_bytes(key_0);

        let round_keys = aes128_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: RefCell::new(round_keys),
        }
    }

    pub(crate) unsafe fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        let mut key_0 = [0u8; 16];
        key_0.copy_from_slice(&key[0..16]);

        let counter = u128::from_le_bytes(counter);
        let key = u128::from_le_bytes(key_0);

        let round_keys = aes128_key_expansion(key);

        self.counter.set(counter);
        *self.round_keys.borrow_mut() = round_keys;
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.counter.get()
    }

    #[inline(always)]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the counter.
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        // We know that there can't be any other reference to its data, and it will also not
        // store a reference to it somewhere. So it's safe for the ASM to read from it directly.
        // Once there are intrinsic, we can again use the cell type, since then the compiler is 
        // able to optimize the access to it.
        let mut round_keys_ptr = self.round_keys.as_ptr();

        // Initialize the state with the counter.
        let mut state = counter;
        let state_ptr = (&mut state) as *mut u128;

        asm!(
            "vsetivli x0, 4, e32, m1, ta, ma",
            "vle32.v v0, (t0)", // Load counter into a register
            "vle32.v v1, (t1)", // Copy all round keys into the vector registers
            "addi t1, t1, 16",
            "vle32.v v2, (t1)",
            "addi t1, t1, 16",
            "vle32.v v3, (t1)",
            "addi t1, t1, 16",
            "vle32.v v4, (t1)",
            "addi t1, t1, 16",
            "vle32.v v5, (t1)",
            "addi t1, t1, 16",
            "vle32.v v6, (t1)",
            "addi t1, t1, 16",
            "vle32.v v7, (t1)",
            "addi t1, t1, 16",
            "vle32.v v8, (t1)",
            "addi t1, t1, 16",
            "vle32.v v9, (t1)",
            "addi t1, t1, 16",
            "vle32.v v10, (t1)",
            "addi t1, t1, 16",
            "vle32.v v11, (t1)",
            "vaesz.vs v0, v1", // Whiten the counter
            "vaesem.vs v0, v2", // Apply 10 rounds of AES
            "vaesem.vs v0, v3",
            "vaesem.vs v0, v4",
            "vaesem.vs v0, v5",
            "vaesem.vs v0, v6",
            "vaesem.vs v0, v7",
            "vaesem.vs v0, v8",
            "vaesem.vs v0, v9",
            "vaesem.vs v0, v10",
            "vaesef.vs v0, v11",
            "vse32.v v0, (t0)", // Store the state
            options(nostack),
            in("t0") state_ptr,
            inout("t1") round_keys_ptr,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
        );

        // Return the encrypted counter as u128.
        state
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64 {
    counter: Cell<[u64; 2]>,
    round_keys: RefCell<[u128; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr64 {
    fn drop(&mut self) {
        self.counter.set([0, 0]);
        *self.round_keys.borrow_mut() = [0; AES256_KEY_COUNT];
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Aes256Ctr64 {
    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let mut key_0 = [0u8; 16];
        let mut key_1 = [0u8; 16];

        key_0.copy_from_slice(&key[0..16]);
        key_1.copy_from_slice(&key[16..32]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [u128::from_le_bytes(key_0), u128::from_le_bytes(key_1)];

        let round_keys = aes256_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: RefCell::new(round_keys),
        }
    }

    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        let mut key_0 = [0u8; 16];
        let mut key_1 = [0u8; 16];

        key_0.copy_from_slice(&key[0..16]);
        key_1.copy_from_slice(&key[16..32]);

        let counter = [u64::from_le_bytes(counter), u64::from_le_bytes(nonce)];
        let key = [u128::from_le_bytes(key_0), u128::from_le_bytes(key_1)];

        let round_keys = aes256_key_expansion(key);

        self.counter.set(counter);
        *self.round_keys.borrow_mut() = round_keys;
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.counter.get()[0]
    }

    #[inline(always)]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the lower 64 bits.
        let counter = self.counter.get();
        let mut new_counter = counter;
        new_counter[0] = counter[0].wrapping_add(1);
        self.counter.set(new_counter);

        // We know that there can't be any other reference to its data, and it will also not
        // store a reference to it somewhere. So it's safe for the ASM to read from it directly.
        // Once there are intrinsic, we can again use the cell type, since then the compiler is 
        // able to optimize the access to it.
        let mut round_keys_ptr = self.round_keys.as_ptr();

        // Initialize the state with the counter.
        let mut state = counter;
        let state_ptr = (&mut state).as_mut_ptr();

        asm!(
            "vsetivli x0, 4, e32, m1, ta, ma",
            "vle32.v v0, (t0)", // Load counter into a register
            "vle32.v v1, (t1)", // Copy all round keys into the vector registers
            "addi t1, t1, 16",
            "vle32.v v2, (t1)",
            "addi t1, t1, 16",
            "vle32.v v3, (t1)",
            "addi t1, t1, 16",
            "vle32.v v4, (t1)",
            "addi t1, t1, 16",
            "vle32.v v5, (t1)",
            "addi t1, t1, 16",
            "vle32.v v6, (t1)",
            "addi t1, t1, 16",
            "vle32.v v7, (t1)",
            "addi t1, t1, 16",
            "vle32.v v8, (t1)",
            "addi t1, t1, 16",
            "vle32.v v9, (t1)",
            "addi t1, t1, 16",
            "vle32.v v10, (t1)",
            "addi t1, t1, 16",
            "vle32.v v11, (t1)",
            "addi t1, t1, 16",
            "vle32.v v12, (t1)",
            "addi t1, t1, 16",
            "vle32.v v13, (t1)",
            "addi t1, t1, 16",
            "vle32.v v14, (t1)",
            "addi t1, t1, 16",
            "vle32.v v15, (t1)",
            "vaesz.vs v0, v1", // Whiten the counter
            "vaesem.vs v0, v2", // Apply 14 rounds of AES
            "vaesem.vs v0, v3",
            "vaesem.vs v0, v4",
            "vaesem.vs v0, v5",
            "vaesem.vs v0, v6",
            "vaesem.vs v0, v7",
            "vaesem.vs v0, v8",
            "vaesem.vs v0, v9",
            "vaesem.vs v0, v10",
            "vaesem.vs v0, v11",
            "vaesem.vs v0, v12",
            "vaesem.vs v0, v13",
            "vaesem.vs v0, v14",
            "vaesef.vs v0, v15",
            "vse32.v v0, (t0)", // Store the state
            options(nostack),
            in("t0") state_ptr,
            inout("t1") round_keys_ptr,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
        );

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
    round_keys: RefCell<[u128; AES256_KEY_COUNT]>,
}

impl Drop for Aes256Ctr128 {
    fn drop(&mut self) {
        self.counter.set(0);
        *self.round_keys.borrow_mut() = [0; AES256_KEY_COUNT];
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

    pub(crate) unsafe fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let mut key_0 = [0u8; 16];
        let mut key_1 = [0u8; 16];

        key_0.copy_from_slice(&key[0..16]);
        key_1.copy_from_slice(&key[16..32]);

        let counter = u128::from_le_bytes(counter);
        let key = [u128::from_le_bytes(key_0), u128::from_le_bytes(key_1)];

        let round_keys = aes256_key_expansion(key);

        Self {
            counter: Cell::new(counter),
            round_keys: RefCell::new(round_keys),
        }
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.counter.get()
    }

    pub(crate) unsafe fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        let mut key_0 = [0u8; 16];
        let mut key_1 = [0u8; 16];

        key_0.copy_from_slice(&key[0..16]);
        key_1.copy_from_slice(&key[16..32]);

        let counter = u128::from_le_bytes(counter);
        let key = [u128::from_le_bytes(key_0), u128::from_le_bytes(key_1)];

        let round_keys = aes256_key_expansion(key);

        self.counter.set(counter);
        *self.round_keys.borrow_mut() = round_keys;
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        true
    }

    #[inline(always)]
    pub(crate) unsafe fn next_impl(&self) -> u128 {
        // Increment the counter.
        let counter = self.counter.get();
        self.counter.set(counter.wrapping_add(1));

        // We know that there can't be any other reference to its data, and it will also not
        // store a reference to it somewhere. So it's safe for the ASM to read from it directly.
        // Once there are intrinsic, we can again use the cell type, since then the compiler is 
        // able to optimize the access to it.
        let mut round_keys_ptr = self.round_keys.as_ptr();

        // Initialize the state with the counter.
        let mut state = counter;
        let state_ptr = (&mut state) as *mut u128;

        asm!(
            "vsetivli x0, 4, e32, m1, ta, ma",
            "vle32.v v0, (t0)", // Load counter into a register
            "vle32.v v1, (t1)", // Copy all round keys into the vector registers
            "addi t1, t1, 16",
            "vle32.v v2, (t1)",
            "addi t1, t1, 16",
            "vle32.v v3, (t1)",
            "addi t1, t1, 16",
            "vle32.v v4, (t1)",
            "addi t1, t1, 16",
            "vle32.v v5, (t1)",
            "addi t1, t1, 16",
            "vle32.v v6, (t1)",
            "addi t1, t1, 16",
            "vle32.v v7, (t1)",
            "addi t1, t1, 16",
            "vle32.v v8, (t1)",
            "addi t1, t1, 16",
            "vle32.v v9, (t1)",
            "addi t1, t1, 16",
            "vle32.v v10, (t1)",
            "addi t1, t1, 16",
            "vle32.v v11, (t1)",
            "addi t1, t1, 16",
            "vle32.v v12, (t1)",
            "addi t1, t1, 16",
            "vle32.v v13, (t1)",
            "addi t1, t1, 16",
            "vle32.v v14, (t1)",
            "addi t1, t1, 16",
            "vle32.v v15, (t1)",
            "vaesz.vs v0, v1", // Whiten the counter
            "vaesem.vs v0, v2", // Apply 14 rounds of AES
            "vaesem.vs v0, v3",
            "vaesem.vs v0, v4",
            "vaesem.vs v0, v5",
            "vaesem.vs v0, v6",
            "vaesem.vs v0, v7",
            "vaesem.vs v0, v8",
            "vaesem.vs v0, v9",
            "vaesem.vs v0, v10",
            "vaesem.vs v0, v11",
            "vaesem.vs v0, v12",
            "vaesem.vs v0, v13",
            "vaesem.vs v0, v14",
            "vaesef.vs v0, v15",
            "vse32.v v0, (t0)", // Store the state
            options(nostack),
            in("t0") state_ptr,
            inout("t1") round_keys_ptr,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
        );

        // Return the encrypted counter as u128.
        state
    }
}

unsafe fn aes128_key_expansion(key: u128) -> [u128; AES128_KEY_COUNT] {
    let mut expanded_keys = [0u128; AES128_KEY_COUNT];
    let key_ptr = &key as *const u128;
    let mut expanded_ptr = (&mut expanded_keys).as_mut_ptr();

    asm!(
        "vsetivli x0, 4, e32, m4, ta, ma",
        "vle32.v v0, (t0)", // Load key as state and copy into expanded
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 1", // Round 1
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 2", // Round 2
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 3", // Round 3
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 4", // Round 4
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 5", // Round 5
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 6", // Round 6
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 7", // Round 7
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 8", // Round 8
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 9", // Round 9
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf1.vi v0, v0, 10", // Round 10
        "add t1, t1, 16",
        "vse32.v v0, (t1)",
        in("t0") key_ptr,
        inout("t1") expanded_ptr,
        options(nostack),
        out("v0") _,
    );

    expanded_keys
}

unsafe fn aes256_key_expansion(key: [u128; 2]) -> [u128; AES256_KEY_COUNT] {
    let mut expanded_keys = [0u128; AES256_KEY_COUNT];
    let mut key_ptr = &key as *const u128;
    let mut expanded_ptr = (&mut expanded_keys).as_mut_ptr();

    asm!(
        "vsetivli x0, 4, e32, m4, ta, ma",
        "vle32.v v0, (t0)",
        "addi t0, t0, 16",
        "vle32.v v4, (t0)",
        "vse32.v v0, (t1)",
        "add t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 2", // Round 2
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 3", // Round 3
        "addi t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 4", // Round 4
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 5", // Round 5
        "addi t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 6", // Round 6
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 7", // Round 7
        "addi t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 8", // Round 8
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 9", // Round 9
        "addi t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 10", // Round 10
        "addi t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 11", // Round 11
        "add t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 12", // Round 12
        "add t1, t1, 16",
        "vse32.v v0, (t1)",
        "vaeskf2.vi v4, v0, 13", // Round 13
        "add t1, t1, 16",
        "vse32.v v4, (t1)",
        "vaeskf2.vi v0, v4, 14", // Round 14
        "add t1, t1, 16",
        "vse32.v v0, (t1)",
        inout("t0") key_ptr,
        inout("t1") expanded_ptr,
        options(nostack),
        out("v0") _,
        out("v4") _,
    );

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
            let mut key = [0u8; 16];
            key.copy_from_slice(&key[0..16]);
            let key = u128::from_le_bytes(key);

            let expanded: [u128; AES128_KEY_COUNT] = unsafe { aes128_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [u128; AES128_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }

    #[test]
    fn test_aes256_key_expansion() {
        aes256_key_expansion_test(|key| {
            let mut key_0 = [0u8; 16];
            let mut key_1 = [0u8; 16];
            key_0.copy_from_slice(&key[0..16]);
            key_1.copy_from_slice(&key[16..32]);
            let key = [u128::from_le_bytes(key_0), u128::from_le_bytes(key_1)];

            let expanded: [u128; AES256_KEY_COUNT] = unsafe { aes256_key_expansion(key) };
            let expanded: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = unsafe {
                core::mem::transmute::<
                    [u128; AES256_KEY_COUNT],
                    [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
                >(expanded)
            };
            expanded
        });
    }
}
