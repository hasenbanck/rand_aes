//! The fixed fallback, when STD is not available or the platform has no hardware based AES support.
use core::cell::RefCell;

use super::software::Aes128Ctr128 as Aes128Ctr128Software;
use super::software::Aes128Ctr64 as Aes128Ctr64Software;
use super::software::Aes256Ctr128 as Aes256Ctr128Software;
use super::software::Aes256Ctr64 as Aes256Ctr64Software;

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64(RefCell<Aes128Ctr64Software>);

impl Aes128Ctr64 {
    #[cfg(feature = "tls")]
    pub(crate) fn zeroed() -> Self {
        let software = Aes128Ctr64Software::zeroed();
        Self(RefCell::new(software))
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let software = Aes128Ctr64Software::from_seed_impl(key, nonce, counter);
        Self(RefCell::new(software))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        self.0.borrow_mut().seed_impl(key, nonce, counter);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        self.0.borrow_mut().is_hardware_accelerated_impl()
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.0.borrow_mut().counter_impl()
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        self.0.borrow_mut().next_impl()
    }
}

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr128(RefCell<Aes128Ctr128Software>);

impl Aes128Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.0.borrow_mut().jump_impl();
        Self(RefCell::new(clone))
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.0.borrow_mut().long_jump_impl();
        Self(RefCell::new(clone))
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        let software = Aes128Ctr128Software::from_seed_impl(key, counter);
        Self(RefCell::new(software))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        self.0.borrow_mut().seed_impl(key, counter);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        self.0.borrow_mut().is_hardware_accelerated_impl()
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.0.borrow_mut().counter_impl()
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        self.0.borrow_mut().next_impl()
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64(RefCell<Aes256Ctr64Software>);

impl Aes256Ctr64 {
    pub(crate) fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        let software = Aes256Ctr64Software::from_seed_impl(key, nonce, counter);
        Self(RefCell::new(software))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        self.0.borrow_mut().seed_impl(key, nonce, counter);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        self.0.borrow_mut().is_hardware_accelerated_impl()
    }

    pub(crate) fn counter_impl(&self) -> u64 {
        self.0.borrow_mut().counter_impl()
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        self.0.borrow_mut().next_impl()
    }
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr128(RefCell<Aes256Ctr128Software>);

impl Aes256Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let clone = self.0.borrow_mut().jump_impl();
        Self(RefCell::new(clone))
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let clone = self.0.borrow_mut().long_jump_impl();
        Self(RefCell::new(clone))
    }

    pub(crate) fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        let software = Aes256Ctr128Software::from_seed_impl(key, counter);
        Self(RefCell::new(software))
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        self.0.borrow_mut().seed_impl(key, counter);
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        self.0.borrow_mut().is_hardware_accelerated_impl()
    }

    pub(crate) fn counter_impl(&self) -> u128 {
        self.0.borrow_mut().counter_impl()
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        self.0.borrow_mut().next_impl()
    }
}
