//! The dynamic fallback, when STD is available or the platform has hardware based AES support.
use core::cell::RefCell;

use crate::hardware::{
    Aes128Ctr128 as Aes128Ctr128Hardware, Aes128Ctr64 as Aes128Ctr64Hardware,
    Aes256Ctr128 as Aes256Ctr128Hardware, Aes256Ctr64 as Aes256Ctr64Hardware,
};

use crate::fallback::software::Aes128Ctr128 as Aes128Ctr128Fallback;
use crate::fallback::software::Aes128Ctr64 as Aes128Ctr64Fallback;
use crate::fallback::software::Aes256Ctr128 as Aes256Ctr128Fallback;
use crate::fallback::software::Aes256Ctr64 as Aes256Ctr64Fallback;

#[allow(unused)]
pub(crate) fn has_hardware_acceleration() -> bool {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse2") && std::arch::is_x86_feature_detected!("aes") {
        return true;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("aes")
    {
        return true;
    }
    #[cfg(target_arch = "riscv64")]
    if std::arch::is_riscv_feature_detected!("zkne") {
        return true;
    }

    false
}

#[derive(Clone)]
enum Aes128Ctr64Inner {
    Hardware(Box<Aes128Ctr64Hardware>),
    Fallback(Box<RefCell<Aes128Ctr64Fallback>>),
}

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr64(Aes128Ctr64Inner);

impl Aes128Ctr64 {
    // This function is needed for the TLS.
    pub(crate) fn zeroed() -> Self {
        match has_hardware_acceleration() {
            true => {
                // Safety: We checked that the hardware acceleration is available.
                let hardware = Aes128Ctr64Hardware::zeroed();
                Self(Aes128Ctr64Inner::Hardware(Box::new(hardware)))
            }
            false => {
                let fallback = Aes128Ctr64Fallback::zeroed();
                Self(Aes128Ctr64Inner::Fallback(Box::new(RefCell::new(fallback))))
            }
        }
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        match has_hardware_acceleration() {
            true => {
                // Safety: We checked that the hardware acceleration is available.
                let hardware = unsafe { Aes128Ctr64Hardware::from_seed_impl(key, nonce, counter) };
                Self(Aes128Ctr64Inner::Hardware(Box::new(hardware)))
            }
            false => {
                let fallback = Aes128Ctr64Fallback::from_seed_impl(key, nonce, counter);
                Self(Aes128Ctr64Inner::Fallback(Box::new(RefCell::new(fallback))))
            }
        }
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], nonce: [u8; 8], counter: [u8; 8]) {
        match &self.0 {
            Aes128Ctr64Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.seed_impl(key, nonce, counter) };
            }
            Aes128Ctr64Inner::Fallback(this) => {
                this.borrow_mut().seed_impl(key, nonce, counter);
            }
        }
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        match &self.0 {
            Aes128Ctr64Inner::Hardware(this) => this.is_hardware_accelerated_impl(),
            Aes128Ctr64Inner::Fallback(this) => this.borrow().is_hardware_accelerated_impl(),
        }
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        match &self.0 {
            Aes128Ctr64Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.next_impl() }
            }
            Aes128Ctr64Inner::Fallback(this) => this.borrow_mut().next_impl(),
        }
    }
}

#[derive(Clone)]
enum Aes128Ctr128Inner {
    Hardware(Box<Aes128Ctr128Hardware>),
    Fallback(Box<RefCell<Aes128Ctr128Fallback>>),
}

/// A random number generator based on the AES-128 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 10 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes128Ctr128(Aes128Ctr128Inner);

impl Aes128Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let inner = match &self.0 {
            Aes128Ctr128Inner::Hardware(this) => {
                Aes128Ctr128Inner::Hardware(Box::new(this.jump_impl()))
            }
            Aes128Ctr128Inner::Fallback(this) => {
                Aes128Ctr128Inner::Fallback(Box::new(RefCell::new(this.borrow_mut().jump_impl())))
            }
        };
        Self(inner)
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let inner = match &self.0 {
            Aes128Ctr128Inner::Hardware(this) => {
                Aes128Ctr128Inner::Hardware(Box::new(this.long_jump_impl()))
            }
            Aes128Ctr128Inner::Fallback(this) => Aes128Ctr128Inner::Fallback(Box::new(
                RefCell::new(this.borrow_mut().long_jump_impl()),
            )),
        };
        Self(inner)
    }

    pub(crate) fn from_seed_impl(key: [u8; 16], counter: [u8; 16]) -> Self {
        match has_hardware_acceleration() {
            true => {
                // Safety: We checked that the hardware acceleration is available.
                let hardware = unsafe { Aes128Ctr128Hardware::from_seed_impl(key, counter) };
                Self(Aes128Ctr128Inner::Hardware(Box::new(hardware)))
            }
            false => {
                let fallback = Aes128Ctr128Fallback::from_seed_impl(key, counter);
                Self(Aes128Ctr128Inner::Fallback(Box::new(RefCell::new(
                    fallback,
                ))))
            }
        }
    }

    pub(crate) fn seed_impl(&self, key: [u8; 16], counter: [u8; 16]) {
        match &self.0 {
            Aes128Ctr128Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.seed_impl(key, counter) };
            }
            Aes128Ctr128Inner::Fallback(this) => {
                this.borrow_mut().seed_impl(key, counter);
            }
        }
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        match &self.0 {
            Aes128Ctr128Inner::Hardware(this) => this.is_hardware_accelerated_impl(),
            Aes128Ctr128Inner::Fallback(this) => this.borrow().is_hardware_accelerated_impl(),
        }
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        match &self.0 {
            Aes128Ctr128Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.next_impl() }
            }
            Aes128Ctr128Inner::Fallback(this) => this.borrow_mut().next_impl(),
        }
    }
}

#[derive(Clone)]
enum Aes256Ctr64Inner {
    Hardware(Box<Aes256Ctr64Hardware>),
    Fallback(Box<RefCell<Aes256Ctr64Fallback>>),
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 64-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr64(Aes256Ctr64Inner);

impl Aes256Ctr64 {
    pub(crate) fn from_seed_impl(key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) -> Self {
        match has_hardware_acceleration() {
            true => {
                // Safety: We checked that the hardware acceleration is available.
                let hardware = unsafe { Aes256Ctr64Hardware::from_seed_impl(key, nonce, counter) };
                Self(Aes256Ctr64Inner::Hardware(Box::new(hardware)))
            }
            false => {
                let fallback = Aes256Ctr64Fallback::from_seed_impl(key, nonce, counter);
                Self(Aes256Ctr64Inner::Fallback(Box::new(RefCell::new(fallback))))
            }
        }
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], nonce: [u8; 8], counter: [u8; 8]) {
        match &self.0 {
            Aes256Ctr64Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.seed_impl(key, nonce, counter) };
            }
            Aes256Ctr64Inner::Fallback(this) => {
                this.borrow_mut().seed_impl(key, nonce, counter);
            }
        }
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        match &self.0 {
            Aes256Ctr64Inner::Hardware(this) => this.is_hardware_accelerated_impl(),
            Aes256Ctr64Inner::Fallback(this) => this.borrow().is_hardware_accelerated_impl(),
        }
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        match &self.0 {
            Aes256Ctr64Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.next_impl() }
            }
            Aes256Ctr64Inner::Fallback(this) => this.borrow_mut().next_impl(),
        }
    }
}

#[derive(Clone)]
enum Aes256Ctr128Inner {
    Hardware(Box<Aes256Ctr128Hardware>),
    Fallback(Box<RefCell<Aes256Ctr128Fallback>>),
}

/// A random number generator based on the AES-256 block cipher that runs in CTR mode and has a
/// period of 128-bit.
///
/// The full 14 rounds of encryption are used.
#[derive(Clone)]
pub struct Aes256Ctr128(Aes256Ctr128Inner);

impl Aes256Ctr128 {
    pub(crate) fn jump_impl(&self) -> Self {
        let inner = match &self.0 {
            Aes256Ctr128Inner::Hardware(this) => {
                Aes256Ctr128Inner::Hardware(Box::new(this.jump_impl()))
            }
            Aes256Ctr128Inner::Fallback(this) => {
                Aes256Ctr128Inner::Fallback(Box::new(RefCell::new(this.borrow_mut().jump_impl())))
            }
        };
        Self(inner)
    }

    pub(crate) fn long_jump_impl(&self) -> Self {
        let inner = match &self.0 {
            Aes256Ctr128Inner::Hardware(this) => {
                Aes256Ctr128Inner::Hardware(Box::new(this.long_jump_impl()))
            }
            Aes256Ctr128Inner::Fallback(this) => Aes256Ctr128Inner::Fallback(Box::new(
                RefCell::new(this.borrow_mut().long_jump_impl()),
            )),
        };
        Self(inner)
    }

    pub(crate) fn from_seed_impl(key: [u8; 32], counter: [u8; 16]) -> Self {
        match has_hardware_acceleration() {
            true => {
                // Safety: We checked that the hardware acceleration is available.
                let hardware = unsafe { Aes256Ctr128Hardware::from_seed_impl(key, counter) };
                Self(Aes256Ctr128Inner::Hardware(Box::new(hardware)))
            }
            false => {
                let fallback = Aes256Ctr128Fallback::from_seed_impl(key, counter);
                Self(Aes256Ctr128Inner::Fallback(Box::new(RefCell::new(
                    fallback,
                ))))
            }
        }
    }

    pub(crate) fn seed_impl(&self, key: [u8; 32], counter: [u8; 16]) {
        match &self.0 {
            Aes256Ctr128Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.seed_impl(key, counter) };
            }
            Aes256Ctr128Inner::Fallback(this) => {
                this.borrow_mut().seed_impl(key, counter);
            }
        }
    }

    pub(crate) fn is_hardware_accelerated_impl(&self) -> bool {
        match &self.0 {
            Aes256Ctr128Inner::Hardware(this) => this.is_hardware_accelerated_impl(),
            Aes256Ctr128Inner::Fallback(this) => this.borrow().is_hardware_accelerated_impl(),
        }
    }

    #[inline(always)]
    pub(crate) fn next_impl(&self) -> u128 {
        match &self.0 {
            Aes256Ctr128Inner::Hardware(this) => {
                // Safety: We checked that the hardware acceleration is available.
                unsafe { this.next_impl() }
            }
            Aes256Ctr128Inner::Fallback(this) => this.borrow_mut().next_impl(),
        }
    }
}
