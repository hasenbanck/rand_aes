//! Test that verify that the software backend and the hardware backends produce the same random numbers for a given seed.

use crate::constants::{AES128_KEY_SIZE, AES256_KEY_SIZE, AES_BLOCK_SIZE};
use crate::fallback::software::Aes128Ctr128 as Aes128Ctr128Software;
use crate::fallback::software::Aes128Ctr64 as Aes128Ctr64Software;
use crate::fallback::software::Aes256Ctr128 as Aes256Ctr128Software;
use crate::fallback::software::Aes256Ctr64 as Aes256Ctr64Software;
use crate::hardware::Aes128Ctr128 as Aes128Ctr128Hardware;
use crate::hardware::Aes128Ctr64 as Aes128Ctr64Hardware;
use crate::hardware::Aes256Ctr128 as Aes256Ctr128Hardware;
use crate::hardware::Aes256Ctr64 as Aes256Ctr64Hardware;

/// Runs the verification testsuite. Will panic once it finds an error.
#[doc(hidden)]
pub fn run_verification() {
    for i in 0..u8::MAX {
        for j in 0..u8::MAX {
            verify_aes128([i; AES128_KEY_SIZE], [j; AES_BLOCK_SIZE]);
            verify_aes256([i; AES256_KEY_SIZE], [j; AES_BLOCK_SIZE]);
            verify_aes128([i; AES128_KEY_SIZE], [j; AES_BLOCK_SIZE]);
            verify_aes256([i; AES256_KEY_SIZE], [j; AES_BLOCK_SIZE]);
        }
    }
}

fn verify_aes128(key: [u8; AES128_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    verify_aes128_ctr64(key, iv);
    verify_aes128_ctr128(key, iv);
}

fn verify_aes256(key: [u8; AES256_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    verify_aes256_ctr64(key, iv);
    verify_aes256_ctr128(key, iv);
}

fn verify_aes128_ctr64(key: [u8; AES128_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    let mut ctr = [0u8; 8];
    let mut nonce = [0u8; 8];
    ctr.copy_from_slice(&iv[0..8]);
    nonce.copy_from_slice(&iv[8..16]);

    let mut software = Aes128Ctr64Software::from_seed_impl(key, nonce, ctr);
    let hardware = unsafe { Aes128Ctr64Hardware::from_seed_impl(key, nonce, ctr) };

    for _ in 0..u8::MAX {
        assert_eq!(software.next_impl(), unsafe { hardware.next_impl() });
    }
}

fn verify_aes128_ctr128(key: [u8; AES128_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    let mut software = Aes128Ctr128Software::from_seed_impl(key, iv);
    let hardware = unsafe { Aes128Ctr128Hardware::from_seed_impl(key, iv) };

    for _ in 0..u8::MAX {
        assert_eq!(software.next_impl(), unsafe { hardware.next_impl() });
    }
}

fn verify_aes256_ctr64(key: [u8; AES256_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    let mut ctr = [0u8; 8];
    let mut nonce = [0u8; 8];
    ctr.copy_from_slice(&iv[0..8]);
    nonce.copy_from_slice(&iv[8..16]);

    let mut software = Aes256Ctr64Software::from_seed_impl(key, nonce, ctr);
    let hardware = unsafe { Aes256Ctr64Hardware::from_seed_impl(key, nonce, ctr) };

    for _ in 0..u8::MAX {
        assert_eq!(software.next_impl(), unsafe { hardware.next_impl() });
    }
}

fn verify_aes256_ctr128(key: [u8; AES256_KEY_SIZE], iv: [u8; AES_BLOCK_SIZE]) {
    let mut software = Aes256Ctr128Software::from_seed_impl(key, iv);
    let hardware = unsafe { Aes256Ctr128Hardware::from_seed_impl(key, iv) };

    for _ in 0..u8::MAX {
        assert_eq!(software.next_impl(), unsafe { hardware.next_impl() });
    }
}
