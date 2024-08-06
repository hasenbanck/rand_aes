#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};
#[cfg(target_arch = "riscv64")]
pub use riscv64::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};
#[cfg(target_arch = "x86_64")]
pub use x86_64::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    test,
    not(any(
        not(any(
            all(
                target_arch = "x86_64",
                target_feature = "sse2",
                target_feature = "aes",
            ),
            all(target_arch = "riscv64", feature = "experimental_riscv"),
            all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "aes",
            ),
        )),
        feature = "force_fallback"
    ))
))]
mod tests {
    use super::*;
    use crate::constants::{
        AES128_KEY_COUNT, AES128_KEY_SIZE, AES256_KEY_COUNT, AES256_KEY_SIZE, AES_BLOCK_SIZE,
    };
    use hex_literal::hex;

    // From NIST FIPS 197
    const TV_AES128_KEY: [u8; AES128_KEY_SIZE] = hex!("000102030405060708090a0b0c0d0e0f");
    const TV_AES128_IV: [u8; AES_BLOCK_SIZE] = hex!("00112233445566778899aabbccddeeff");
    const TV_AES128_ROUND_KEYS: [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT] = [
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("d6aa74fdd2af72fadaa678f1d6ab76fe"),
        hex!("b692cf0b643dbdf1be9bc5006830b3fe"),
        hex!("b6ff744ed2c2c9bf6c590cbf0469bf41"),
        hex!("47f7f7bc95353e03f96c32bcfd058dfd"),
        hex!("3caaa3e8a99f9deb50f3af57adf622aa"),
        hex!("5e390f7df7a69296a7553dc10aa31f6b"),
        hex!("14f9701ae35fe28c440adf4d4ea9c026"),
        hex!("47438735a41c65b9e016baf4aebf7ad2"),
        hex!("549932d1f08557681093ed9cbe2c974e"),
        hex!("13111d7fe3944a17f307a78b4d2b30c5"),
    ];
    const TV_AES128_NEXT_0: [u8; AES_BLOCK_SIZE] = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
    const TV_AES128_NEXT_1: [u8; AES_BLOCK_SIZE] = hex!("a556156c72876577f67f95a9d9e640a7");

    // From NIST FIPS 197
    const TV_AES256_KEY: [u8; AES256_KEY_SIZE] =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const TV_AES256_IV: [u8; AES_BLOCK_SIZE] = hex!("00112233445566778899aabbccddeeff");
    const TV_AES256_ROUND_KEYS: [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT] = [
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("101112131415161718191a1b1c1d1e1f"),
        hex!("a573c29fa176c498a97fce93a572c09c"),
        hex!("1651a8cd0244beda1a5da4c10640bade"),
        hex!("ae87dff00ff11b68a68ed5fb03fc1567"),
        hex!("6de1f1486fa54f9275f8eb5373b8518d"),
        hex!("c656827fc9a799176f294cec6cd5598b"),
        hex!("3de23a75524775e727bf9eb45407cf39"),
        hex!("0bdc905fc27b0948ad5245a4c1871c2f"),
        hex!("45f5a66017b2d387300d4d33640a820a"),
        hex!("7ccff71cbeb4fe5413e6bbf0d261a7df"),
        hex!("f01afafee7a82979d7a5644ab3afe640"),
        hex!("2541fe719bf500258813bbd55a721c0a"),
        hex!("4e5a6699a9f24fe07e572baacdf8cdea"),
        hex!("24fc79ccbf0979e9371ac23c6d68de36"),
    ];
    const TV_AES256_NEXT_0: [u8; AES_BLOCK_SIZE] = hex!("8ea2b7ca516745bfeafc49904b496089");
    const TV_AES256_NEXT_1: [u8; AES_BLOCK_SIZE] = hex!("81ae7d5e4138bf730d2a8871fec2cd0c");

    pub(crate) fn aes128_key_expansion_test<F>(expansion: F)
    where
        F: FnOnce([u8; AES128_KEY_SIZE]) -> [[u8; AES_BLOCK_SIZE]; AES128_KEY_COUNT],
    {
        let expanded = expansion(TV_AES128_KEY);

        for (exp, act) in TV_AES128_ROUND_KEYS.iter().zip(expanded.iter()) {
            assert_eq!(exp, act);
        }
    }

    pub(crate) fn aes256_key_expansion_test<F>(expansion: F)
    where
        F: FnOnce([u8; AES256_KEY_SIZE]) -> [[u8; AES_BLOCK_SIZE]; AES256_KEY_COUNT],
    {
        let expanded = expansion(TV_AES256_KEY);

        for (exp, act) in TV_AES256_ROUND_KEYS.iter().zip(expanded.iter()) {
            assert_eq!(exp, act);
        }
    }

    #[test]
    fn test_aes128_64_ctr() {
        let mut ctr = [0u8; 8];
        let mut nonce = [0u8; 8];
        ctr.copy_from_slice(&TV_AES128_IV[0..8]);
        nonce.copy_from_slice(&TV_AES128_IV[8..16]);

        let prng = unsafe { Aes128Ctr64::from_seed_impl(TV_AES128_KEY, nonce, ctr) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_1);
    }

    #[test]
    fn test_aes128_128_ctr() {
        let prng = unsafe { Aes128Ctr128::from_seed_impl(TV_AES128_KEY, TV_AES128_IV) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES128_NEXT_1);
    }

    #[test]
    fn test_aes256_64_ctr() {
        let mut ctr = [0u8; 8];
        let mut nonce = [0u8; 8];
        ctr.copy_from_slice(&TV_AES256_IV[0..8]);
        nonce.copy_from_slice(&TV_AES256_IV[8..16]);

        let prng = unsafe { Aes256Ctr64::from_seed_impl(TV_AES256_KEY, nonce, ctr) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_1);
    }

    #[test]
    fn test_aes256_128_ctr() {
        let prng = unsafe { Aes256Ctr128::from_seed_impl(TV_AES256_KEY, TV_AES256_IV) };

        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_0);
        assert_eq!(unsafe { prng.next_impl().to_le_bytes() }, TV_AES256_NEXT_1);
    }
}
