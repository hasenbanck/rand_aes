//! Seeds are used to properly initialize the provided random number generators.

#[cfg(feature = "getrandom")]
use crate::secure_bytes;

/// Seed for the [`crate::Aes128Ctr64`] PRNG.
#[derive(Clone, Default)]
pub struct Aes128Ctr64Seed([u8; 32]);

impl Aes128Ctr64Seed {
    /// Creates a new seed using a key, nonce and u64 based counter.
    pub fn new(key: [u8; 16], nonce: [u8; 8], counter: u64) -> Self {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(&key);
        seed[16..24].copy_from_slice(&nonce);
        seed[24..32].copy_from_slice(&counter.to_le_bytes());
        Self(seed)
    }

    /// Creates a new seed from the OS provided entropy source.
    #[cfg(feature = "getrandom")]
    pub fn from_entropy() -> Self {
        Aes128Ctr64Seed(secure_bytes())
    }
}

impl AsMut<[u8]> for Aes128Ctr64Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for Aes128Ctr64Seed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 32]> for Aes128Ctr64Seed {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Seed for the [`crate::Aes128Ctr128`] PRNG.
#[derive(Clone, Default)]
pub struct Aes128Ctr128Seed([u8; 32]);

impl Aes128Ctr128Seed {
    /// Creates a new seed using a key and u128 based counter.
    pub fn new(key: [u8; 16], counter: u128) -> Self {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(&key);
        seed[16..32].copy_from_slice(&counter.to_le_bytes());
        Self(seed)
    }

    /// Creates a new seed from the OS provided entropy source.
    #[cfg(feature = "getrandom")]
    pub fn from_entropy() -> Self {
        Aes128Ctr128Seed(secure_bytes())
    }
}

impl AsMut<[u8]> for Aes128Ctr128Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for Aes128Ctr128Seed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 32]> for Aes128Ctr128Seed {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Seed for the [`crate::Aes256Ctr64`] PRNG.
#[derive(Clone)]
pub struct Aes256Ctr64Seed([u8; 48]);

impl Aes256Ctr64Seed {
    /// Creates a new seed using a key, nonce and u64 based counter.
    pub fn new(key: [u8; 32], nonce: [u8; 8], counter: u64) -> Self {
        let mut seed = [0u8; 48];
        seed[..32].copy_from_slice(&key);
        seed[32..40].copy_from_slice(&nonce);
        seed[40..48].copy_from_slice(&counter.to_le_bytes());
        Self(seed)
    }

    /// Creates a new seed from the OS provided entropy source.
    #[cfg(feature = "getrandom")]
    pub fn from_entropy() -> Self {
        Aes256Ctr64Seed(secure_bytes())
    }
}

impl Default for Aes256Ctr64Seed {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl AsMut<[u8]> for Aes256Ctr64Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for Aes256Ctr64Seed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 48]> for Aes256Ctr64Seed {
    fn from(value: [u8; 48]) -> Self {
        Self(value)
    }
}

/// Seed for the [`crate::Aes256Ctr128`] PRNG.
#[derive(Clone)]
pub struct Aes256Ctr128Seed([u8; 48]);

impl Aes256Ctr128Seed {
    /// Creates a new seed using a key and u128 based counter.
    pub fn new(key: [u8; 32], counter: u128) -> Self {
        let mut seed = [0u8; 48];
        seed[..32].copy_from_slice(&key);
        seed[32..48].copy_from_slice(&counter.to_le_bytes());
        Self(seed)
    }

    /// Creates a new seed from the OS provided entropy source.
    #[cfg(feature = "getrandom")]
    pub fn from_entropy() -> Self {
        Aes256Ctr128Seed(secure_bytes())
    }
}

impl Default for Aes256Ctr128Seed {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

impl AsMut<[u8]> for Aes256Ctr128Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl AsRef<[u8]> for Aes256Ctr128Seed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 48]> for Aes256Ctr128Seed {
    fn from(value: [u8; 48]) -> Self {
        Self(value)
    }
}
