use crate::{seeds, Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64, Jump, Random};

#[cfg(feature = "getrandom")]
use crate::secure_bytes;

macro_rules! safely_call {
    ($what:expr) => {
        #[cfg(not(feature = "force_fallback"))]
        unsafe {
            $what
        }

        #[cfg(feature = "force_fallback")]
        $what
    };
}

impl core::fmt::Debug for Aes128Ctr64 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes128Ctr64").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes128Ctr128 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes128Ctr128").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes256Ctr64 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes256Ctr64").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Aes256Ctr128 {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("Aes256Ctr128").finish_non_exhaustive()
    }
}

impl Random for Aes128Ctr64 {
    type Seed = seeds::Aes128Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[16..24]);
        counter_bytes.copy_from_slice(&seed.as_ref()[24..32]);

        safely_call! { Aes128Ctr64::from_seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[16..24]);
        counter_bytes.copy_from_slice(&seed.as_ref()[24..32]);

        safely_call! { self.seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 32] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes128Ctr64::next_impl(self) }
    }
}

impl Random for Aes128Ctr128 {
    type Seed = seeds::Aes128Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 16];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        counter_bytes.copy_from_slice(&seed.as_ref()[16..32]);

        safely_call! { Aes128Ctr128::from_seed_impl(seed_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 16];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..16]);
        counter_bytes.copy_from_slice(&seed.as_ref()[16..32]);

        safely_call! { self.seed_impl(seed_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 32] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes128Ctr128::next_impl(self) }
    }
}

impl Random for Aes256Ctr64 {
    type Seed = seeds::Aes256Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[32..40]);
        counter_bytes.copy_from_slice(&seed.as_ref()[40..48]);

        safely_call! { Aes256Ctr64::from_seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 8];
        let mut counter_bytes = [0u8; 8];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        nonce_bytes.copy_from_slice(&seed.as_ref()[32..40]);
        counter_bytes.copy_from_slice(&seed.as_ref()[40..48]);

        safely_call! { self.seed_impl(seed_bytes, nonce_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 48] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes256Ctr64::next_impl(self) }
    }
}

impl Random for Aes256Ctr128 {
    type Seed = seeds::Aes256Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut seed_bytes = [0u8; 32];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        counter_bytes.copy_from_slice(&seed.as_ref()[32..48]);

        safely_call! { Aes256Ctr128::from_seed_impl(seed_bytes, counter_bytes) }
    }

    fn seed(&self, seed: Self::Seed) {
        let mut seed_bytes = [0u8; 32];
        let mut counter_bytes = [0u8; 16];

        seed_bytes.copy_from_slice(&seed.as_ref()[..32]);
        counter_bytes.copy_from_slice(&seed.as_ref()[32..48]);

        safely_call! { self.seed_impl(seed_bytes, counter_bytes) }
    }

    #[cfg(feature = "getrandom")]
    fn from_entropy() -> Self {
        let bytes: [u8; 48] = secure_bytes();
        Random::from_seed(bytes.into())
    }

    #[cfg(feature = "getrandom")]
    fn seed_from_entropy(&self) {
        safely_call! { self.seed_impl(secure_bytes(), secure_bytes()) }
    }

    fn is_hardware_accelerated(&self) -> bool {
        self.is_hardware_accelerated_impl()
    }

    #[inline(always)]
    fn next(&self) -> u128 {
        safely_call! { Aes256Ctr128::next_impl(self) }
    }
}

impl Jump for Aes128Ctr128 {
    fn jump(&self) -> Self {
        self.jump_impl()
    }

    fn long_jump(&self) -> Self {
        self.long_jump_impl()
    }
}

impl Jump for Aes256Ctr128 {
    fn jump(&self) -> Self {
        self.jump_impl()
    }

    fn long_jump(&self) -> Self {
        self.long_jump_impl()
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes128Ctr64 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes128Ctr128 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes256Ctr64 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::RngCore for Aes256Ctr128 {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        safely_call! { self.next_impl() as u32 }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        safely_call! { self.next_impl() as u64 }
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::fill_bytes(self, dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Random::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes128Ctr64 {
    type Seed = seeds::Aes128Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes128Ctr128 {
    type Seed = seeds::Aes128Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes256Ctr64 {
    type Seed = seeds::Aes256Ctr64Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::SeedableRng for Aes256Ctr128 {
    type Seed = seeds::Aes256Ctr128Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Random::from_seed(seed)
    }
}
