use core::ops::{Bound, RangeBounds};

macro_rules! range_integer {
    ($fn:tt, $target:tt, $base:tt, $tmp:tt, $doc:tt) => {
        #[doc = $doc]
        #[inline(always)]
        fn $fn<T: RangeBounds<$target>>(&self, range: T) -> $target {
            let low = match range.start_bound() {
                Bound::Included(&x) => x,
                Bound::Excluded(&x) => x.checked_add(1).unwrap_or_else(|| {
                    panic!(
                        "start is invalid: {:?}..{:?}",
                        range.start_bound(),
                        range.end_bound()
                    )
                }),
                Bound::Unbounded => $target::MIN,
            };

            let high = match range.end_bound() {
                Bound::Included(&x) => x,
                Bound::Excluded(&x) => x.checked_sub(1).unwrap_or_else(|| {
                    panic!(
                        "end is invalid: {:?}..{:?}",
                        range.start_bound(),
                        range.end_bound()
                    )
                }),
                Bound::Unbounded => $target::MAX,
            };

            if low > high {
                panic!(
                    "start is bigger than end: {:?}..{:?}",
                    range.start_bound(),
                    range.end_bound()
                );
            }

            if low == $target::MIN && high == $target::MAX {
                self.next() as $target
            } else {
                let range = high.wrapping_sub(low).wrapping_add(1) as $base;

                // As described in "Fast Random Integer Generation in an Interval" by Daniel Lemire.
                // <https://arxiv.org/abs/1805.10941>
                let mut x = self.next() as $base;
                let mut result = (x as $tmp).wrapping_mul(range as $tmp);
                let mut leftover = result as $base;
                if leftover < range {
                    let threshold = range.wrapping_neg() % range;
                    while leftover < threshold {
                        x = self.next() as $base;
                        result = (x as $tmp).wrapping_mul(range as $tmp);
                        leftover = result as $base;
                    }
                }

                low.wrapping_add((result >> $base::BITS) as $target)
            }
        }
    };
}

/// Provides common jump functionality to RNG with 128-bit period.
pub trait Jump {
    /// Returns a clone of this RNG and advances the counter of itself by 2^64, equivalent to
    /// generating 2^64 random numbers.
    ///
    /// This can be used to create 2^64 non-overlapping subsequences for parallel computations.
    ///
    /// Note: 2^64 is approximately 18.4 quintillion (1.84 × 10^19).
    /// For perspective, if you generated 1 billion numbers per second,
    /// it would take about 584 years to generate 2^64 numbers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rand_aes::*;
    ///
    /// let mut rng0 = Aes128Ctr128::from_entropy();
    /// let mut rng1 = rng1.long_jump(); // Returns a clone and advances rng0 by 2^64 steps
    /// let mut rng2 = rng1.long_jump(); // Returns a clone and advances rng0 by additional 2^64 steps
    ///
    /// let period = 1u128 << 64;
    /// assert_eq!(rng1.counter(), 0);
    /// assert_eq!(rng2.counter(), period);
    /// assert_eq!(rng0.counter(), period * 2);
    /// ```
    fn jump(&self) -> Self;

    /// Returns a clone of this RNG and advances the counter of itself by 2^96, equivalent to
    /// generating 2^96 random numbers.
    ///
    /// This can be used to create 2^32 non-overlapping subsequences for parallel computations.
    ///
    /// Note: 2^96 is approximately 79 octillion (7.9 × 10^28).
    /// At 1 billion numbers per second, it would take about 2.5 trillion years
    /// to generate 2^96 numbers, far exceeding the age of the universe.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rand_aes::*;
    ///
    /// let mut rng0 = Aes128Ctr128::from_entropy();
    /// let mut rng1 = rng1.long_jump(); // Returns a clone and advances rng1 by 2^96 steps
    /// let mut rng2 = rng1.long_jump(); // Returns a clone and advances rng1 by further 2^96 steps
    ///
    /// let period = 1u128 << 96;
    /// assert_eq!(rng1.counter(), 0);
    /// assert_eq!(rng2.counter(), period);
    /// assert_eq!(rng0.counter(), period * 2);
    fn long_jump(&self) -> Self;
}

/// Provides common random number generation functionality.
pub trait Random {
    type Seed;
    type Counter;

    /// Creates a new random number generator using the given seed.
    fn from_seed(seed: Self::Seed) -> Self;

    /// Seeds the random number generator using the given seed.
    fn seed(&self, seed: Self::Seed);

    #[cfg(feature = "getrandom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
    /// Creates a new random number generator using a seed from the entropy source of the OS.
    fn from_entropy() -> Self;

    #[cfg(feature = "getrandom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
    /// Seeds the random number generator from the entropy source of the OS.
    fn seed_from_entropy(&self);

    /// Returns `true` if the random number generator is using hardware accelerated AES.
    fn is_hardware_accelerated(&self) -> bool;

    /// Returns the current counter value of the PRNG. This value should be treated as confidential.
    fn counter(&self) -> Self::Counter;

    /// Generates the next `u128` value.
    fn next(&self) -> u128;

    /// Generates a random `u8` value.
    fn u8(&self) -> u8 {
        self.next() as u8
    }

    /// Generates a random `u16` value.
    fn u16(&self) -> u16 {
        self.next() as u16
    }

    /// Generates a random `u32` value.
    fn u32(&self) -> u32 {
        self.next() as u32
    }

    /// Generates a random `u64` value.
    fn u64(&self) -> u64 {
        self.next() as u64
    }

    /// Generates a random `u128` value.
    fn u128(&self) -> u128 {
        self.next()
    }

    /// Generates a random `usize` value.
    fn usize(&self) -> usize {
        self.next() as usize
    }

    /// Generates a random `i8` value.
    fn i8(&self) -> i8 {
        self.next() as i8
    }

    /// Generates a random `i16` value.
    fn i16(&self) -> i16 {
        self.next() as i16
    }

    /// Generates a random `i32` value.
    fn i32(&self) -> i32 {
        self.next() as i32
    }

    /// Generates a random `i64` value.
    fn i64(&self) -> i64 {
        self.next() as i64
    }

    /// Generates a random `i128` value.
    fn i128(&self) -> i128 {
        self.next() as i128
    }

    /// Generates a random `isize` value.
    fn isize(&self) -> isize {
        self.next() as isize
    }

    /// Generates a random `bool` value.
    fn bool(&self) -> bool {
        self.next() as usize % 2 == 0
    }

    /// Generates a random f32 value in the range of 0..1.
    fn f32(&self) -> f32 {
        ((self.u32() >> 8) as f32) * 0.000000059604645
    }

    /// Generates a random f64 value in the range of 0..1.
    fn f64(&self) -> f64 {
        ((self.u64() >> 11) as f64) * 0.00000000000000011102230246251565
    }

    /// Randomly shuffles a slice.
    fn shuffle<T>(&self, slice: &mut [T]) {
        for i in 1..slice.len() {
            slice.swap(i, self.range_usize(..=i));
        }
    }

    /// Fills a mutable `[u8]` slice with random bytes.
    fn fill_bytes(&self, slice: &mut [u8]) {
        const SIZE_BYTES: usize = (u128::BITS / 8) as usize;

        let mut chunks = slice.chunks_exact_mut(SIZE_BYTES);
        for chunk in &mut chunks {
            let random_bytes: [u8; SIZE_BYTES] = self.next().to_le_bytes();
            chunk.copy_from_slice(&random_bytes)
        }
        chunks
            .into_remainder()
            .iter_mut()
            .for_each(|x| *x = self.next() as u8);
    }

    /// Generates an array filled with random bytes.
    fn byte_array<const N: usize>(&self) -> [u8; N] {
        let mut buffer = [0; N];
        self.fill_bytes(&mut buffer);
        buffer
    }

    /// Generates a random u8 value in the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_u8()`] instead for no bias.
    fn mod_u8(&self, n: u8) -> u8 {
        (self.next() as u8 as u16)
            .wrapping_mul(n as u16)
            .wrapping_shr(8) as u8
    }

    /// Generates a random u16 value in the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_u16()`] instead for no bias.
    fn mod_u16(&self, n: u16) -> u16 {
        (self.next() as u16 as u32)
            .wrapping_mul(n as u32)
            .wrapping_shr(16) as u16
    }

    /// Generates a random u32 value in the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_u32()`] instead for no bias.
    fn mod_u32(&self, n: u32) -> u32 {
        (self.next() as u32 as u64)
            .wrapping_mul(n as u64)
            .wrapping_shr(32) as u32
    }

    /// Generates a random u64 value in the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_u64()`] instead for no bias.
    fn mod_u64(&self, n: u64) -> u64 {
        (self.next() as u64 as u128)
            .wrapping_mul(n as u128)
            .wrapping_shr(64) as u64
    }

    #[cfg(target_pointer_width = "16")]
    /// Generates a random usize value in the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_usize()`] instead for no bias.
    fn mod_usize(&self, n: usize) -> usize {
        (self.next() as u16 as u32)
            .wrapping_mul(n as u32)
            .wrapping_shr(16) as usize
    }

    #[cfg(target_pointer_width = "32")]
    /// Generates a random usize value the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_usize()`] instead for no bias.
    fn mod_usize(&self, n: usize) -> usize {
        (self.next() as u32 as u64)
            .wrapping_mul(n as u64)
            .wrapping_shr(32) as usize
    }

    #[cfg(target_pointer_width = "64")]
    /// Generates a random usize value the range of 0..n.
    ///
    /// # Notice
    /// This has a very slight bias. Use [`Random::range_usize()`] instead for no bias.
    fn mod_usize(&self, n: usize) -> usize {
        (self.next() as u64 as u128)
            .wrapping_mul(n as u128)
            .wrapping_shr(64) as usize
    }

    range_integer!(
        range_u8,
        u8,
        u8,
        u16,
        "Generates a random u8 value in the given range."
    );

    range_integer!(
        range_u16,
        u16,
        u16,
        u32,
        "Generates a random u16 value in the given range."
    );

    range_integer!(
        range_u32,
        u32,
        u32,
        u64,
        "Generates a random u32 value in the given range."
    );

    range_integer!(
        range_u64,
        u64,
        u64,
        u128,
        "Generates a random u64 value in the given range."
    );

    #[cfg(target_pointer_width = "16")]
    range_integer!(
        range_usize,
        usize,
        u16,
        u32,
        "Generates a random usize value in the given range."
    );

    #[cfg(target_pointer_width = "32")]
    range_integer!(
        range_usize,
        usize,
        u32,
        u64,
        "Generates a random usize value in the given range."
    );

    #[cfg(target_pointer_width = "64")]
    range_integer!(
        range_usize,
        usize,
        u64,
        u128,
        "Generates a random usize value in the given range."
    );

    range_integer!(
        range_i8,
        i8,
        u8,
        u16,
        "Generates a random i8 value in the given range."
    );

    range_integer!(
        range_i16,
        i16,
        u16,
        u32,
        "Generates a random i16 value in the given range."
    );

    range_integer!(
        range_i32,
        i32,
        u32,
        u64,
        "Generates a random i32 value in the given range."
    );

    range_integer!(
        range_i64,
        i64,
        u64,
        u128,
        "Generates a random i64 value in the given range."
    );

    #[cfg(target_pointer_width = "16")]
    range_integer!(
        range_isize,
        isize,
        u16,
        u32,
        "Generates a random isize value in the given range."
    );

    #[cfg(target_pointer_width = "32")]
    range_integer!(
        range_isize,
        isize,
        u32,
        u64,
        "Generates a random isize value in the given range."
    );

    #[cfg(target_pointer_width = "64")]
    range_integer!(
        range_isize,
        isize,
        u64,
        u128,
        "Generates a random isize value in the given range."
    );
}
