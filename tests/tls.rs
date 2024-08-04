#[cfg(feature = "tls")]
mod test {
    use rand_aes::seeds::*;
    use rand_aes::tls::*;

    macro_rules! test_range {
        ($name:ident, $method:ident, $range:expr) => {
            #[test]
            fn $name() {
                rand_seed(Aes128Ctr64Seed::default());
                for _ in 0..1000 {
                    let value = $method($range.clone());
                    assert!(
                        $range.contains(&value),
                        "PRNG {} value should be in range {:?}",
                        stringify!($method),
                        $range
                    );
                }
            }
        };
    }

    test_range!(test_prng_rand_u8, rand_range_u8, 10..20);
    test_range!(test_prng_range_u16, rand_range_u16, 100..200);
    test_range!(test_prng_range_u32, rand_range_u32, 1000..2000);
    test_range!(test_prng_range_u64, rand_range_u64, 10000..20000);
    test_range!(test_prng_range_usize, rand_range_usize, 100000..200000);
    test_range!(test_prng_range_i8, rand_range_i8, -10..10);
    test_range!(test_prng_range_i16, rand_range_i16, -100..100);
    test_range!(test_prng_range_i32, rand_range_i32, -1000..1000);
    test_range!(test_prng_range_i64, rand_range_i64, -10000..10000);
    test_range!(test_prng_range_isize, rand_range_isize, -100000..100000);

    macro_rules! test_mod {
        ($name:ident, $method:ident, $max:expr) => {
            #[test]
            fn $name() {
                rand_seed(Aes128Ctr64Seed::default());
                for _ in 0..1000 {
                    let value = $method($max);
                    assert!(
                        value < $max,
                        "PRNG {} value should be less than {}",
                        stringify!($method),
                        $max
                    );
                }
            }
        };
    }

    test_mod!(test_prng_mod_u8, rand_mod_u8, 100);
    test_mod!(test_prng_mod_u16, rand_mod_u16, 1000);
    test_mod!(test_prng_mod_u32, rand_mod_u32, 10000);
    test_mod!(test_prng_mod_u64, rand_mod_u64, 100000);
    test_mod!(test_prng_mod_usize, rand_mod_usize, 1000000);

    macro_rules! test_primitive_integer {
        ($name:ident, $method:ident) => {
            #[test]
            fn $name() {
                rand_seed(Aes128Ctr64Seed::default());
                for _ in 0..1000 {
                    let _value = $method();
                }
            }
        };
    }

    test_primitive_integer!(test_prng_u8, rand_u8);
    test_primitive_integer!(test_prng_u16, rand_u16);
    test_primitive_integer!(test_prng_u32, rand_u32);
    test_primitive_integer!(test_prng_u64, rand_u64);
    test_primitive_integer!(test_prng_usize, rand_usize);
    test_primitive_integer!(test_prng_i8, rand_i8);
    test_primitive_integer!(test_prng_i16, rand_i16);
    test_primitive_integer!(test_prng_i32, rand_i32);
    test_primitive_integer!(test_prng_i64, rand_i64);
    test_primitive_integer!(test_prng_isize, rand_isize);

    #[test]
    fn test_prng_bool() {
        rand_seed(Aes128Ctr64Seed::default());
        let mut true_count = 0;
        let mut false_count = 0;
        for _ in 0..1000 {
            if rand_bool() {
                true_count += 1;
            } else {
                false_count += 1;
            }
        }
        // We should have a mix of true and false
        assert!(true_count > 0, "PRNG bool should generate true values");
        assert!(false_count > 0, "PRNG bool should generate false values");
    }

    #[test]
    fn test_prng_f32() {
        rand_seed(Aes128Ctr64Seed::default());
        for _ in 0..1000 {
            let value = rand_f32();
            assert!(
                (0.0..1.0).contains(&value),
                "PRNG f32 value should be in range 0.0..1.0"
            );
        }
    }

    #[test]
    fn test_prng_f64() {
        rand_seed(Aes128Ctr64Seed::default());
        for _ in 0..1000 {
            let value = rand_f64();
            assert!(
                (0.0..1.0).contains(&value),
                "PRNG f64 value should be in range 0.0..1.0"
            );
        }
    }

    #[test]
    fn test_prng_fill_bytes() {
        rand_seed(Aes128Ctr64Seed::default());
        let mut bytes = [0u8; 16];
        rand_fill_bytes(&mut bytes);
        assert!(
            !bytes.iter().all(|&x| x == 0),
            "Filled bytes should not be all zeros"
        );
    }

    #[test]
    fn test_prng_shuffle() {
        rand_seed(Aes128Ctr64Seed::default());
        let mut array = [0usize; 256];
        for (i, x) in array.as_mut_slice().iter_mut().enumerate() {
            *x = i;
        }
        let copy = array;

        rand_shuffle(&mut array);

        assert_ne!(array, copy);

        array.sort();

        // Check that all elements are still present
        for (i, x) in array.iter().copied().enumerate() {
            assert_eq!(
                x, i,
                "Array should contain all original elements after shuffle"
            );
        }
    }
}
