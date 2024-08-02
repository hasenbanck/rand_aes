use rand_aes::seeds::*;
use rand_aes::*;

// TODO add a test for the TLS functionality.
// TODO add a test for each implementation.

macro_rules! test_range {
    ($name:ident, $method:ident, $range:expr) => {
        #[test]
        fn $name() {
            let prng: Aes128Ctr128 = Random::from_seed(Aes128Ctr128Seed::default());
            for _ in 0..1000 {
                let value = prng.$method($range.clone());
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

test_range!(test_prng_range_u8, range_u8, 10..20);
test_range!(test_prng_range_u16, range_u16, 100..200);
test_range!(test_prng_range_u32, range_u32, 1000..2000);
test_range!(test_prng_range_u64, range_u64, 10000..20000);
test_range!(test_prng_range_usize, range_usize, 100000..200000);
test_range!(test_prng_range_i8, range_i8, -10..10);
test_range!(test_prng_range_i16, range_i16, -100..100);
test_range!(test_prng_range_i32, range_i32, -1000..1000);
test_range!(test_prng_range_i64, range_i64, -10000..10000);
test_range!(test_prng_range_isize, range_isize, -100000..100000);

macro_rules! test_mod {
    ($name:ident, $method:ident, $max:expr) => {
        #[test]
        fn $name() {
            let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
            for _ in 0..1000 {
                let value = prng.$method($max);
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

test_mod!(test_prng_mod_u8, mod_u8, 100);
test_mod!(test_prng_mod_u16, mod_u16, 1000);
test_mod!(test_prng_mod_u32, mod_u32, 10000);
test_mod!(test_prng_mod_u64, mod_u64, 100000);
test_mod!(test_prng_mod_usize, mod_usize, 1000000);

macro_rules! test_primitive_integer {
    ($name:ident, $method:ident) => {
        #[test]
        fn $name() {
            let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
            for _ in 0..1000 {
                let _value = prng.$method();
            }
        }
    };
}

test_primitive_integer!(test_prng_u8, u8);
test_primitive_integer!(test_prng_u16, u16);
test_primitive_integer!(test_prng_u32, u32);
test_primitive_integer!(test_prng_u64, u64);
test_primitive_integer!(test_prng_usize, usize);
test_primitive_integer!(test_prng_i8, i8);
test_primitive_integer!(test_prng_i16, i16);
test_primitive_integer!(test_prng_i32, i32);
test_primitive_integer!(test_prng_i64, i64);
test_primitive_integer!(test_prng_isize, isize);

#[test]
fn test_prng_bool() {
    let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    let mut true_count = 0;
    let mut false_count = 0;
    for _ in 0..1000 {
        if prng.bool() {
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
    let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    for _ in 0..1000 {
        let value = prng.f32();
        assert!(
            (0.0..1.0).contains(&value),
            "PRNG f32 value should be in range 0.0..1.0"
        );
    }
}

#[test]
fn test_prng_f64() {
    let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    for _ in 0..1000 {
        let value = prng.f64();
        assert!(
            (0.0..1.0).contains(&value),
            "PRNG f64 value should be in range 0.0..1.0"
        );
    }
}

#[test]
fn test_prng_fill_bytes() {
    let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    let mut bytes = [0u8; 16];
    prng.fill_bytes(&mut bytes);
    assert!(
        !bytes.iter().all(|&x| x == 0),
        "Filled bytes should not be all zeros"
    );
}

#[test]
fn test_prng_shuffle() {
    let prng = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    let mut array = [0usize; 256];
    for (i, x) in array.as_mut_slice().iter_mut().enumerate() {
        *x = i;
    }
    let copy = array;

    prng.shuffle(&mut array);

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
