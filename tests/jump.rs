use rand_aes::seeds::*;
use rand_aes::*;

#[test]
fn test_jump_aes128_ctr128() {
    let period = 1u128 << 64;

    let rng0 = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    let rng1 = rng0.jump();
    let rng2 = rng0.jump();
    let rng3 = rng0.jump();
    let rng4 = rng0.jump();
    let rng5 = rng0.jump();

    assert_eq!(rng1.counter(), 0);
    assert_eq!(rng2.counter(), period);
    assert_eq!(rng3.counter(), period * 2);
    assert_eq!(rng4.counter(), period * 3);
    assert_eq!(rng5.counter(), period * 4);
    assert_eq!(rng0.counter(), period * 5);
}

#[test]
fn test_long_jump_aes128_ctr128() {
    let period = 1u128 << 96;

    let rng0 = Aes128Ctr128::from_seed(Aes128Ctr128Seed::default());
    let rng1 = rng0.long_jump();
    let rng2 = rng0.long_jump();
    let rng3 = rng0.long_jump();
    let rng4 = rng0.long_jump();
    let rng5 = rng0.long_jump();

    assert_eq!(rng1.counter(), 0);
    assert_eq!(rng2.counter(), period);
    assert_eq!(rng3.counter(), period * 2);
    assert_eq!(rng4.counter(), period * 3);
    assert_eq!(rng5.counter(), period * 4);
    assert_eq!(rng0.counter(), period * 5);
}

#[test]
fn test_jump_aes256_ctr128() {
    let period = 1u128 << 64;

    let rng0 = Aes256Ctr128::from_seed(Aes256Ctr128Seed::default());
    let rng1 = rng0.jump();
    let rng2 = rng0.jump();
    let rng3 = rng0.jump();
    let rng4 = rng0.jump();
    let rng5 = rng0.jump();

    assert_eq!(rng1.counter(), 0);
    assert_eq!(rng2.counter(), period);
    assert_eq!(rng3.counter(), period * 2);
    assert_eq!(rng4.counter(), period * 3);
    assert_eq!(rng5.counter(), period * 4);
    assert_eq!(rng0.counter(), period * 5);
}

#[test]
fn test_long_jump_aes256_ctr128() {
    let period = 1u128 << 96;

    let rng0 = Aes256Ctr128::from_seed(Aes256Ctr128Seed::default());
    let rng1 = rng0.long_jump();
    let rng2 = rng0.long_jump();
    let rng3 = rng0.long_jump();
    let rng4 = rng0.long_jump();
    let rng5 = rng0.long_jump();

    assert_eq!(rng1.counter(), 0);
    assert_eq!(rng2.counter(), period);
    assert_eq!(rng3.counter(), period * 2);
    assert_eq!(rng4.counter(), period * 3);
    assert_eq!(rng5.counter(), period * 4);
    assert_eq!(rng0.counter(), period * 5);
}
