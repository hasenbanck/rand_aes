#[allow(unreachable_code)]
fn main() {
    println!("Starting verification");

    #[cfg(feature = "verification")]
    rand_aes::verification::run_verification();

    #[cfg(not(feature = "verification"))]
    panic!("Compiled without feature 'verification'");

    println!("Passed verification!");
}
