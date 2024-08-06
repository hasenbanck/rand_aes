fn main() {
    println!("Starting verification");

    unsafe {
        rand_aes::verification::run_verification()
    };

    println!("Passed verification!");
}
