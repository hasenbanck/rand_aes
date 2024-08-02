fn main() {
    println!("cargo::rerun-if-changed=src");

    #[cfg(not(any(
        all(
            target_arch = "x86_64",
            target_feature = "sse2",
            target_feature = "aes",
        ),
        all(target_arch = "riscv64", target_feature = "zkne"),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "aes",
        ),
    )))]
    println!("cargo::rustc-cfg=feature=\"force_fallback\"");

    #[cfg(not(all(
        feature = "std",
        any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64",
        )
    )))]
    println!("cargo::rustc-cfg=feature=\"force_no_runtime_detection\"");
}
