#[cfg(all(target_arch = "aarch64", not(feature = "force_software")))]
pub(crate) mod aarch64;

#[cfg(all(
    target_arch = "riscv64",
    feature = "experimental_riscv",
    not(feature = "force_software")
))]
pub(crate) mod riscv64;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force_software")
))]
pub(crate) mod x86;

#[cfg(any(
    not(any(
        all(
            any(target_arch = "x86_64", target_arch = "x86"),
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
    feature = "force_runtime_detection",
    feature = "force_software",
    feature = "verification",
))]
pub(crate) mod soft;
