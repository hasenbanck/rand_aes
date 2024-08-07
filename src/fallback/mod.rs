//! We have two fallbacks:
//!     - Runtime: Uses the STD library for targets that support hardware based AES to query if the
//!                current CPU has hardware based AES. If not, it will fall back to the software
//!                AES implementation.
//!     - Fixed: Always uses the software AES implementation.
#[cfg(all(
    any(
        not(all(feature = "std", any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))),
        feature = "force_no_runtime_detection"
    ),
    not(feature = "verification")
))]
mod fixed;

#[cfg(all(
    not(any(
        not(all(feature = "std", any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))),
        feature = "force_no_runtime_detection"
    )),
    not(feature = "verification")
))]
mod runtime;

pub(crate) mod software;

#[cfg(all(
    feature = "std",
    any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force_no_runtime_detection"),
    not(feature = "verification")
))]
pub use runtime::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(all(
    any(
        not(all(feature = "std", any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))),
        feature = "force_no_runtime_detection"
    ),
    not(feature = "verification")
))]
pub use fixed::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};
