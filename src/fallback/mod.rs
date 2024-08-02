//! We have two fallbacks:
//!     - Runtime: Uses the STD library for targets that support hardware based AES to query if the
//!                current CPU has hardware based AES. If not, it will fall back to the software
//!                AES implementation.
//!     - Fixed: Always uses the software AES implementation.
#[cfg(feature = "force_no_runtime_detection")]
mod fixed;

#[cfg(not(feature = "force_no_runtime_detection"))]
mod runtime;

pub(crate) mod software;

#[cfg(not(feature = "force_no_runtime_detection"))]
pub use runtime::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};

#[cfg(feature = "force_no_runtime_detection")]
pub use fixed::{Aes128Ctr128, Aes128Ctr64, Aes256Ctr128, Aes256Ctr64};
