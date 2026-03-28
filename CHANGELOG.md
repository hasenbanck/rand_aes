# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-03-28

### Fixed

- Fixes the TLS feature when using the software backend

## [0.6.0] - 2025-10-31

### Changed

- Removed internal workaround for now safe functionality. This increases the MSRV to v1.91. Use v0.5.0 which has the
  functionality as v0.6.0 if you can't update to Rust v1.91.

### Fixed

- Fixed compiling when using "--no-default-features"

## [0.5.0] - 2025-01-28

### Changed

- Target rand_core version 0.9
- Target getrandom version 0.3

## [0.4.0] - 2025-01-08

### Added

- Enable building for the WASM target

## [0.3.1] - 2024-08-11

### Fixed

- Improve efficiency of fill_bytes()
- Don't reimplement byte_array() in rand_byte_array()

## [0.3.0] - 2024-08-10

### Added

- Add `byte_array()` function to the `Random` trait.
- Add missing `rand_u128()`, `rand_i128()` and new `rand_byte_array()` functions to the TLS API.

## [0.2.0] - 2024-08-09

### Added

- Fixed various documentation errors.
- Added the RISC-V vector crypto extension based backend.
- Support x86 based target (32-bit)
- Add features to select the PRNG version of the TLS instance.

### Fixed

- Properly detect available target features when cross compiling.

### Removed

- The verification binary is not published anymore.
- Removed the RISC-V scalar crypto extension based backend.

## [0.1.3] - 2024-08-04

### Changed

- Fixed various documentation errors.

## [0.1.2] - 2024-08-04

### Changed

- Add missing feature toggle for proper rendering on docs.rs

## [0.1.1] - 2024-08-04

### Changed

- Updated the documentation to properly render on docs.rs

## [0.1.0] - 2024-08-04

### Added

- Initial release.
