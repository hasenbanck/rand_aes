# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
