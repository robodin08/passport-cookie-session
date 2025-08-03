# Changelog

<!-- ## [Unreleased]
### Added
- Placeholder for upcoming features or fixes. -->

## [1.0.0] - 2025-08-03

### Added
- Added `timeout` option to configure max duration (in ms) for custom async encrypt/decrypt functions.
- Added `checkEncryption` boolean option to enable startup validation of custom async encrypt/decrypt functions in non-production environments.
- Added `name` option to customize the cookie session name (default: `'session'`).
- Included detailed warnings about insecure sample XOR cipher encryption in docs.
- Improved options validation to cover `timeout` and ensure encrypt/decrypt functions are async with proper signatures.
- Enhanced API documentation with clear explanations of keys, cookie options, and security best practices.

### Changed
- Migrated from callback-based encrypt/decrypt functions to async/await style.
- Default timeout for encryption/decryption functions set to 3000 ms.
- Standardized logging and error messages for encryption/decryption checks.

### Fixed
- Corrected misleading error messages during encryption/decryption validation.
- Strengthened cookie option validation with stricter type checks.

## [0.0.1] - 2025-08-02

### Added
- Initial pre-release implementation using callback-based encrypt/decrypt functions.
- Basic cookie session support with encryption and key rotation.