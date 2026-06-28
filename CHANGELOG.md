# Changelog

## [0.2.0] — 2026-06-28

### Added
- **CLI fully wired** — all crypto/stego primitives accessible from command line
  - `enc`/`dec` — AES-256-CTR and ChaCha20 stream encryption with file/stdio support
  - `hash` — SHA-256 of files, strings, or stdin
  - `hmac` — HMAC-SHA256
  - `keygen` — random key/nonce generation with configurable size and count
  - `container create`/`extract` — password-protected encrypted containers (AES-256-CTR + HKDF-SHA256 + HMAC-SHA256 integrity)
  - `stego embed`/`extract`/`detect`/`capacity` — LSB steganography for BMP, PNG, WAV
  - `x25519 keygen`/`derive` — Curve25519 ECDH key exchange
  - `ed25519 keygen`/`sign`/`verify` — Ed25519 digital signatures
- **CI/CD** — GitHub Actions workflows for testing (clippy, fmt) and multi-platform release builds (Linux, macOS, Windows)
- Comprehensive round-trip and property tests across all modules
- Constant-time comparison for integrity verification in containers

### Changed
- Version bumped from 0.1.0 to 0.2.0
- All functions now include detailed help text accessible via `--help`
- ChaCha20 implementation uses RFC 8439 nonce/counter layout
- steganography detect command provides scoring (0.0 to 1.0) for stego likelihood

## [0.1.0] — 2026-06-27

### Added
- Initial release of cipher-core: AES-256-CTR, ChaCha20, SHA-256, HMAC-SHA256, HKDF-SHA256
- Steganography: BMP, PNG, WAV LSB embedding + JPEG EXIF manipulation
- Encrypted container format with password-based key derivation
- Curve25519 X25519 ECDH and Ed25519 signatures
- Zero external crypto dependencies outside of `getrandom`
- 39 tests covering core algorithms and stego round-trips
