# CIPHER

**Zero-dep Rust cryptography & steganography suite.**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%2F39-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/deps-zero-red.svg)]()

```
 ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░
```

## Features

### Cryptography
| Algorithm   | Standard       | Status |
|-------------|----------------|--------|
| AES-256-CTR | FIPS-197       | ✅     |
| ChaCha20    | RFC 8439       | ✅     |
| SHA-256     | FIPS-180-4     | ✅     |
| HMAC-SHA256 | RFC 2104       | ✅     |
| HKDF-SHA256 | RFC 5869       | ✅     |
| X25519      | RFC 7748       | 🚧     |
| Ed25519     | RFC 8032       | 🚧     |
| Poly1305    | RFC 8439       | ⏳     |

### Steganography
| Format | Type           | Status |
|--------|----------------|--------|
| BMP    | LSB embedding  | ✅     |
| PNG    | LSB embedding  | ✅     |
| WAV    | LSB embedding  | ✅     |
| JPEG   | EXIF metadata  | ✅     |

### Encrypted Container
- AES-256-CTR encryption with HKDF-SHA256 key derivation
- HMAC-SHA256 integrity verification
- Tamper detection

## Architecture

```
cipher/
├── cipher-core/       # Core cryptographic primitives (no_std-compatible)
│   ├── aes.rs         #   AES-256-CTR
│   ├── chacha20.rs    #   ChaCha20 stream cipher
│   ├── sha256.rs      #   SHA-256 hash
│   ├── hkdf.rs        #   HMAC-SHA256 + HKDF-SHA256
│   ├── curve25519.rs  #   X25519 + Ed25519
│   ├── container.rs   #   Encrypted container format
│   ├── encoding.rs    #   Hex/Base64
│   ├── csprng.rs      #   CSPRNG
│   ├── constant_time.rs #  Constant-time operations
│   └── bytes.rs       #   Low-level byte utilities
├── cipher-stego/      # Steganography toolkit
│   ├── bmp.rs         #   BMP LSB steganography
│   ├── png.rs         #   PNG LSB steganography
│   ├── wav.rs         #   WAV LSB steganography
│   ├── exif.rs        #   JPEG EXIF manipulation
│   └── lib.rs         #   Core LSB + entropy analysis
├── cipher-cli/        # Command-line interface
│   └── main.rs        #   CLI entry point
└── Cargo.toml         # Workspace manifest
```

## Usage

### As a Library

```toml
[dependencies]
cipher-core = { git = "https://github.com/Obisidian/cipher" }
```

```rust
use cipher_core::{aes::Aes256Ctr, sha256::sha256, hkdf::hkdf_sha256};
use cipher_core::csprng::random_array;

// AES-256-CTR encryption
let key = random_array::<32>().unwrap();
let iv = random_array::<16>().unwrap();
let mut cipher = Aes256Ctr::new(&key, &iv);
let plaintext = b"Hello, world!";
let ciphertext = cipher.encrypt(plaintext);
let decrypted = cipher.decrypt(&ciphertext);
assert_eq!(decrypted, plaintext);

// SHA-256 hashing
let hash = sha256(b"Hello, world!");
println!("{:x}", hash);

// HKDF key derivation
let key_material = hkdf_sha256(b"salt", b"input key", b"info", 32).unwrap();
```

### Encrypted Container

```rust
use cipher_core::container::Container;

// Encrypt
let container = Container::encrypt(b"my password", b"secret data").unwrap();
let bytes = container.to_bytes();

// Decrypt
let parsed = Container::from_bytes(&bytes).unwrap();
let data = parsed.decrypt(b"my password").unwrap();
```

### Steganography

```rust
use cipher_stego::{lsb_embed, lsb_extract, detect_lsb_stego};

let mut carrier = vec![0xFFu8; 1000];
let payload = b"hidden message";

lsb_embed(&mut carrier, payload).unwrap();
let extracted = lsb_extract(&carrier, payload.len());

// Detect steganography
let score = detect_lsb_stego(&carrier);
```

## Design Principles

- **Zero external crypto dependencies** — all algorithms implemented from scratch from RFC/spec
- **Constant-time operations** — prevents timing side-channel attacks
- **Pure Rust** — no unsafe code, no C dependencies
- **no_std compatible core** — `cipher-core` can run in embedded environments

## Testing

```bash
cargo test --workspace
```

39 tests covering:
- NIST AES test vectors
- RFC 8439 ChaCha20 test vectors
- NIST SHA-256 test vectors
- RFC 5869 HKDF test vectors
- Roundtrip tests for all ciphers
- Container encryption/decryption/tamper detection
- Steganography embed/extract for BMP/PNG/WAV

## License

MIT License — see [LICENSE](LICENSE).
