    md
    <h1 align="center">cipher</h1>
    
    <p align="center">
      Zero-dependency Rust cryptography & steganography suite.
    </p>
    
    <p align="center">
      <a href="https://github.com/Obisidan/cipher/actions"><img src="https://img.shields.io/github/actions/workflow/status/Obisidan/cipher/ci?style=flat-square&label=CI" /></a>
      <img src="https://img.shields.io/badge/tests-15%20passed-brightgreen?style=flat-square" />
      <img src="https://img.shields.io/crates/l/MIT?style=flat-square" />
      <img src="https://img.shields.io/badge/zero%20deps-Rust%20stdlib%20only-blue?style=flat-square" />
    </p>
    
    
    
    Install
    
    bash
    cargo install --git https://github.com/Obisidan/cipher cipher-cli
    
    
    What's inside
    
    cipher-core — pure Rust, no external dependencies
    - AES-256-CTR
    - ChaCha20
    - SHA-256
    - HMAC
    - HKDF
    - X25519 key exchange
    - Ed25519 signatures
    - CSPRNG (getrandom only)
    - Constant-time comparison
    - Encrypted containers
    
    cipher-stego — LSB steganography
    - BMP, PNG, WAV, JPEG carriers
    - Embed/extract with XOR cipher
    - Capacity reporting & Shannon entropy scoring
    
    cipher-cli — Sayori-themed terminal interface
    
    Why
    
    I wanted to understand how these primitives actually work instead of wrapping ring or openssl. Every algorithm is implemented from the spec. No hidden dependencies, no magic — just Rust and math.
    
    Status
    
    Early. Core crypto is tested and working. Curve25519 needs RFC test vector matching (currently ignored). Stego works on BMP/PNG/WAV/JPEG. CLI is functional but minimal.
