<div align="center">

  <img src="assets/sayori-half-body.png" width="200" alt="Sayori" />

  <h1>🔐 CIPHER</h1>

  <p><b>Zero-dep Rust cryptography & steganography suite</b><br/>
  <i>if it needs to run bare, I write it myself</i></p>

  <p>
    <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square&logo=rust" />
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
    <img src="https://img.shields.io/badge/tests-46%2F46-brightgreen?style=flat-square" />
    <img src="https://img.shields.io/badge/deps-zero-red?style=flat-square" />
    <img src="https://img.shields.io/badge/version-0.2.0-ff69b4?style=flat-square" />
  </p>

</div>

---

![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=800&color=FF69B4&center=true&vCenter=true&width=500&lines=AES-256-CTR+%2B+ChaCha20;SHA-256+%2B+HMAC+%2B+HKDF;LSB+Steganography;Encrypted+Containers;X25519+%2B+Ed25519)

---

## �️ What's good?

**CIPHER** is a from-scratch cryptography & steganography toolkit in pure Rust. Zero external crypto dependencies. Every algorithm implemented directly from the RFC/spec — no OpenSSL, no `ring`, no `rust-crypto`. If it needs to run bare, I write it myself.

---

## � Arsenal in Production

| Module | Description | Status |
|--------|-------------|--------|
| 🔒 **cipher-core** | AES-256-CTR, ChaCha20, SHA-256, HMAC, HKDF | ✅ Ship it |
| �️ **cipher-stego** | BMP/PNG/WAV LSB + JPEG EXIF manipulation | ✅ Ship it |
| 📦 **Encrypted Container** | AES-256-CTR + HKDF + HMAC-SHA256 integrity | ✅ Ship it |
| 🔑 **X25519/Ed25519** | Curve25519 ECDH + EdDSA signatures | ✅ Ship it |
| �️ **cipher-cli** | Full CLI for all operations | ✅ v0.2.0 |

---

## 🏆 Algorithms & Standards

### Cryptography
| Algorithm | Standard | Status |
|-----------|----------|--------|
| AES-256-CTR | FIPS-197, SP800-38A | ✅ Verified |
| ChaCha20 | RFC 8439 | ✅ Verified |
| SHA-256 | FIPS-180-4 | ✅ Verified |
| HMAC-SHA256 | RFC 2104 | ✅ Verified |
| HKDF-SHA256 | RFC 5869 | ✅ Verified |
| X25519 | RFC 7748 | ✅ Verified |
| Ed25519 | RFC 8032 | ✅ Verified |

### Steganography
| Format | Method | Status |
|--------|--------|--------|
| BMP | LSB substitution | ✅ |
| PNG | LSB in IDAT chunks | ✅ |
| WAV | LSB in PCM samples | ✅ |
| JPEG | EXIF metadata injection | ✅ |

---

## 📦 Quick Start

```bash
# Build from source
git clone https://github.com/Obisidan/cipher.git
cd cipher
cargo build --release

# Run directly
cargo run -- --help
```

### Encrypt a file
```bash
# Generate a key and nonce
KEY=$(cipher keygen)
NONCE=$(cipher keygen --size 12 --nonce)

# Encrypt
cipher enc aes -i secret.txt -o secret.enc --key $KEY --nonce $NONCE

# Decrypt
cipher dec aes -i secret.enc -o decrypted.txt --key $KEY --nonce $NONCE
```

### Password-protected container
```bash
cipher container create -p "my-secret-password" -i document.pdf -o document.cipher
cipher container extract -p "my-secret-password" -i document.cipher -o document.pdf
```

### Hide data in an image
```bash
cipher stego embed -c photo.png -i secret.txt -o photo_stego.png
cipher stego extract -c photo_stego.png -i secret_recovered.txt
cipher stego detect -c photo_stego.png
cipher stego capacity -c photo.png
```

### Hash & sign
```bash
cipher hash myfile.txt
cipher hmac --key $KEY -i myfile.txt

cipher ed25519 keygen
cipher ed25519 sign --key $SECRET -i message.txt
cipher ed25519 verify --key $PUBLIC --sig $SIG -i message.txt
```

### Key exchange
```bash
cipher x25519 keygen              # generates keypair
cipher x25519 derive --secret $A --public $B  # shared secret
```

---

## �️ CLI Reference

<details>
<summary><b>Encryption</b></summary>

```
cipher enc <aes|chacha20> -i <input> -o <output> --key <hex> --nonce <hex>
cipher dec <aes|chacha20> -i <input> -o <output> --key <hex> --nonce <hex>
```
Use `-` for stdin/stdout.
</details>

<details>
<summary><b>Hashing & MAC</b></summary>

```
cipher hash <file|string|->
cipher hmac --key <hex> [file|string|-]
```
</details>

<details>
<summary><b>Key Generation</b></summary>

```
cipher keygen [--size N] [--count N] [--nonce]
```
</details>

<details>
<summary><b>Encrypted Containers</b></summary>

```
cipher container create -p <password> -i <input> -o <output>
cipher container extract -p <password> -i <container> -o <output>
```
Containers use AES-256-CTR with HKDF-SHA256 key derivation and HMAC-SHA256 integrity verification.
</details>

<details>
<summary><b>Steganography</b></summary>

```
cipher stego embed   -c <carrier> -i <payload> -o <output> [-f bmp|png|wav]
cipher stego extract -c <carrier> -o <output>           [-f bmp|png|wav]
cipher stego detect  -c <carrier>                       [-f bmp|png|wav]
cipher stego capacity -c <carrier>                      [-f bmp|png|wav]
```
Format auto-detected from file extension if `-f` omitted.
</details>

<details>
<summary><b>Curve25519 / Ed25519</b></summary>

```
cipher x25519 keygen
cipher x25519 derive --secret <hex> --public <hex>

cipher ed25519 keygen
cipher ed25519 sign   --key <hex> -i <input>
cipher ed25519 verify --key <hex> --sig <hex> -i <input>
```
</details>

---

## 📊 Project Stats

<div align="center">

  ![Tests](https://img.shields.io/badge/tests-46%2F46+passing-brightgreen?style=for-the-badge)
  ![LOC](https://img.shields.io/badge/LOC-~3500-blue?style=for-the-badge)
  ![Crates](https://img.shields.io/badge/workspace-3+crates-orange?style=for-the-badge)

</div>

---

## � Tech Stack

<div align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
  <img src="https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white" />
</div>

---

## � License

MIT — do whatever you want, just don't blame me.

---

<div align="center">

  🌸 **CIPHER** — *hehe i make stuffz* 🌸

  <sub><a href="https://github.com/Obisidan/cipher">github.com/Obisidan/cipher</a> · <a href="https://discord.com/users/alexdagreatest2">Discord</a></sub>

</div>
