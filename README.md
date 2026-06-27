<div align="right">
  <img src="assets/sayori-chibi.png" width="180" alt="Sayori Chibi" />
</div>

<h1 align="center">🔐 CIPHER</h1>

<p align="center">
  <b>Zero-dep Rust cryptography & steganography suite</b><br/>
  <i>if it needs to run bare, I write it myself</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square&logo=rust" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/tests-39%2F39-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/deps-zero-red?style=flat-square" />
</p>

---

<div align="center">

  ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=800&color=FF69B4&center=true&vCenter=true&width=500&lines=AES-256-CTR+%2B+ChaCha20;SHA-256+%2B+HMAC+%2B+HKDF;LSB+Steganography;Encrypted+Containers;X25519+%2B+Ed25519)

</div>

---

## 🕶️ What's good?

**CIPHER** is a from-scratch cryptography & steganography toolkit in pure Rust. Zero external crypto dependencies. Every algorithm implemented directly from the RFC/spec — no OpenSSL, no `ring`, no `rust-crypto`. If it needs to run bare, I write it myself.

---

## 🔭 Arsenal in Production

| Module | Description | Status |
|--------|-------------|--------|
| 🔒 **cipher-core** | AES-256-CTR, ChaCha20, SHA-256, HMAC, HKDF | ✅ Ship it |
| 🖼️ **cipher-stego** | BMP/PNG/WAV LSB + JPEG EXIF manipulation | ✅ Ship it |
| 📦 **Encrypted Container** | AES-256-CTR + HKDF + HMAC-SHA256 integrity | ✅ Ship it |
| 🔑 **X25519/Ed25519** | Curve25519 ECDH + EdDSA signatures | 🚧 Core done |

---

## 🏆 Algorithms & Standards

### Cryptography
| Algorithm | Standard | Status |
|-----------|----------|--------|
| AES-256-CTR | FIPS-197, SP800-38A | ✅ NIST vectors verified |
| ChaCha20 | RFC 8439 | ✅ RFC vectors verified |
| SHA-256 | FIPS-180-4 | ✅ NIST vectors verified |
| HMAC-SHA256 | RFC 2104 | ✅ RFC vectors verified |
| HKDF-SHA256 | RFC 5869 | ✅ RFC vectors verified |
| X25519 | RFC 7748 | 🚧 Self-consistent |
| Ed25519 | RFC 8032 | 🚧 Keygen done |
| Poly1305 | RFC 8439 | ⏳ Planned |

### Steganography
| Format | Method | Status |
|--------|--------|--------|
| BMP | LSB substitution | ✅ |
| PNG | LSB in IDAT chunks | ✅ |
| WAV | LSB in PCM samples | ✅ |
| JPEG | EXIF metadata injection | ✅ |

---

## 📊 Project Stats

<div align="center">

  ![CIPHER Tests](https://img.shields.io/badge/tests-39%2F39+passing-brightgreen?style=for-the-badge)
  ![Lines of Code](https://img.shields.io/badge/LOC-~4000-blue?style=for-the-badge)
  ![Crates](https://img.shields.io/badge/workspace-3+crates-orange?style=for-the-badge)

</div>

---

## 🐍 Contribution Snake

<div align="center">

  ![Snake animation](https://github.com/Obisidan/Obisidan/blob/output/github-contribution-grid-snake.svg)

  <sub><i>The snake auto-generates daily via GitHub Actions.</i></sub>

</div>

---

## 🧰 Tech Stack & Tools

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
  <img src="https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white" />
  <img src="https://img.shields.io/badge/Neovim-57A143?style=for-the-badge&logo=neovim&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" />
</p>

---

## 📜 License

MIT — do whatever you want, just don't blame me.

---

<div align="center">

  🌸 **CIPHER** — *hehe i make stuffz* 🌸

</div>
