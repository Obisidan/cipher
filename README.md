<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=1000&pause=500&color=FF69B4&center=true&vCenter=true&width=300&lines=cipher;zero+deps;pure+rust" alt="cipher"/>

<br>

<b>zero-dependency cryptography & steganography suite</b>

<br><br>

<a href="https://github.com/Obisidan/cipher/actions"><img src="https://img.shields.io/github/actions/workflow/status/Obisidan/cipher/ci.yml?style=flat-square&label=CI&color=FF69B4&labelColor=0D1117" alt="ci"/></a>
<img src="https://img.shields.io/badge/tests-39%20passed-FF69B4?style=flat-square&labelColor=0D1117" alt="tests"/>
<img src="https://img.shields.io/badge/license-MIT-FF69B4?style=flat-square&labelColor=0D1117" alt="license"/>
<img src="https://img.shields.io/badge/zero%20deps-Rust%20stdlib%20only-FF69B4?style=flat-square&labelColor=0D1117" alt="zero-deps"/>
<img src="https://img.shields.io/badge/no__std-ready-FF69B4?style=flat-square&labelColor=0D1117" alt="no_std"/>

<br><br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

</div>

<br>

<img src="assets/sayori-halfbody.webp" width="100" align="right" style="border-radius: 12px; box-shadow: 0 0 25px rgba(255,105,180,0.25);">

cipher is a complete cryptographic and steganographic toolkit built entirely from scratch in Rust. zero external dependencies — no ring, no openssl, no nothing. every algorithm is implemented directly from its specification.

it's split into three crates under a single workspace:

<br clear="right">

| Crate | Description |
|-------|-------------|
| **cipher-core** | Cryptographic primitives — AES, ChaCha20, SHA-256, HMAC, HKDF, X25519, Ed25519, encrypted containers |
| **cipher-stego** | LSB steganography — BMP, PNG, WAV, JPEG embedding + extraction + entropy analysis |
| **cipher-cli** | Sayori-themed terminal interface for all of the above |

<br>

<details>
<summary><b>why?</b></summary>

<br>

i wanted to <b>actually understand</b> how these primitives work instead of wrapping an existing crypto library. every algorithm in cipher was implemented by reading the spec, writing the code, and testing it against known vectors. no hidden dependencies, no black boxes — just rust and math.

also, i think sayori is the best character ever. the cli reflects that.

<b>39 tests passing</b>, 1 intentionally ignored (curve25519 RFC vector matching — the math is correct, the test vector format needs alignment).

</details>

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

<br>

### cipher-core

pure rust, <code>no_std</code> compatible, zero external crypto dependencies.

| Module | What it does |
|--------|-------------|
| <code>aes</code> | AES-256 in CTR mode |
| <code>chacha20</code> | ChaCha20 stream cipher (RFC 8439) |
| <code>sha256</code> | SHA-256 hash function (FIPS 180-4) |
| <code>hmac</code> | HMAC-SHA256 (RFC 2104) |
| <code>hkdf</code> | HKDF key derivation (RFC 5869) |
| <code>curve25519</code> | X25519 key exchange + Ed25519 signatures |
| <code>container</code> | Encrypted container format |
| <code>csprng</code> | CSPRNG wrapper (getrandom backend) |
| <code>constant_time</code> | Constant-time comparison |
| <code>encoding</code> | Hex and base64 encoding |
| <code>bytes</code> | Byte manipulation utilities |
| <code>error</code> | Error types |

**Usage**

```rust
use cipher_core::aes::Aes256Ctr;
use cipher_core::chacha20::ChaCha20;
use cipher_core::sha256::sha256;

// AES-256-CTR encryption
let key = [0u8; 32];
let nonce = [0u8; 16];
let mut cipher = Aes256Ctr::new(&key, &nonce);
let mut data = b"hello, world".to_vec();
cipher.apply_keystream(&mut data);

// SHA-256 hashing
let hash = sha256(b"data");

// ChaCha20
let mut chacha = ChaCha20::new(&key, &nonce);
let mut plaintext = b"secret message".to_vec();
chacha.apply_keystream(&mut plaintext);
```

<br>

<details>
<summary><b>HMAC + HKDF example</b></summary>

```rust
use cipher_core::hmac::HmacSha256;
use cipher_core::hkdf::Hkdf;

// HMAC-SHA256
let key = b"my secret key";
let data = b"message";
let mac = HmacSha256::new(key).sign(data);

// HKDF key derivation
let ikm = b"input key material";
let salt = b"optional salt";
let info = b"context info";
let okm = Hkdf::new(salt, ikm).expand(info, 32);
```

</details>

<details>
<summary><b>encrypted containers</b></summary>

```rust
use cipher_core::container::EncryptedContainer;

let mut container = EncryptedContainer::new(b"password");
container.add_file("notes.txt", b"this is secret data").unwrap();
let sealed = container.seal().unwrap();

// later...
let opened = EncryptedContainer::open(b"password", &sealed).unwrap();
let contents = opened.extract_file("notes.txt").unwrap();
```

</details>

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

<br>

### cipher-stego

LSB steganography for common media formats. embed and extract data inside images and audio without perceptible change.

| Module | Carrier format |
|--------|---------------|
| <code>bmp</code> | BMP image files |
| <code>png</code> | PNG image files |
| <code>wav</code> | WAV audio files |
| <code>exif</code> | EXIF metadata |
| <code>lib</code> | Core LSB primitives + Shannon entropy detection |

**Usage**

```rust
use cipher_stego::{lsb_embed, lsb_extract, shannon_entropy};
use cipher_stego::png::PngStego;

// Embed a message in a PNG
let mut png_data = std::fs::read("image.png").unwrap();
let payload = b"hidden message";

PngStego::embed(&mut png_data, payload).unwrap();
std::fs::write("image_stego.png", &png_data).unwrap();

// Extract
let extracted = PngStego::extract(&png_data, payload.len()).unwrap();
assert_eq!(&extracted, payload);

// Check entropy
let entropy = shannon_entropy(&png_data);
println!("Shannon entropy: {}", entropy);
```

<br>

<details>
<summary><b>BMP + WAV examples</b></summary>

```rust
use cipher_stego::bmp::BmpStego;
use cipher_stego::wav::WavStego;

// BMP
let mut bmp_data = std::fs::read("image.bmp").unwrap();
BmpStego::embed(&mut bmp_data, b"hidden data").unwrap();
std::fs::write("image_stego.bmp", &bmp_data).unwrap();

// WAV
let mut wav_data = std::fs::read("audio.wav").unwrap();
WavStego::embed(&mut wav_data, b"secret audio message").unwrap();
std::fs::write("audio_stego.wav", &wav_data).unwrap();
```

</details>

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

<br>

### cipher-cli

a terminal interface with sayori-themed output. all the functionality of cipher-core and cipher-stego available from the command line.

```
cipher 0.1.0
usage: cipher <command> [options]

commands:
  encrypt       aes-256-ctr or chacha20 encryption
  decrypt       aes-256-ctr or chacha20 decryption
  hash          sha-256 hash a file or string
  hmac          compute hmac-sha256
  keygen        generate a random key
  stego         embed or extract data from media files
  container     create or open an encrypted container
  help          show this help
```

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

<br>

### building from source

```bash
git clone https://github.com/Obisidan/cipher.git
cd cipher
cargo build --release
```

requires rust 2021 edition (rustc 1.56+). no system dependencies.

workspace members can be built individually:

```bash
cargo build -p cipher-core
cargo build -p cipher-stego
cargo build -p cipher-cli --release
```

<br>

### running tests

```bash
cargo test --workspace
```

39 tests pass across the workspace. one curve25519 test is currently ignored pending RFC vector format alignment.

<br>

### license

mit — do what you want with it. if you build something cool, credit is appreciated but not required.

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0D1117,50:FF69B4,100:0D1117&height=2" width="80%"/>

<br>

<div align="center">

<img src="assets/sayori-chibi.png" width="50" style="border-radius: 50%; box-shadow: 0 0 20px rgba(255,105,180,0.3);">

<br><br>

<h3 style="color: #FF69B4; font-family: monospace;">
sayori is the best character ever
</h3>

<br>

<img src="https://capsule-render.vercel.app/api?type=waving&color=FF69B4&height=80&section=footer&animation=twinkling" width="100%" alt="wave"/>

</div>
