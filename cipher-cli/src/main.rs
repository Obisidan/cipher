//! CIPHER v0.2.0 CLI — Encryption, hashing, steganography, and key management.
//! Wires up all functions from cipher-core and cipher-stego crates.

use std::fs;
use std::io::{self, Read, Write};

use cipher_core::aes::Aes256Ctr;
use cipher_core::chacha20::ChaCha20;
use cipher_core::container::Container;
use cipher_core::csprng;
use cipher_core::curve25519;
use cipher_core::encoding::{hex_decode, hex_encode};
use cipher_core::hkdf::hmac_sha256;
use cipher_core::sha256::sha256;

// ── ANSI colors ────────────────────────────────────────────────────────

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn eprint_err(msg: &str) {
    eprintln!("{}{}Error:{} {}", BOLD, RED, RESET, msg);
}

fn print_success(msg: &str) {
    println!("{}+{} {}", GREEN, RESET, msg);
}

fn print_warn(msg: &str) {
    println!("{}{}!{} {}", BOLD, YELLOW, RESET, msg);
}

// ── I/O helpers ────────────────────────────────────────────────────────

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).map_err(|e| format!("stdin read: {}", e))?;
        Ok(buf)
    } else {
        fs::read(path).map_err(|e| format!("read '{}': {}", path, e))
    }
}

fn write_output(path: &str, data: &[u8]) -> Result<(), String> {
    if path == "-" {
        io::stdout().write_all(data).map_err(|e| format!("stdout write: {}", e))?;
        Ok(())
    } else {
        fs::write(path, data).map_err(|e| format!("write '{}': {}", path, e))
    }
}

fn parse_hex_key(hex: &str, expected: usize, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(hex).map_err(|e| format!("invalid {} hex: {}", label, e))?;
    if bytes.len() != expected {
        return Err(format!("{} must be {} bytes, got {}", label, expected, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr[..expected].copy_from_slice(&bytes[..expected]);
    Ok(arr)
}

fn parse_hex_nonce(hex: &str, expected: usize, label: &str) -> Result<[u8; 12], String> {
    let bytes = hex_decode(hex).map_err(|e| format!("invalid {} hex: {}", label, e))?;
    if bytes.len() != expected {
        return Err(format!("{} must be {} bytes, got {}", label, expected, bytes.len()));
    }
    let mut arr = [0u8; 12];
    arr[..expected].copy_from_slice(&bytes[..expected]);
    Ok(arr)
}

fn get_opt_arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).map(|s| s.as_str());
        }
        i += 1;
    }
    None
}

fn require_arg<'a>(args: &'a [String], flag: &str, label: &str) -> Result<&'a str, String> {
    get_opt_arg(args, flag).ok_or_else(|| format!("missing {}", label))
}

// ── Encryption / Decryption ────────────────────────────────────────────

fn cmd_enc(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: enc <aes|chacha20> -i input -o output --key hex --nonce hex".into());
    }
    let algo = &args[0];
    let input_path = require_arg(args, "-i", "-i input")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let key_hex = require_arg(args, "--key", "--key")?;
    let nonce_hex = require_arg(args, "--nonce", "--nonce")?;
    let input_data = read_input(input_path)?;

    let output = match algo.as_str() {
        "aes" => {
            let key = parse_hex_key(key_hex, 32, "key")?;
            let nonce = parse_hex_nonce(nonce_hex, 12, "nonce")?;
            let mut cipher = Aes256Ctr::new(&key, &nonce);
            cipher.encrypt(&input_data)
        }
        "chacha20" => {
            let key = parse_hex_key(key_hex, 32, "key")?;
            let nonce = parse_hex_nonce(nonce_hex, 12, "nonce")?;
            let mut cipher = ChaCha20::new(&key, &nonce);
            cipher.encrypt(&input_data)
        }
        other => return Err(format!("unknown algorithm '{}', use aes or chacha20", other)),
    };

    write_output(output_path, &output)?;
    print_success(&format!("encrypted {} bytes with {}", output.len(), algo));
    Ok(())
}

fn cmd_dec(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: dec <aes|chacha20> -i input -o output --key hex --nonce hex".into());
    }
    let algo = &args[0];
    let input_path = require_arg(args, "-i", "-i input")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let key_hex = require_arg(args, "--key", "--key")?;
    let nonce_hex = require_arg(args, "--nonce", "--nonce")?;
    let input_data = read_input(input_path)?;

    let output = match algo.as_str() {
        "aes" => {
            let key = parse_hex_key(key_hex, 32, "key")?;
            let nonce = parse_hex_nonce(nonce_hex, 12, "nonce")?;
            let mut cipher = Aes256Ctr::new(&key, &nonce);
            cipher.decrypt(&input_data)
        }
        "chacha20" => {
            let key = parse_hex_key(key_hex, 32, "key")?;
            let nonce = parse_hex_nonce(nonce_hex, 12, "nonce")?;
            let mut cipher = ChaCha20::new(&key, &nonce);
            cipher.decrypt(&input_data)
        }
        other => return Err(format!("unknown algorithm '{}', use aes or chacha20", other)),
    };

    write_output(output_path, &output)?;
    print_success(&format!("decrypted {} bytes with {}", output.len(), algo));
    Ok(())
}

// ── Hashing ────────────────────────────────────────────────────────────

fn cmd_hash(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: hash <file|string>".into());
    }
    let target = &args[0];
    let data = if target == "-" {
        read_input("-")?
    } else {
        match fs::read(target) {
            Ok(d) => d,
            Err(_) => target.as_bytes().to_vec(),
        }
    };
    let digest = sha256(&data);
    println!("{}", hex_encode(&digest));
    Ok(())
}

fn cmd_hmac(args: &[String]) -> Result<(), String> {
    let key_hex = require_arg(args, "--key", "--key")?;
    let key = hex_decode(key_hex).map_err(|e| format!("invalid key hex: {}", e))?;

    // Find positional arg after the --key <value>
    let pos_arg = args.iter().position(|a| a == key_hex)
        .and_then(|idx| args.get(idx + 1))
        .map(|s| s.as_str());

    let data = if let Some(target) = pos_arg {
        if target == "-" {
            read_input("-")?
        } else {
            match fs::read(target) {
                Ok(d) => d,
                Err(_) => target.as_bytes().to_vec(),
            }
        }
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).map_err(|e| format!("stdin: {}", e))?;
        buf
    };

    let mac = hmac_sha256(&key, &data);
    println!("{}", hex_encode(&mac));
    Ok(())
}

// ── Key generation ─────────────────────────────────────────────────────

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let mut size: usize = 32;
    let mut count: usize = 1;
    let mut generate_nonce = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--size" => {
                i += 1;
                size = args.get(i).ok_or("missing size")?.parse::<usize>()
                    .map_err(|e| format!("invalid size: {}", e))?;
            }
            "--count" => {
                i += 1;
                count = args.get(i).ok_or("missing count")?.parse::<usize>()
                    .map_err(|e| format!("invalid count: {}", e))?;
            }
            "--nonce" => generate_nonce = true,
            other => return Err(format!("unknown option: {}", other)),
        }
        i += 1;
    }

    if generate_nonce {
        for _ in 0..count {
            let nonce = csprng::random_nonce(size).map_err(|e| format!("entropy: {}", e))?;
            println!("{}", hex_encode(&nonce));
        }
    } else {
        for _ in 0..count {
            let key = csprng::random_key(size).map_err(|e| format!("entropy: {}", e))?;
            println!("{}", hex_encode(&key));
        }
    }
    Ok(())
}

// ── Container ──────────────────────────────────────────────────────────

fn cmd_container(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: container <create|extract> ...".into());
    }
    match args[0].as_str() {
        "create" => cmd_container_create(&args[1..]),
        "extract" => cmd_container_extract(&args[1..]),
        other => Err(format!("unknown container subcommand: {}", other)),
    }
}

fn cmd_container_create(args: &[String]) -> Result<(), String> {
    let password = require_arg(args, "-p", "-p password")?;
    let input_path = require_arg(args, "-i", "-i input")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let plaintext = read_input(input_path)?;

    let container = Container::encrypt(password.as_bytes(), &plaintext)
        .map_err(|e| format!("container encrypt: {}", e))?;
    let bytes = container.to_bytes();
    write_output(output_path, &bytes)?;
    print_success(&format!("container created: {} bytes", bytes.len()));
    Ok(())
}

fn cmd_container_extract(args: &[String]) -> Result<(), String> {
    let password = require_arg(args, "-p", "-p password")?;
    let input_path = require_arg(args, "-i", "-i input")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let data = read_input(input_path)?;

    let container = Container::from_bytes(&data)
        .map_err(|e| format!("container parse: {}", e))?;
    let plaintext = container.decrypt(password.as_bytes())
        .map_err(|e| format!("container decrypt: {}", e))?;
    write_output(output_path, &plaintext)?;
    print_success(&format!("container extracted: {} bytes", plaintext.len()));
    Ok(())
}

// ── Steganography ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum StegoFormat {
    Bmp,
    Png,
    Wav,
}

impl std::fmt::Display for StegoFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StegoFormat::Bmp => write!(f, "bmp"),
            StegoFormat::Png => write!(f, "png"),
            StegoFormat::Wav => write!(f, "wav"),
        }
    }
}

fn detect_format(args: &[String]) -> Result<StegoFormat, String> {
    if let Some(fmt) = get_opt_arg(args, "-f") {
        return match fmt {
            "bmp" => Ok(StegoFormat::Bmp),
            "png" => Ok(StegoFormat::Png),
            "wav" => Ok(StegoFormat::Wav),
            other => Err(format!("unknown format '{}', use bmp/png/wav", other)),
        };
    }
    if let Some(carrier_path) = get_opt_arg(args, "-c") {
        let lower = carrier_path.to_lowercase();
        if lower.ends_with(".bmp") { return Ok(StegoFormat::Bmp); }
        if lower.ends_with(".png") { return Ok(StegoFormat::Png); }
        if lower.ends_with(".wav") { return Ok(StegoFormat::Wav); }
    }
    Err("cannot detect format; use -f <bmp|png|wav>".into())
}

fn cmd_stego(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: stego <embed|extract|detect|capacity> ...".into());
    }
    match args[0].as_str() {
        "embed" => cmd_stego_embed(&args[1..]),
        "extract" => cmd_stego_extract(&args[1..]),
        "detect" => cmd_stego_detect(&args[1..]),
        "capacity" => cmd_stego_capacity(&args[1..]),
        other => Err(format!("unknown stego subcommand: {}", other)),
    }
}

fn cmd_stego_embed(args: &[String]) -> Result<(), String> {
    let carrier_path = require_arg(args, "-c", "-c carrier")?;
    let payload_path = require_arg(args, "-i", "-i payload")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let format = detect_format(args)?;

    let carrier_data = read_input(carrier_path)?;
    let payload_data = read_input(payload_path)?;

    match format {
        StegoFormat::Bmp => {
            let mut bmp = cipher_stego::bmp::BmpFile::parse(&carrier_data)
                .map_err(|e| format!("BMP parse: {}", e))?;
            bmp.embed(&payload_data).map_err(|e| format!("BMP embed: {}", e))?;
            write_output(output_path, &bmp.data)?;
        }
        StegoFormat::Png => {
            let mut png = cipher_stego::png::PngFile::parse(&carrier_data)
                .map_err(|e| format!("PNG parse: {}", e))?;
            png.embed(&payload_data).map_err(|e| format!("PNG embed: {}", e))?;
            write_output(output_path, &png.data)?;
        }
        StegoFormat::Wav => {
            let mut wav = cipher_stego::wav::WavFile::parse(&carrier_data)
                .map_err(|e| format!("WAV parse: {}", e))?;
            wav.embed(&payload_data).map_err(|e| format!("WAV embed: {}", e))?;
            write_output(output_path, &wav.data)?;
        }
    }
    print_success(&format!("embedded {} bytes in {} carrier", payload_data.len(), format));
    Ok(())
}

fn cmd_stego_extract(args: &[String]) -> Result<(), String> {
    let carrier_path = require_arg(args, "-c", "-c carrier")?;
    let output_path = require_arg(args, "-o", "-o output")?;
    let format = detect_format(args)?;

    let carrier_data = read_input(carrier_path)?;
    let payload = match format {
        StegoFormat::Bmp => {
            let bmp = cipher_stego::bmp::BmpFile::parse(&carrier_data)
                .map_err(|e| format!("BMP parse: {}", e))?;
            bmp.extract().map_err(|e| format!("BMP extract: {}", e))?
        }
        StegoFormat::Png => {
            let png = cipher_stego::png::PngFile::parse(&carrier_data)
                .map_err(|e| format!("PNG parse: {}", e))?;
            png.extract().map_err(|e| format!("PNG extract: {}", e))?
        }
        StegoFormat::Wav => {
            let wav = cipher_stego::wav::WavFile::parse(&carrier_data)
                .map_err(|e| format!("WAV parse: {}", e))?;
            wav.extract().map_err(|e| format!("WAV extract: {}", e))?
        }
    };
    write_output(output_path, &payload)?;
    print_success(&format!("extracted {} bytes from {} carrier", payload.len(), format));
    Ok(())
}

fn cmd_stego_detect(args: &[String]) -> Result<(), String> {
    let carrier_path = require_arg(args, "-c", "-c carrier")?;
    let format = detect_format(args)?;
    let carrier_data = read_input(carrier_path)?;

    let lsb_data: Vec<u8> = match format {
        StegoFormat::Bmp => {
            let bmp = cipher_stego::bmp::BmpFile::parse(&carrier_data)
                .map_err(|e| format!("BMP parse: {}", e))?;
            bmp.pixel_data().to_vec()
        }
        StegoFormat::Png => {
            let png = cipher_stego::png::PngFile::parse(&carrier_data)
                .map_err(|e| format!("PNG parse: {}", e))?;
            png.raw_bytes().to_vec()
        }
        StegoFormat::Wav => {
            let wav = cipher_stego::wav::WavFile::parse(&carrier_data)
                .map_err(|e| format!("WAV parse: {}", e))?;
            wav.sample_data().to_vec()
        }
    };

    let score = cipher_stego::detect_lsb_stego(&lsb_data);
    let label = if score > 0.7 {
        format!("{}{:.4} -- likely steganographic content{}", RED, score, RESET)
    } else if score > 0.3 {
        format!("{}{:.4} -- possible steganographic content{}", YELLOW, score, RESET)
    } else {
        format!("{}{:.4} -- unlikely steganographic content{}", GREEN, score, RESET)
    };
    println!("LSB stego detection score: {}", label);
    Ok(())
}

fn cmd_stego_capacity(args: &[String]) -> Result<(), String> {
    let carrier_path = require_arg(args, "-c", "-c carrier")?;
    let format = detect_format(args)?;
    let carrier_data = read_input(carrier_path)?;

    let cap = match format {
        StegoFormat::Bmp => {
            let bmp = cipher_stego::bmp::BmpFile::parse(&carrier_data)
                .map_err(|e| format!("BMP parse: {}", e))?;
            bmp.capacity()
        }
        StegoFormat::Png => {
            let png = cipher_stego::png::PngFile::parse(&carrier_data)
                .map_err(|e| format!("PNG parse: {}", e))?;
            png.capacity()
        }
        StegoFormat::Wav => {
            let wav = cipher_stego::wav::WavFile::parse(&carrier_data)
                .map_err(|e| format!("WAV parse: {}", e))?;
            wav.capacity()
        }
    };
    println!("{} carrier capacity: {} bytes ({:.2} KB)", format, cap, cap as f64 / 1024.0);
    Ok(())
}

// ── X25519 ─────────────────────────────────────────────────────────────

fn cmd_x25519(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: x25519 <keygen|derive>".into());
    }
    match args[0].as_str() {
        "keygen" => cmd_x25519_keygen(),
        "derive" => cmd_x25519_derive(&args[1..]),
        other => Err(format!("unknown x25519 subcommand: {}", other)),
    }
}

fn cmd_x25519_keygen() -> Result<(), String> {
    let (private, public) = curve25519::x25519_keypair();
    println!("{}Private (hex):{} {}", BOLD, RESET, hex_encode(&private));
    println!("{}Public (hex):{}  {}", BOLD, RESET, hex_encode(&public));
    print_warn("Store the private key securely. The public key can be shared.");
    Ok(())
}

fn cmd_x25519_derive(args: &[String]) -> Result<(), String> {
    let secret_hex = require_arg(args, "--secret", "--secret hex")?;
    let public_hex = require_arg(args, "--public", "--public hex")?;

    let secret_bytes = hex_decode(secret_hex).map_err(|e| format!("invalid secret hex: {}", e))?;
    let public_bytes = hex_decode(public_hex).map_err(|e| format!("invalid public hex: {}", e))?;

    if secret_bytes.len() != 32 {
        return Err(format!("secret must be 32 bytes, got {}", secret_bytes.len()));
    }
    if public_bytes.len() != 32 {
        return Err(format!("public must be 32 bytes, got {}", public_bytes.len()));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let mut public = [0u8; 32];
    public.copy_from_slice(&public_bytes);

    let shared = curve25519::x25519(&secret, &public);
    println!("{}Shared secret (hex):{} {}", BOLD, RESET, hex_encode(&shared));
    Ok(())
}

// ── Ed25519 ────────────────────────────────────────────────────────────

fn cmd_ed25519(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: ed25519 <keygen|sign|verify>".into());
    }
    match args[0].as_str() {
        "keygen" => cmd_ed25519_keygen(),
        "sign" => cmd_ed25519_sign(&args[1..]),
        "verify" => cmd_ed25519_verify(&args[1..]),
        other => Err(format!("unknown ed25519 subcommand: {}", other)),
    }
}

fn cmd_ed25519_keygen() -> Result<(), String> {
    let (priv_key, pub_key) = curve25519::Ed25519PrivateKey::generate();
    println!("{}Private key (scalar, hex):{} {}", BOLD, RESET, hex_encode(priv_key.as_scalar_bytes()));
    println!("{}Public key (hex):{}  {}", BOLD, RESET, hex_encode(pub_key.as_bytes()));
    print_warn("Store the private key securely. The public key can be shared.");
    Ok(())
}

fn cmd_ed25519_sign(args: &[String]) -> Result<(), String> {
    let key_hex = require_arg(args, "--key", "--key hex (private key seed)")?;
    let message_path = require_arg(args, "-i", "-i message file")?;

    let key_bytes = hex_decode(key_hex).map_err(|e| format!("invalid key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!("private key seed must be 32 bytes, got {}", key_bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);

    let (priv_key, _) = curve25519::Ed25519PrivateKey::from_seed(&seed);
    let message = read_input(message_path)?;
    let sig = priv_key.sign(&message);

    println!("{}Signature (hex):{} {}", BOLD, RESET, hex_encode(sig.as_bytes()));
    Ok(())
}

fn cmd_ed25519_verify(args: &[String]) -> Result<(), String> {
    let key_hex = require_arg(args, "--key", "--key hex (public key)")?;
    let sig_hex = require_arg(args, "--sig", "--sig hex (signature)")?;
    let message_path = require_arg(args, "-i", "-i message file")?;

    let key_bytes = hex_decode(key_hex).map_err(|e| format!("invalid key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!("public key must be 32 bytes, got {}", key_bytes.len()));
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&key_bytes);

    let sig_bytes = hex_decode(sig_hex).map_err(|e| format!("invalid sig hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err(format!("signature must be 64 bytes, got {}", sig_bytes.len()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let pub_key = curve25519::Ed25519PublicKey::from_bytes(pub_arr);
    let sig = curve25519::Ed25519Signature::from_bytes(sig_arr);
    let message = read_input(message_path)?;

    if pub_key.verify(&message, &sig) {
        print_success("signature is VALID");
    } else {
        eprint_err("signature is INVALID");
        std::process::exit(1);
    }
    Ok(())
}

// ── Version / Help ─────────────────────────────────────────────────────

fn cmd_version() {
    println!("{}CIPHER{} v0.2.0", BOLD, RESET);
}

fn cmd_help() {
    let help = format!(
        "{b}CIPHER v0.2.0{r} - Encryption, hashing, steganography, and key management

{b}USAGE:{r}
  cipher <command> [options]

{b}COMMANDS:{r}
  {c}enc{r} <aes|chacha20> -i input -o output --key hex --nonce hex
      Encrypt data with AES-256-CTR or ChaCha20

  {c}dec{r} <aes|chacha20> -i input -o output --key hex --nonce hex
      Decrypt data with AES-256-CTR or ChaCha20

  {c}hash{r} <file|string>
      Compute SHA-256 hash

  {c}hmac{r} --key hex [file|string]
      Compute HMAC-SHA256

  {c}keygen{r} [--size N] [--count N] [--nonce]
      Generate random keys or nonces

  {c}container create{r} -p password -i input -o output
      Create encrypted container

  {c}container extract{r} -p password -i input -o output
      Extract from encrypted container

  {c}stego embed{r} -c carrier -i payload -o output [-f bmp|png|wav]
      Embed payload in carrier using LSB steganography

  {c}stego extract{r} -c carrier -o output [-f bmp|png|wav]
      Extract payload from carrier

  {c}stego detect{r} -c carrier [-f bmp|png|wav]
      Detect potential steganography

  {c}stego capacity{r} -c carrier [-f bmp|png|wav]
      Show carrier capacity in bytes

  {c}x25519 keygen{r}
      Generate X25519 key pair

  {c}x25519 derive{r} --secret hex --public hex
      Derive shared secret

  {c}ed25519 keygen{r}
      Generate Ed25519 key pair

  {c}ed25519 sign{r} --key hex -i message
      Sign a message

  {c}ed25519 verify{r} --key hex --sig hex -i message
      Verify a signature

  {c}version{r}
      Show version

  {c}help{r}
      Show this help message

Use {c}-{r} for stdin/stdout paths.",
        b = BOLD, r = RESET, c = CYAN
    );
    println!("{}", help);
}

// ── Main ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        cmd_help();
        std::process::exit(1);
    }

    let command = &args[1];
    let sub_args = &args[2..];

    let result = match command.as_str() {
        "enc" => cmd_enc(&sub_args.to_vec()),
        "dec" => cmd_dec(&sub_args.to_vec()),
        "hash" => cmd_hash(&sub_args.to_vec()),
        "hmac" => cmd_hmac(&sub_args.to_vec()),
        "keygen" => cmd_keygen(&sub_args.to_vec()),
        "container" => cmd_container(&sub_args.to_vec()),
        "stego" => cmd_stego(&sub_args.to_vec()),
        "x25519" => cmd_x25519(&sub_args.to_vec()),
        "ed25519" => cmd_ed25519(&sub_args.to_vec()),
        "version" | "-v" | "--version" => { cmd_version(); Ok(()) }
        "help" | "-h" | "--help" => { cmd_help(); Ok(()) }
        other => Err(format!("unknown command '{}'. Run 'cipher help' for usage.", other)),
    };

    if let Err(e) = result {
        eprint_err(&e);
        std::process::exit(1);
    }
}
