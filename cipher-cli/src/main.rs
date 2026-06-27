//! CIPHER — Zero-dep Rust cryptography & steganography suite
//! Command-line interface with Sayori-themed output.

use std::env;
use std::process::ExitCode;

const VERSION: &str = "0.1.0";

const BANNER: &str = r#"
 ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░
"#;

const PINK: &str = "\x1b[38;5;213m";
const CYAN: &str = "\x1b[38;5;87m";
const GREEN: &str = "\x1b[38;5;120m";
const YELLOW: &str = "\x1b[38;5;228m";
const RED: &str = "\x1b[38;5;204m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

fn print_banner() {
    println!("{}{}{}", PINK, BANNER, RESET);
    println!(
        "  {}🌸 {}CIPHER v{}{} — zero-dep crypto & stego suite{} 🌸",
        PINK, CYAN, VERSION, PINK, RESET
    );
    println!("  {}hehe i make stuffz{}\n", YELLOW, RESET);
}

fn print_usage() {
    println!("  {}Usage: cipher <command> [options]{}", BOLD, RESET);
    println!();
    println!("  {}Commands:{}", BOLD, RESET);
    println!(
        "    {}enc{}        Encrypt data with AES-256-CTR",
        CYAN, RESET
    );
    println!(
        "    {}dec{}        Decrypt data with AES-256-CTR",
        CYAN, RESET
    );
    println!("    {}hash{}       Compute SHA-256 hash", CYAN, RESET);
    println!(
        "    {}keygen{}     Generate random keys/nonces",
        CYAN, RESET
    );
    println!(
        "    {}container{}  Create/extract encrypted containers",
        CYAN, RESET
    );
    println!("    {}stego{}      Steganography operations", CYAN, RESET);
    println!("    {}version{}    Show version info", CYAN, RESET);
    println!();
    println!("  {}Options:{}", BOLD, RESET);
    println!("    {}--help{}      Show this help message", CYAN, RESET);
    println!("    {}--version{}   Show version", CYAN, RESET);
}

fn cmd_enc(args: &[String]) {
    if args.len() < 2 {
        println!(
            "  {}Usage: cipher enc <input> <output> [--key <hex>] [--nonce <hex>]{}",
            YELLOW, RESET
        );
        return;
    }
    println!("  {}🔒 Encrypting...{}", CYAN, RESET);
    println!("  {}   Input:  {}{}", PINK, args[0], RESET);
    println!("  {}   Output: {}{}", PINK, args[1], RESET);
    println!(
        "  {}   (Full implementation coming in v0.2){}",
        YELLOW, RESET
    );
}

fn cmd_dec(args: &[String]) {
    if args.len() < 2 {
        println!(
            "  {}Usage: cipher dec <input> <output> [--key <hex>] [--nonce <hex>]{}",
            YELLOW, RESET
        );
        return;
    }
    println!("  {}🔓 Decrypting...{}", CYAN, RESET);
    println!("  {}   Input:  {}{}", PINK, args[0], RESET);
    println!("  {}   Output: {}{}", PINK, args[1], RESET);
    println!(
        "  {}   (Full implementation coming in v0.2){}",
        YELLOW, RESET
    );
}

fn cmd_hash(args: &[String]) {
    use cipher_core::encoding::hex_encode;
    use cipher_core::sha256::sha256;

    if args.is_empty() {
        // Hash stdin
        let input = b"CIPHER test input";
        let hash = sha256(input);
        println!("  {}🔐 SHA-256: {}{}", GREEN, hex_encode(&hash), RESET);
    } else {
        let input = args[0].as_bytes();
        let hash = sha256(input);
        println!(
            "  {}🔐 SHA-256({}): {}{}",
            GREEN,
            args[0],
            hex_encode(&hash),
            RESET
        );
    }
}

fn cmd_keygen(args: &[String]) {
    use cipher_core::csprng::random_array;
    use cipher_core::encoding::hex_encode;

    let size = if !args.is_empty() {
        args[0].parse::<usize>().unwrap_or(32)
    } else {
        32
    };

    if size <= 32 {
        let key = random_array::<32>().unwrap();
        println!(
            "  {}🔑 Key ({} bytes): {}{}",
            GREEN,
            size,
            hex_encode(&key[..size]),
            RESET
        );
    } else {
        use cipher_core::csprng::random_bytes;
        let mut key = vec![0u8; size];
        random_bytes(&mut key).unwrap();
        println!(
            "  {}🔑 Key ({} bytes): {}{}",
            GREEN,
            size,
            hex_encode(&key),
            RESET
        );
    }
}

fn cmd_container(args: &[String]) {
    if args.is_empty() {
        println!(
            "  {}Usage: cipher container <create|extract> [options]{}",
            YELLOW, RESET
        );
        return;
    }

    match args[0].as_str() {
        "create" => {
            println!("  {}📦 Creating encrypted container...{}", CYAN, RESET);
            println!(
                "  {}   (Full implementation coming in v0.2){}",
                YELLOW, RESET
            );
        }
        "extract" => {
            println!("  {}📦 Extracting encrypted container...{}", CYAN, RESET);
            println!(
                "  {}   (Full implementation coming in v0.2){}",
                YELLOW, RESET
            );
        }
        _ => {
            println!(
                "  {}❌ Unknown container command: {}{}",
                RED, args[0], RESET
            );
        }
    }
}

fn cmd_stego(args: &[String]) {
    if args.is_empty() {
        println!(
            "  {}Usage: cipher stego <embed|extract|detect> [options]{}",
            YELLOW, RESET
        );
        return;
    }

    match args[0].as_str() {
        "embed" => {
            println!("  {}🖼️  Embedding data...{}", CYAN, RESET);
            println!(
                "  {}   (Full implementation coming in v0.2){}",
                YELLOW, RESET
            );
        }
        "extract" => {
            println!("  {}🖼️  Extracting data...{}", CYAN, RESET);
            println!(
                "  {}   (Full implementation coming in v0.2){}",
                YELLOW, RESET
            );
        }
        "detect" => {
            println!("  {}🔍 Detecting steganography...{}", CYAN, RESET);
            println!(
                "  {}   (Full implementation coming in v0.2){}",
                YELLOW, RESET
            );
        }
        _ => {
            println!("  {}❌ Unknown stego command: {}{}", RED, args[0], RESET);
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_banner();
        print_usage();
        return ExitCode::SUCCESS;
    }

    let command = args[1].as_str();
    let cmd_args = &args[2..];

    match command {
        "enc" | "encrypt" => cmd_enc(cmd_args),
        "dec" | "decrypt" => cmd_dec(cmd_args),
        "hash" | "sha256" => cmd_hash(cmd_args),
        "keygen" | "key" => cmd_keygen(cmd_args),
        "container" => cmd_container(cmd_args),
        "stego" | "steganography" => cmd_stego(cmd_args),
        "version" | "--version" | "-V" => {
            print_banner();
        }
        "help" | "--help" | "-h" => {
            print_banner();
            print_usage();
        }
        _ => {
            println!("  {}❌ Unknown command: {}{}", RED, command, RESET);
            print_usage();
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}
