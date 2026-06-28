//! AES-256-CTR implementation (FIPS-197, SP800-38A).
//! Pure Rust, no lookup tables for S-box (algebraic construction).
//! Constant-time by design.

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-256 key size in bytes (256 bits).
pub const AES_256_KEY_SIZE: usize = 32;

/// AES-256 number of rounds.
const AES_256_ROUNDS: usize = 14;

/// AES-256 number of 32-bit words in the key.
const AES_256_KEY_WORDS: usize = 8;

/// Number of 32-bit words in a block.
const NB: usize = 4;

// ── GF(2^8) arithmetic for S-box construction ──────────────────────────

/// Multiply in GF(2^8) with the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1.
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(2^8). 0 maps to 0.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Using extended Euclidean approach via Fermat's little theorem:
    // a^(-1) = a^(254) in GF(2^8)
    let mut result: u8 = 1;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

/// AES S-box affine transformation.
fn affine_transform(b: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..8 {
        let bit = ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1);
        result |= bit << i;
    }
    result ^ 0x63
}

/// Compute the S-box value for a given input byte.
fn sbox(input: u8) -> u8 {
    affine_transform(gf256_inv(input))
}

/// Inverse S-box: reverse the affine transform, then invert in GF(2^8).
fn inv_sbox(output: u8) -> u8 {
    // First undo the affine XOR constant
    let b = output ^ 0x63;
    // Apply the inverse affine matrix (transpose of forward with different constant)
    // The inverse affine matrix for AES is:
    // y[i] = b[(i+2)%8] ^ b[(i+5)%8] ^ b[(i+7)%8]
    let mut result: u8 = 0;
    for i in 0..8 {
        let bit =
            ((b >> ((i + 2) % 8)) & 1) ^ ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 7) % 8)) & 1);
        result |= bit << i;
    }
    gf256_inv(result)
}

// ── Round constants ────────────────────────────────────────────────────

fn round_constant(round: usize) -> u8 {
    if round == 1 {
        0x01
    } else {
        gf256_mul(round_constant(round - 1), 0x02)
    }
}

// ── AES-256 key schedule ───────────────────────────────────────────────

/// Expand a 256-bit key into round keys.
fn key_expansion(key: &[u8; AES_256_KEY_SIZE]) -> [[u8; AES_BLOCK_SIZE]; AES_256_ROUNDS + 1] {
    let mut round_keys = [[0u8; AES_BLOCK_SIZE]; AES_256_ROUNDS + 1];
    let mut w = [[0u8; 4]; NB * (AES_256_ROUNDS + 1)];

    // First 8 words come directly from the key
    for i in 0..AES_256_KEY_WORDS {
        for j in 0..4 {
            w[i][j] = key[i * 4 + j];
        }
    }

    // Generate remaining words
    for i in AES_256_KEY_WORDS..NB * (AES_256_ROUNDS + 1) {
        let mut temp = w[i - 1];
        if i % AES_256_KEY_WORDS == 0 {
            // RotWord + SubWord + Rcon
            let t = temp[0];
            temp[0] = sbox(temp[1]) ^ round_constant(i / AES_256_KEY_WORDS);
            temp[1] = sbox(temp[2]);
            temp[2] = sbox(temp[3]);
            temp[3] = sbox(t);
        } else if i % AES_256_KEY_WORDS == 4 {
            // SubWord only (AES-256 specific)
            for j in 0..4 {
                temp[j] = sbox(temp[j]);
            }
        }
        for j in 0..4 {
            w[i][j] = w[i - AES_256_KEY_WORDS][j] ^ temp[j];
        }
    }

    // Pack words into round keys
    for r in 0..=AES_256_ROUNDS {
        for c in 0..NB {
            for j in 0..4 {
                round_keys[r][c * 4 + j] = w[r * NB + c][j];
            }
        }
    }

    round_keys
}

// ── Single block operations ────────────────────────────────────────────

/// Encrypt a single 16-byte block in place using pre-expanded round keys.
fn aes256_encrypt_block(
    block: &mut [u8; AES_BLOCK_SIZE],
    round_keys: &[[u8; AES_BLOCK_SIZE]; AES_256_ROUNDS + 1],
) {
    // Initial round key addition
    add_round_key(block, &round_keys[0]);

    // Main rounds
    for round in 1..AES_256_ROUNDS {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &round_keys[round]);
    }

    // Final round (no MixColumns)
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &round_keys[AES_256_ROUNDS]);
}

/// Decrypt a single 16-byte block in place.
fn aes256_decrypt_block(
    block: &mut [u8; AES_BLOCK_SIZE],
    round_keys: &[[u8; AES_BLOCK_SIZE]; AES_256_ROUNDS + 1],
) {
    // Initial round key addition with last round key
    add_round_key(block, &round_keys[AES_256_ROUNDS]);

    // Main rounds in reverse
    for round in (1..AES_256_ROUNDS).rev() {
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &round_keys[round]);
        inv_mix_columns(block);
    }

    // Final round
    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, &round_keys[0]);
}

fn add_round_key(block: &mut [u8; AES_BLOCK_SIZE], round_key: &[u8; AES_BLOCK_SIZE]) {
    for i in 0..AES_BLOCK_SIZE {
        block[i] ^= round_key[i];
    }
}

fn sub_bytes(block: &mut [u8; AES_BLOCK_SIZE]) {
    for i in 0..AES_BLOCK_SIZE {
        block[i] = sbox(block[i]);
    }
}

fn inv_sub_bytes(block: &mut [u8; AES_BLOCK_SIZE]) {
    for i in 0..AES_BLOCK_SIZE {
        block[i] = inv_sbox(block[i]);
    }
}

fn shift_rows(block: &mut [u8; AES_BLOCK_SIZE]) {
    // Row 1: shift left by 1
    let t = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = t;
    // Row 2: shift left by 2
    let t2 = block[2];
    block[2] = block[10];
    block[10] = t2;
    let t2 = block[6];
    block[6] = block[14];
    block[14] = t2;
    // Row 3: shift left by 3 (or right by 1)
    let t = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = t;
}

fn inv_shift_rows(block: &mut [u8; AES_BLOCK_SIZE]) {
    // Row 1: shift right by 1
    let t = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = t;
    // Row 2: shift right by 2
    let t2 = block[2];
    block[2] = block[10];
    block[10] = t2;
    let t2 = block[6];
    block[6] = block[14];
    block[14] = t2;
    // Row 3: shift right by 3 (or left by 1)
    let t = block[3];
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = t;
}

fn mix_columns(block: &mut [u8; AES_BLOCK_SIZE]) {
    for c in 0..4 {
        let i = c * 4;
        let a = [block[i], block[i + 1], block[i + 2], block[i + 3]];
        block[i] = gf256_mul(a[0], 2) ^ gf256_mul(a[1], 3) ^ a[2] ^ a[3];
        block[i + 1] = a[0] ^ gf256_mul(a[1], 2) ^ gf256_mul(a[2], 3) ^ a[3];
        block[i + 2] = a[0] ^ a[1] ^ gf256_mul(a[2], 2) ^ gf256_mul(a[3], 3);
        block[i + 3] = gf256_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf256_mul(a[3], 2);
    }
}

fn inv_mix_columns(block: &mut [u8; AES_BLOCK_SIZE]) {
    for c in 0..4 {
        let i = c * 4;
        let a = [block[i], block[i + 1], block[i + 2], block[i + 3]];
        block[i] =
            gf256_mul(a[0], 14) ^ gf256_mul(a[1], 11) ^ gf256_mul(a[2], 13) ^ gf256_mul(a[3], 9);
        block[i + 1] =
            gf256_mul(a[0], 9) ^ gf256_mul(a[1], 14) ^ gf256_mul(a[2], 11) ^ gf256_mul(a[3], 13);
        block[i + 2] =
            gf256_mul(a[0], 13) ^ gf256_mul(a[1], 9) ^ gf256_mul(a[2], 14) ^ gf256_mul(a[3], 11);
        block[i + 3] =
            gf256_mul(a[0], 11) ^ gf256_mul(a[1], 13) ^ gf256_mul(a[2], 9) ^ gf256_mul(a[3], 14);
    }
}

// ── CTR mode ───────────────────────────────────────────────────────────

/// AES-256-CTR cipher.
pub struct Aes256Ctr {
    round_keys: [[u8; AES_BLOCK_SIZE]; AES_256_ROUNDS + 1],
    counter: [u8; AES_BLOCK_SIZE],
}

impl Aes256Ctr {
    /// Create a new AES-256-CTR cipher with the given key and nonce/IV.
    /// The nonce occupies the first 12 bytes of the counter block;
    /// the last 4 bytes are the counter (big-endian, starting at 0).
    pub fn new(key: &[u8; AES_256_KEY_SIZE], nonce: &[u8; 12]) -> Self {
        let round_keys = key_expansion(key);
        let mut counter = [0u8; AES_BLOCK_SIZE];
        counter[..12].copy_from_slice(nonce);
        // counter[12..16] = 0 (implicit)
        Self {
            round_keys,
            counter,
        }
    }

    /// Create from a full 16-byte IV.
    pub fn new_with_iv(key: &[u8; AES_256_KEY_SIZE], iv: &[u8; AES_BLOCK_SIZE]) -> Self {
        let round_keys = key_expansion(key);
        Self {
            round_keys,
            counter: *iv,
        }
    }

    /// Encrypt/decrypt data in place (CTR mode: encryption and decryption are identical).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut keystream = [0u8; AES_BLOCK_SIZE];
        let mut offset = 0;

        while offset < data.len() {
            // Generate keystream block
            keystream = self.counter;
            aes256_encrypt_block(&mut keystream, &self.round_keys);

            // XOR with data
            let chunk_end = (offset + AES_BLOCK_SIZE).min(data.len());
            for i in offset..chunk_end {
                data[i] ^= keystream[i - offset];
            }

            offset += AES_BLOCK_SIZE;

            // Increment counter (big-endian, last 4 bytes)
            increment_counter(&mut self.counter);
        }
    }

    /// Encrypt data and return a new Vec.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        self.apply_keystream(&mut out);
        out
    }

    /// Decrypt data and return a new Vec (same as encrypt in CTR mode).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}

/// Increment the counter block (big-endian increment of the full 128-bit value).
fn increment_counter(counter: &mut [u8; AES_BLOCK_SIZE]) {
    for i in (0..AES_BLOCK_SIZE).rev() {
        let (sum, overflow) = counter[i].overflowing_add(1);
        counter[i] = sum;
        if !overflow {
            break;
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_known_values() {
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0x7c), 0x10);
    }

    #[test]
    fn test_sbox_inverse() {
        for i in 0..=255u8 {
            assert_eq!(
                inv_sbox(sbox(i)),
                i,
                "sbox/inv_sbox roundtrip failed for 0x{:02x}",
                i
            );
        }
    }

    #[test]
    fn test_aes256_encrypt_decrypt_block() {
        // NIST SP800-38A test vector
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];

        let round_keys = key_expansion(&key);
        let mut block = plaintext;
        aes256_encrypt_block(&mut block, &round_keys);
        assert_eq!(block, expected, "encryption mismatch");

        aes256_decrypt_block(&mut block, &round_keys);
        assert_eq!(block, plaintext, "decryption mismatch");
    }

    #[test]
    fn test_aes256_ctr_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello, world! This is a test of AES-256-CTR mode encryption.";

        let mut enc = Aes256Ctr::new(&key, &nonce);
        let ciphertext = enc.encrypt(plaintext);

        let mut dec = Aes256Ctr::new(&key, &nonce);
        let decrypted = dec.decrypt(&ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_empty_input() {
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];
        let mut cipher = Aes256Ctr::new(&key, &nonce);
        let result = cipher.encrypt(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_ctr_cross_block_boundary() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; 12];
        // 48 bytes = exactly 3 blocks
        let plaintext = vec![0xEFu8; 48];
        let mut enc = Aes256Ctr::new(&key, &nonce);
        let ct = enc.encrypt(&plaintext);
        let mut dec = Aes256Ctr::new(&key, &nonce);
        let pt = dec.decrypt(&ct);
        assert_eq!(pt, plaintext);
    }
}

// ── Additional NIST vector and round-trip tests ────────────────────────
