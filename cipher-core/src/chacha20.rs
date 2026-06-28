//! ChaCha20 stream cipher (RFC 8439). Pure Rust, no external deps.

use crate::bytes::{read_u32_le, write_u32_le};

/// ChaCha20 key size in bytes (256 bits).
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96 bits as per RFC 8439).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20 block size in bytes.
const CHACHA20_BLOCK_SIZE: usize = 64;

/// The ChaCha20 constant "expand 32-byte k" as four little-endian u32 words.
const CHACHA_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// A quarter-round operation on four words of the state.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate one 64-byte keystream block.
fn chacha20_block(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; CHACHA20_NONCE_SIZE],
    counter: u32,
) -> [u8; CHACHA20_BLOCK_SIZE] {
    let mut state = [0u32; 16];

    // Constants
    state[0..4].copy_from_slice(&CHACHA_CONSTANTS);

    // Key (8 words, little-endian)
    for i in 0..8 {
        state[4 + i] = read_u32_le(&key[i * 4..(i + 1) * 4]);
    }

    // Counter
    state[12] = counter;

    // Nonce (3 words, little-endian)
    state[13] = read_u32_le(&nonce[0..4]);
    state[14] = read_u32_le(&nonce[4..8]);
    state[15] = read_u32_le(&nonce[8..12]);

    let initial_state = state;

    // 20 rounds (10 double-rounds: column + diagonal)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    // Serialize to bytes
    let mut output = [0u8; CHACHA20_BLOCK_SIZE];
    for i in 0..16 {
        write_u32_le(&mut output[i * 4..(i + 1) * 4], state[i]);
    }
    output
}

/// ChaCha20 cipher.
pub struct ChaCha20 {
    key: [u8; CHACHA20_KEY_SIZE],
    nonce: [u8; CHACHA20_NONCE_SIZE],
    counter: u32,
}

impl ChaCha20 {
    /// Create a new ChaCha20 cipher.
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE]) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter: 0,
        }
    }

    /// Create with a specific initial counter value.
    pub fn with_counter(
        key: &[u8; CHACHA20_KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        counter: u32,
    ) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter,
        }
    }

    /// Apply the keystream to data in place (encrypt or decrypt — same operation).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let block = chacha20_block(&self.key, &self.nonce, self.counter);
            self.counter += 1;

            let chunk_end = (offset + CHACHA20_BLOCK_SIZE).min(data.len());
            for i in offset..chunk_end {
                data[i] ^= block[i - offset];
            }
            offset += CHACHA20_BLOCK_SIZE;
        }
    }

    /// Encrypt data and return a new Vec.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        self.apply_keystream(&mut out);
        out
    }

    /// Decrypt data and return a new Vec (same as encrypt for stream ciphers).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    #[test]
    fn test_chacha20_rfc8439_block_vector() {
        // RFC 8439 Section 2.3.2 — all-zero key, counter=0
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let block = chacha20_block(&key, &nonce, 0);
        let expected = "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";

        assert_eq!(hex_encode(&block), expected);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0xDEu8; 32];
        let nonce = [0xADu8; 12];
        let plaintext = b"The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()";

        let mut enc = ChaCha20::new(&key, &nonce);
        let ct = enc.encrypt(plaintext);

        let mut dec = ChaCha20::new(&key, &nonce);
        let pt = dec.decrypt(&ct);

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_chacha20_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut cipher = ChaCha20::new(&key, &nonce);
        let result = cipher.encrypt(b"");
        assert!(result.is_empty());
    }
}

// ── Additional RFC 8439 test vectors and round-trip tests ──────────────
