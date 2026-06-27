//! Steganography: LSB embedding in PNG, BMP, WAV files.
//! Pure Rust, no external deps.

pub mod bmp;
pub mod png;
pub mod wav;

pub use cipher_core::CipherError;

/// Calculate the maximum payload size (in bytes) for a given carrier size (in bits).
pub fn capacity_bits_to_bytes(carrier_bits: usize) -> usize {
    carrier_bits / 8
}

/// Calculate the required carrier size (in bits) for a given payload size (in bytes).
pub fn bytes_to_capacity_bits(payload_bytes: usize) -> usize {
    payload_bytes * 8
}

/// Embed a payload into a carrier using LSB substitution.
/// Each bit of the payload replaces the least significant bit of a carrier byte.
pub fn lsb_embed(carrier: &mut [u8], payload: &[u8]) -> Result<(), CipherError> {
    let total_bits = payload.len() * 8;
    if total_bits > carrier.len() {
        return Err(CipherError::CarrierTooSmall);
    }

    for (bit_idx, bit) in payload
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| (byte >> (7 - i)) & 1))
        .enumerate()
    {
        carrier[bit_idx] = (carrier[bit_idx] & 0xFE) | bit;
    }

    Ok(())
}

/// Extract a payload from a carrier using LSB extraction.
pub fn lsb_extract(carrier: &[u8], payload_len_bytes: usize) -> Vec<u8> {
    let total_bits = payload_len_bytes * 8;
    let mut result = vec![0u8; payload_len_bytes];

    for bit_idx in 0..total_bits.min(carrier.len()) {
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        result[byte_idx] |= (carrier[bit_idx] & 1) << bit_pos;
    }

    result
}

/// Calculate the Shannon entropy of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Detect potential steganography by analyzing LSB entropy.
/// Returns a score from 0.0 (definitely not stego) to 1.0 (likely stego).
pub fn detect_lsb_stego(data: &[u8]) -> f64 {
    let lsb_entropy = shannon_entropy(&data.iter().map(|&b| b & 1).collect::<Vec<_>>());
    let msb_entropy = shannon_entropy(&data.iter().map(|&b| (b >> 7) & 1).collect::<Vec<_>>());

    // If LSB entropy is significantly lower than MSB entropy, it might indicate stego
    if msb_entropy > 0.0 {
        1.0 - (lsb_entropy / msb_entropy)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsb_embed_extract() {
        let mut carrier = vec![0xFFu8; 256];
        let payload = b"Hello, World!";

        lsb_embed(&mut carrier, payload).unwrap();
        let extracted = lsb_extract(&carrier, payload.len());

        assert_eq!(extracted, payload.to_vec());
    }

    #[test]
    fn test_lsb_carrier_too_small() {
        let mut carrier = vec![0xFFu8; 4];
        let payload = b"Hello, World!";

        assert!(matches!(
            lsb_embed(&mut carrier, payload),
            Err(CipherError::CarrierTooSmall)
        ));
    }

    #[test]
    fn test_shannon_entropy() {
        // Constant data has zero entropy
        assert!(shannon_entropy(&[0u8; 100]) < 0.001);

        // Random data has high entropy
        let random: Vec<u8> = (0..256).map(|i| i as u8).collect();
        assert!(shannon_entropy(&random) > 7.0);
    }
}
