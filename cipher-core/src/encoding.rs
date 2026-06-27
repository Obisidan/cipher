//! Encoding/decoding utilities: hex, base64.

use crate::error::CipherError;

/// Encode bytes as lowercase hexadecimal.
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Decode a hex string into bytes. Accepts both lowercase and uppercase.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, CipherError> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(CipherError::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| CipherError::InvalidEncoding)?;
        out.push(byte);
    }
    Ok(out)
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as base64 (standard, with padding).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < data.len() {
        let n = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | (data[i + 2] as u32);
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 63) as usize] as char);
        out.push(B64_ALPHABET[(n & 63) as usize] as char);
        i += 3;
    }
    // Handle remaining 1 or 2 bytes
    if i < data.len() {
        let remaining = data.len() - i;
        if remaining == 1 {
            let n = (data[i] as u32) << 16;
            out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        } else {
            let n = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8;
            out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(B64_ALPHABET[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
    }
    out
}

/// Decode a base64 string into bytes. Handles padding and whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, CipherError> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if input.len() % 4 != 0 {
        return Err(CipherError::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits_collected: u8 = 0;

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = decode_b64_char(ch)?;
        buffer = (buffer << 6) | val as u32;
        bits_collected += 6;
        if bits_collected >= 8 {
            bits_collected -= 8;
            out.push(((buffer >> bits_collected) & 0xFF) as u8);
        }
    }
    Ok(out)
}

fn decode_b64_char(c: char) -> Result<u8, CipherError> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(c as u8 - b'a' + 26),
        '0'..='9' => Ok(c as u8 - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(CipherError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "68656c6c6f20776f726c64");
        assert_eq!(hex_decode(&encoded).unwrap(), data.to_vec());
    }

    #[test]
    fn test_base64_roundtrip() {
        let cases: Vec<&[u8]> = vec![b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for data in cases {
            let encoded = base64_encode(data);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }

    #[test]
    fn test_base64_known_values() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
    }
}
