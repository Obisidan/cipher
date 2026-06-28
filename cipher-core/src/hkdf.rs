//! HKDF-SHA256 (RFC 5869). Pure Rust, no external deps.

use crate::sha256::{sha256, SHA256_DIGEST_SIZE};

/// HKDF-Extract: extract a pseudo-random key from input keying material and salt.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand: expand a pseudo-random key to the desired length.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, ()> {
    if length > 255 * SHA256_DIGEST_SIZE {
        return Err(());
    }

    let n = (length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    let mut output = Vec::with_capacity(n * SHA256_DIGEST_SIZE);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut data = t.clone();
        data.extend_from_slice(info);
        data.push(i as u8);
        t = hmac_sha256(prk, &data).to_vec();
        output.extend_from_slice(&t);
    }

    output.truncate(length);
    Ok(output)
}

/// Full HKDF: extract + expand.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, ()> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    const BLOCK_SIZE: usize = 64;

    let mut key_padded = if key.len() > BLOCK_SIZE {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    key_padded.resize(BLOCK_SIZE, 0);

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + SHA256_DIGEST_SIZE);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    #[test]
    fn test_hmac_sha256_rfc4231() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        assert_eq!(
            hex_encode(&result),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_hkdf_rfc5869_test1() {
        let ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let salt_hex = "000102030405060708090a0b0c";
        let info_hex = "f0f1f2f3f4f5f6f7f8f9";

        let ikm = hex_decode(ikm_hex).unwrap();
        let salt = hex_decode(salt_hex).unwrap();
        let info = hex_decode(info_hex).unwrap();
        let length = 42usize;

        let okm = hkdf_sha256(&salt, &ikm, &info, length).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_hkdf_long_output() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"context and application";
        let length = 64usize;

        let okm = hkdf_sha256(salt, ikm, info, length).unwrap();
        assert_eq!(okm.len(), 64);
        let okm2 = hkdf_sha256(salt, ikm, info, length).unwrap();
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_hmac_sha256_64byte_key() {
        let key = [0x01u8; 64];
        let data = b"test data";
        let result = hmac_sha256(&key, data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        let long_key = vec![0x02u8; 100];
        let data = b"test data";
        let result = hmac_sha256(&long_key, data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_empty() {
        let key = b"key";
        let result = hmac_sha256(key, b"");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_sha256_empty() {
        let key = b"";
        let result = hmac_sha256(key, b"data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_only() {
        let salt = b"salt";
        let ikm = b"input keying material";
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), 32);
    }

    #[test]
    fn test_hkdf_max_output() {
        let ikm = b"ikm";
        let salt = b"salt";
        let info = b"info";
        let length = 255 * 32 - 1;
        let okm = hkdf_sha256(salt, ikm, info, length);
        assert!(okm.is_ok());
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
        crate::encoding::hex_decode(hex).map_err(|_| ())
    }
}
// ── Additional RFC 5869 test vectors ───────────────────────────────────
