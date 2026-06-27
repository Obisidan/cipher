//! HKDF-SHA256 (RFC 5869). Pure Rust, no external deps.

use crate::sha256::{sha256, SHA256_DIGEST_SIZE};

/// HKDF-Extract: extract a pseudo-random key from input keying material and salt.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    // HMAC-SHA256 with salt as key
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

    // Key padding
    let mut key_padded = if key.len() > BLOCK_SIZE {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    key_padded.resize(BLOCK_SIZE, 0);

    // Inner and outer padded keys
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    // HMAC = H(opad || H(ipad || message))
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
        // RFC 4231 Test Case 1
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
        // RFC 5869 Test Case 1
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex_decode("000102030405060708090a0b0c").unwrap();
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let length = 42u32 as usize;

        let okm = hkdf_sha256(&salt, &ikm, &info, length).unwrap();
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
        crate::encoding::hex_decode(hex).map_err(|_| ())
    }
}
