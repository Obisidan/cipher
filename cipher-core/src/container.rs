//! Encrypted container format.
//!
//! File layout:
//! [magic:8][version:1][kdf_salt:32][kdf_iterations:4][nonce:16]
//! [encrypted_header:48]  (contains: payload_length:8, reserved:32, hmac:32)
//! [encrypted_payload:N]
//! [hmac:32]
//!
//! Encryption: AES-256-CTR with key derived via HKDF-SHA256
//! Integrity: HMAC-SHA256 over entire file (except HMAC field)

use crate::aes::{Aes256Ctr, AES_256_KEY_SIZE};
use crate::error::CipherError;
use crate::hkdf::hkdf_sha256;
use crate::sha256::SHA256_DIGEST_SIZE;

const CIPHER_MAGIC: &[u8; 8] = b"CIPHER01";
const CONTAINER_VERSION: u8 = 1;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const HEADER_SIZE: usize = 48;
const HMAC_SIZE: usize = 32;
const DEFAULT_KDF_ITERATIONS: u32 = 100_000;

/// An encrypted container.
pub struct Container {
    salt: [u8; SALT_SIZE],
    kdf_iterations: u32,
    nonce: [u8; NONCE_SIZE],
    encrypted_payload: Vec<u8>,
    hmac: [u8; HMAC_SIZE],
}

impl Container {
    /// Create a new encrypted container from plaintext using a password.
    pub fn encrypt(password: &[u8], plaintext: &[u8]) -> Result<Self, CipherError> {
        use crate::csprng::{random_bytes, random_nonce};

        // Generate random salt and nonce
        let mut salt = [0u8; SALT_SIZE];
        random_bytes(&mut salt).map_err(|_| CipherError::EntropyError)?;
        let nonce = random_nonce(NONCE_SIZE).map_err(|_| CipherError::EntropyError)?;
        let mut nonce_arr = [0u8; NONCE_SIZE];
        nonce_arr.copy_from_slice(&nonce);

        // Derive key using HKDF-SHA256
        let iterations = DEFAULT_KDF_ITERATIONS;
        let mut info = Vec::new();
        info.extend_from_slice(b"CIPHER-AES-256-CTR-KEY");
        info.extend_from_slice(&iterations.to_be_bytes());
        let key_material = hkdf_sha256(
            &salt,
            password,
            &info,
            AES_256_KEY_SIZE + SHA256_DIGEST_SIZE,
        )
        .map_err(|_| CipherError::InvalidLength)?;

        let mut enc_key = [0u8; AES_256_KEY_SIZE];
        enc_key.copy_from_slice(&key_material[..AES_256_KEY_SIZE]);
        let mut hmac_key = [0u8; SHA256_DIGEST_SIZE];
        hmac_key.copy_from_slice(&key_material[AES_256_KEY_SIZE..]);

        // Encrypt payload
        let mut cipher = Aes256Ctr::new_with_iv(&enc_key, &nonce_arr);
        let encrypted_payload = cipher.encrypt(plaintext);

        // Build container
        let container = Self {
            salt,
            kdf_iterations: iterations,
            nonce: nonce_arr,
            encrypted_payload,
            hmac: [0u8; HMAC_SIZE], // placeholder
        };

        // Compute HMAC
        let hmac = container.compute_hmac(&hmac_key);

        Ok(Self { hmac, ..container })
    }

    /// Decrypt a container using a password.
    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Derive key using HKDF-SHA256
        let mut info = Vec::new();
        info.extend_from_slice(b"CIPHER-AES-256-CTR-KEY");
        info.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        let key_material = hkdf_sha256(
            &self.salt,
            password,
            &info,
            AES_256_KEY_SIZE + SHA256_DIGEST_SIZE,
        )
        .map_err(|_| CipherError::InvalidLength)?;

        let mut enc_key = [0u8; AES_256_KEY_SIZE];
        enc_key.copy_from_slice(&key_material[..AES_256_KEY_SIZE]);
        let mut hmac_key = [0u8; SHA256_DIGEST_SIZE];
        hmac_key.copy_from_slice(&key_material[AES_256_KEY_SIZE..]);

        // Verify HMAC
        let expected_hmac = self.compute_hmac(&hmac_key);
        if !crate::constant_time::eq(&expected_hmac, &self.hmac) {
            return Err(CipherError::AuthenticationFailed);
        }

        // Decrypt payload
        let mut cipher = Aes256Ctr::new_with_iv(&enc_key, &self.nonce);
        Ok(cipher.decrypt(&self.encrypted_payload))
    }

    /// Serialize the container to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(CIPHER_MAGIC);
        result.push(CONTAINER_VERSION);
        result.extend_from_slice(&self.salt);
        result.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.encrypted_payload);
        result.extend_from_slice(&self.hmac);
        result
    }

    /// Parse a container from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CipherError> {
        let min_size = 8 + 1 + SALT_SIZE + 4 + NONCE_SIZE + HMAC_SIZE;
        if data.len() < min_size {
            return Err(CipherError::InvalidFormat);
        }

        if &data[..8] != CIPHER_MAGIC {
            return Err(CipherError::InvalidFormat);
        }

        let version = data[8];
        if version != CONTAINER_VERSION {
            return Err(CipherError::InvalidFormat);
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[9..9 + SALT_SIZE]);

        let kdf_iterations = u32::from_be_bytes([
            data[9 + SALT_SIZE],
            data[10 + SALT_SIZE],
            data[11 + SALT_SIZE],
            data[12 + SALT_SIZE],
        ]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[13 + SALT_SIZE..13 + SALT_SIZE + NONCE_SIZE]);

        let payload_end = data.len() - HMAC_SIZE;
        let encrypted_payload = data[13 + SALT_SIZE + NONCE_SIZE..payload_end].to_vec();

        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&data[payload_end..]);

        Ok(Self {
            salt,
            kdf_iterations,
            nonce,
            encrypted_payload,
            hmac,
        })
    }

    /// Compute HMAC-SHA256 over the container (excluding the HMAC field).
    fn compute_hmac(&self, key: &[u8]) -> [u8; HMAC_SIZE] {
        let mut data = Vec::new();
        data.extend_from_slice(CIPHER_MAGIC);
        data.push(CONTAINER_VERSION);
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.encrypted_payload);
        crate::hkdf::hmac_sha256(key, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_roundtrip() {
        let password = b"correct horse battery staple";
        let plaintext = b"This is a secret message that will be encrypted in a container.";

        let container = Container::encrypt(password, plaintext).unwrap();
        let decrypted = container.decrypt(password).unwrap();

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_container_wrong_password() {
        let password = b"correct horse battery staple";
        let wrong_password = b"wrong password";
        let plaintext = b"Secret data";

        let container = Container::encrypt(password, plaintext).unwrap();
        let result = container.decrypt(wrong_password);

        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_container_serialization() {
        let password = b"test password";
        let plaintext = b"Serialization test data";

        let container = Container::encrypt(password, plaintext).unwrap();
        let bytes = container.to_bytes();
        let parsed = Container::from_bytes(&bytes).unwrap();
        let decrypted = parsed.decrypt(password).unwrap();

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_container_tampered() {
        let password = b"test password";
        let plaintext = b"Tamper test data";

        let mut container = Container::encrypt(password, plaintext).unwrap();
        // Tamper with the encrypted payload
        if !container.encrypted_payload.is_empty() {
            container.encrypted_payload[0] ^= 0xFF;
        }

        let result = container.decrypt(password);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }
}