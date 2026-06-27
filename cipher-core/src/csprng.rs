//! Cryptographically secure random number generation.
//! Thin wrapper over OS entropy (getrandom).

use crate::error::CipherError;

/// Fill `dest` with cryptographically secure random bytes.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), CipherError> {
    getrandom::getrandom(dest).map_err(|_| CipherError::EntropyError)
}

/// Generate a random 32-bit unsigned integer.
pub fn random_u32() -> Result<u32, CipherError> {
    let mut buf = [0u8; 4];
    random_bytes(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Generate a random 64-bit unsigned integer.
pub fn random_u64() -> Result<u64, CipherError> {
    let mut buf = [0u8; 8];
    random_bytes(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Generate a random byte in range [0, 256).
pub fn random_u8() -> Result<u8, CipherError> {
    let mut buf = [0u8; 1];
    random_bytes(&mut buf)?;
    Ok(buf[0])
}

/// Generate a random nonce of the given size.
pub fn random_nonce(size: usize) -> Result<Vec<u8>, CipherError> {
    let mut nonce = vec![0u8; size];
    random_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random key of the given size.
pub fn random_key(size: usize) -> Result<Vec<u8>, CipherError> {
    random_nonce(size)
}

/// Fill a fixed-size array with random bytes (const-generic).
pub fn random_array<const N: usize>() -> Result<[u8; N], CipherError> {
    let mut arr = [0u8; N];
    random_bytes(&mut arr)?;
    Ok(arr)
}
