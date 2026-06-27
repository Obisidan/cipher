//! Error types for cipher-core.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// Input data is too short or too long for the operation
    InvalidLength,
    /// Authentication tag verification failed (tampered data)
    AuthenticationFailed,
    /// Invalid key size for the chosen algorithm
    InvalidKeySize { expected: usize, got: usize },
    /// Invalid nonce/IV size
    InvalidNonceSize { expected: usize, got: usize },
    /// Entropy source failure
    EntropyError,
    /// Invalid encoding (hex/base64 parse failure)
    InvalidEncoding,
    /// Steganography carrier too small for payload
    CarrierTooSmall,
    /// Invalid format or corrupted data
    InvalidFormat,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid input length"),
            Self::AuthenticationFailed => write!(f, "authentication failed: data may be tampered"),
            Self::InvalidKeySize { expected, got } => {
                write!(f, "invalid key size: expected {}, got {}", expected, got)
            }
            Self::InvalidNonceSize { expected, got } => {
                write!(f, "invalid nonce size: expected {}, got {}", expected, got)
            }
            Self::EntropyError => write!(f, "system entropy source unavailable"),
            Self::InvalidEncoding => write!(f, "invalid encoding"),
            Self::CarrierTooSmall => write!(f, "carrier too small for payload"),
            Self::InvalidFormat => write!(f, "invalid or corrupted data format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CipherError {}
