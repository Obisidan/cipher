//! Core cryptographic primitives for CIPHER.
//! Pure Rust, no_std compatible, zero external crypto dependencies.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod aes;
pub mod bytes;
pub mod chacha20;
pub mod constant_time;
pub mod csprng;
pub mod encoding;
pub mod error;
pub mod hkdf;
pub mod sha256;

pub use error::CipherError;
