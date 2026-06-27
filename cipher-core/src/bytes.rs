//! Low-level byte manipulation utilities.

/// Securely zero a byte slice. Uses a volatile write to prevent
/// the compiler from optimizing away the zeroing.
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // SAFETY: writing to a valid mutable reference
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    // Fence to prevent reordering
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// XOR two byte slices in place. `dst` must be at least as long as `src`.
/// Returns the number of bytes XORed.
pub fn xor_in_place(dst: &mut [u8], src: &[u8]) -> usize {
    let len = dst.len().min(src.len());
    for i in 0..len {
        dst[i] ^= src[i];
    }
    len
}

/// XOR two byte slices into a new Vec. Panics if lengths differ.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "xor inputs must have equal length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Rotate a 32-bit integer left by n bits.
#[inline(always)]
pub fn rotl32(val: u32, n: u32) -> u32 {
    val.rotate_left(n)
}

/// Rotate a 64-bit integer left by n bits.
#[inline(always)]
pub fn rotl64(val: u64, n: u32) -> u64 {
    val.rotate_left(n)
}

/// Read a big-endian u32 from a 4-byte slice.
#[inline(always)]
pub fn read_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Read a little-endian u32 from a 4-byte slice.
#[inline(always)]
pub fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Read a little-endian u64 from an 8-byte slice.
#[inline(always)]
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Write a big-endian u32 into a 4-byte slice.
#[inline(always)]
pub fn write_u32_be(out: &mut [u8], val: u32) {
    let b = val.to_be_bytes();
    out[0] = b[0];
    out[1] = b[1];
    out[2] = b[2];
    out[3] = b[3];
}

/// Write a little-endian u32 into a 4-byte slice.
#[inline(always)]
pub fn write_u32_le(out: &mut [u8], val: u32) {
    let b = val.to_le_bytes();
    out[0] = b[0];
    out[1] = b[1];
    out[2] = b[2];
    out[3] = b[3];
}

/// Write a little-endian u64 into an 8-byte slice.
#[inline(always)]
pub fn write_u64_le(out: &mut [u8], val: u64) {
    let b = val.to_le_bytes();
    out.copy_from_slice(&b);
}
