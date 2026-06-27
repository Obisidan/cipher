//! Constant-time operations to prevent timing side-channels.

/// Compare two byte slices in constant time.
/// Returns true if they are equal, false otherwise.
/// The time taken is proportional to `a.len()`, not to the content.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Compare two u32 values in constant time.
/// Returns true if equal.
pub fn eq_u32(a: u32, b: u32) -> bool {
    let diff = a ^ b;
    // diff is 0 iff a == b. We need to OR all bits together.
    let mut acc = diff;
    acc |= diff >> 16;
    acc |= diff >> 8;
    acc |= diff >> 4;
    acc |= diff >> 2;
    acc |= diff >> 1;
    (acc & 1) == 0
}

/// Constant-time conditional copy.
/// If `condition` is true (non-zero), copy `src` into `dst`.
/// Otherwise, leave `dst` unchanged.
/// Both slices must have the same length.
pub fn conditional_copy(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let mask = if condition { 0xFFu8 } else { 0x00 };
    for i in 0..dst.len() {
        dst[i] = (dst[i] & !mask) | (src[i] & mask);
    }
}

/// Constant-time selection: returns `a` if `choice` is false, `b` if true.
pub fn select_u32(choice: bool, a: u32, b: u32) -> u32 {
    let mask = -(choice as i32) as u32;
    (a & !mask) | (b & mask)
}

/// Constant-time less-than comparison for u32.
/// Returns true if `a < b`.
pub fn lt_u32(a: u32, b: u32) -> bool {
    // If the high bit of (a - b) is set, then a < b (mod 2^32)
    let diff = a.wrapping_sub(b);
    ((diff ^ a ^ b) >> 31) == 1
}
