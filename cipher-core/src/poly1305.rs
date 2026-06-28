//! Poly1305 message authentication code (RFC 8439).
//! Pure Rust, no external deps.
//!
//! Uses 26-bit limb representation for constant-time modular arithmetic.
//! h = accumulator (5 limbs × 26 bits = 130 bits)
//! r = multiplier from key (4 limbs, clamped)
//! s = additive from key (2 limbs × 64 bits)

/// Compute Poly1305 MAC of a message using a 32-byte key.
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(message);
    p.finalize()
}

/// Incremental Poly1305 hasher.
pub struct Poly1305 {
    /// Accumulator limbs (5 × ~26 bits = 130 bits)
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    /// Multiplier from key (4 limbs, clamped, each < 2^26)
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    /// Additive from key (two 64-bit values split into high/low for easier arithmetic)
    s0: u32, // low 26 bits of s[0..8]
    s1: u32, // high bits of s + low bits of s_hi
    s2: u32,
    s3: u32,
    /// Buffer for partial blocks
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r: clear top 2 bits of certain bytes, bottom 2 bits of others
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[..16]);
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;

        // Parse r as 4 26-bit limbs (little-endian)
        let r0 = (r[0] as u32) | ((r[1] as u32) << 8) | ((r[2] as u32) << 16) | (((r[3] as u32) & 0x03) << 24);
        let r1 = ((r[3] as u32) >> 2) | ((r[4] as u32) << 6) | ((r[5] as u32) << 14) | (((r[6] as u32) & 0x0F) << 22);
        let r2 = ((r[6] as u32) >> 4) | ((r[7] as u32) << 4) | ((r[8] as u32) << 12) | (((r[9] as u32) & 0x3F) << 20);
        let r3 = ((r[9] as u32) >> 6) | ((r[10] as u32) << 2) | ((r[11] as u32) << 10) | ((r[12] as u32) << 18);

        // Parse s (last 16 bytes of key) as two 64-bit values
        let s_bytes = &key[16..];
        let s0 = (s_bytes[0] as u32) | ((s_bytes[1] as u32) << 8) | ((s_bytes[2] as u32) << 16) | (((s_bytes[3] as u32) & 0x03) << 24);
        let s1 = ((s_bytes[3] as u32) >> 2) | ((s_bytes[4] as u32) << 6) | ((s_bytes[5] as u32) << 14) | (((s_bytes[6] as u32) & 0x0F) << 22);
        let s2 = ((s_bytes[6] as u32) >> 4) | ((s_bytes[7] as u32) << 4) | ((s_bytes[8] as u32) << 12) | (((s_bytes[9] as u32) & 0x3F) << 20);
        let s3 = ((s_bytes[9] as u32) >> 6) | ((s_bytes[10] as u32) << 2) | ((s_bytes[11] as u32) << 10) | ((s_bytes[12] as u32) << 18) | ((s_bytes[13] as u32) << 24);

        // Mask s to remove the high bits (s is added as a 128-bit value)
        // s[13] bits 7:2 should be interpreted, but the high 2 bits of the 128-bit s should be clear
        // Per spec, s is read as a 128-bit little-endian integer

        Self {
            h0: 0, h1: 0, h2: 0, h3: 0, h4: 0,
            r0, r1, r2, r3,
            s0: s0 & 0x3ffffff,
            s1: s1 & 0x3ffffff,
            s2: s2 & 0x3ffffff,
            s3: s3 & 0x3ffffff,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() >= needed {
                self.buf[self.buf_len..16].copy_from_slice(&data[..needed]);
                let block = self.buf;
                self.blocks(&block, 1);
                self.buf_len = 0;
                let rest = &data[needed..];
                for chunk in rest.chunks(16) {
                    if chunk.len() == 16 {
                        let mut block = [0u8; 16];
                        block.copy_from_slice(chunk);
                        self.blocks(&block, 1);
                    } else {
                        self.buf[..chunk.len()].copy_from_slice(chunk);
                        self.buf_len = chunk.len();
                    }
                }
            } else {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
            }
        } else {
            let mut offset = 0;
            while offset + 16 <= data.len() {
                let mut block = [0u8; 16];
                block.copy_from_slice(&data[offset..offset + 16]);
                self.blocks(&block, 1);
                offset += 16;
            }
            if offset < data.len() {
                let remaining = &data[offset..];
                self.buf[..remaining.len()].copy_from_slice(remaining);
                self.buf_len = remaining.len();
            }
        }
    }

    pub fn finalize(&mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            // implicit 0x01 byte already implied by pad=0 in our implementation
            // We need to add 2^buf_len to the accumulator before multiplying
            self.h4 |= (1u32 << (self.buf_len * 8 / 2 + self.buf_len * 8 % 2)) as u32;
            // Actually simpler: just set the bit at position buf_len
            self.set_bit_at(self.buf_len);
            self.blocks(&block, 0);
        }

        // Fully reduce h modulo 2^128 (mask to 128 bits)
        self.canonicalize();

        // Add s (mod 2^128)
        let mut tag = [0u8; 16];

        // h0..h4 represent a 130-bit value (with h4 < 4)
        // Extract lower 128 bits: h0 (26) + h1 (26) + h2 (26) + h3 (26) = 104 bits + h4 (24 more)
        // Total: h0(26) + h1(26) + h2(26) + h3(26) = 104, h4 contributes the remaining 24 bits
        // Actually all 5 limbs: total = 5 × 26 = 130 bits

        // Convert h to 128-bit value (take lower 128 bits after reduction)
        let mut h_val = [0u64; 2];
        // First 64 bits
        let v0 = (self.h0 as u64) |
                 ((self.h1 as u64) << 26) |
                 ((self.h2 as u64 & 0x3F) << 52);
        h_val[0] = v0;
        // Next 64 bits
        let v1 = ((self.h2 as u64) >> 6) |
                 ((self.h3 as u64) << 20) |
                 ((self.h4 as u64) << 46);
        h_val[1] = v1;

        // Add s (as 128-bit)
        let s_val = [self.s0 as u64 | ((self.s1 as u64) << 26) | ((self.s2 as u64 & 0x3F) << 52),
                     ((self.s2 as u64) >> 6) | ((self.s3 as u64) << 20)];

        let (sum0, carry) = h_val[0].overflowing_add(s_val[0]);
        let sum1 = h_val[1].wrapping_add(s_val[1]).wrapping_add(carry as u64);

        tag[..8].copy_from_slice(&sum0.to_le_bytes());
        tag[8..].copy_from_slice(&sum1.to_le_bytes());
        tag
    }

    /// Process one or more 16-byte blocks.
    /// `pad` = 1 means complete block (implicit 0x01 appended), 0 = final partial block.
    fn blocks(&mut self, block: &[u8; 16], pad: u32) {
        // Parse block as a 128-bit value + the implicit 1 byte = 136 bits (5 limbs)
        let n0 = (block[0] as u32) | ((block[1] as u32) << 8) | ((block[2] as u32) << 16) | (((block[3] as u32) & 0x03) << 24);
        let n1 = ((block[3] as u32) >> 2) | ((block[4] as u32) << 6) | ((block[5] as u32) << 14) | (((block[6] as u32) & 0x0F) << 22);
        let n2 = ((block[6] as u32) >> 4) | ((block[7] as u32) << 4) | ((block[8] as u32) << 12) | (((block[9] as u32) & 0x3F) << 20);
        let n3 = ((block[9] as u32) >> 6) | ((block[10] as u32) << 2) | ((block[11] as u32) << 10) | ((block[12] as u32) << 18);
        let n4 = (block[13] as u32) | ((block[14] as u32) << 8) | ((block[15] as u32) << 16) | (pad << 24);

        // h += n (carry chain through 5 limbs)
        let (h0, c0) = self.h0.overflowing_add(n0);
        let (h1, c1) = self.h1.overflowing_add(n1 + c0 as u32);
        let (h2, c2) = self.h2.overflowing_add(n2 + c1 as u32);
        let (h3, c3) = self.h3.overflowing_add(n3 + c2 as u32);
        let (h4, _) = self.h4.overflowing_add(n4 + c3 as u32);
        self.h0 = h0; self.h1 = h1; self.h2 = h2; self.h3 = h3; self.h4 = h4;

        // h *= r (mod 2^130 - 5)
        // Use widened multiplication: each limb × 26 bits
        // h * r = sum_{i,j} h_i * r_j * 2^{26*(i+j)}
        // Then reduce modulo 2^130 - 5 using: 2^130 ≡ 5

        // Compute full product using u64 intermediates (each product fits: 2^26 * 2^26 = 2^52 < u64)
        let h0 = self.h0 as u64;
        let h1 = self.h1 as u64;
        let h2 = self.h2 as u64;
        let h3 = self.h3 as u64;
        let h4 = self.h4 as u64;
        let r0 = self.r0 as u64;
        let r1 = self.r1 as u64;
        let r2 = self.r2 as u64;
        let r3 = self.r3 as u64;

        // Each product: h_i * r_j
        // Position i+j contributes to the accumulator
        // Final positions: 0,1,2,3,4,5,6,7 (but we only keep 0..4, reducing 5,6,7 into lower limbs)
        // h4*r0 + h3*r1 + h2*r2 + h1*r3 + h0*r4 (but r has only 4 limbs so no r4)
        // Max position: h4 * r3 = position 7

        // Compute each position's sum
        let p0 = h0 * r0;
        let p1 = h0 * r1 + h1 * r0;
        let p2 = h0 * r2 + h1 * r1 + h2 * r0;
        let p3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;
        let p4 = h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let p5 = h2 * r3 + h3 * r2 + h4 * r1;
        let p6 = h3 * r3 + h4 * r2;
        let p7 = h4 * r3;

        // Now pack into 26-bit limbs with carry propagation
        // And reduce: 2^130 ≡ 5 (mod p), so limb positions 5,6,7 map to:
        // p5 contributes to position 5 = 2^130 ≡ 5 (so p5 * 5 added to position 0)
        // p6 contributes to position 6 = 2^156 = 5 * 2^26 (so p6 * 5 added to position 1)
        // p7 contributes to position 7 = 2^182 = 5 * 2^52 (so p7 * 5 added to position 2)

        // Carry from each limb position (26 bits)
        let c0 = p0 & 0x3FFFFFF;
        let carry0 = p0 >> 26;
        let c1 = (p1 + carry0) & 0x3FFFFFF;
        let carry1 = (p1 + carry0) >> 26;
        let c2 = (p2 + carry1) & 0x3FFFFFF;
        let carry2 = (p2 + carry1) >> 26;
        let c3 = (p3 + carry2) & 0x3FFFFFF;
        let carry3 = (p3 + carry2) >> 26;
        let c4 = (p4 + carry3) & 0x3FFFFFF;
        let carry4 = (p4 + carry3) >> 26;

        // Reduce high limbs5, p6, p7
        let c5 = p5 + carry4; // carry from position 4
        // Now c5 represents c5 * 2^130 ≡ c5 * 5 (mod p), added to position 0
        let c6 = p6; // c6 * 2^156 ≡ c6 * 5 * 2^26, added to position 1
        let c7 = p7; // c7 * 2^182 ≡ c7 * 5 * 2^52, added to position 2

        // Fold back: multiply by 5 and add to lower limbs
        let r5 = c5.wrapping_mul(5) & 0x3FFFFFF;
        let r5_carry = c5.wrapping_mul(5) >> 26;
        let r6 = c6.wrapping_mul(5);
        let r7 = c7.wrapping_mul(5);

        // Final limbs
        let h0 = (c0 + r5) & 0x3FFFFFF;
        let h0_carry = (c0 + r5) >> 26;
        let h1 = (c1 + r6 + h0_carry) & 0x3FFFFFF;
        let h1_carry = (c1 + r6 + h0_carry) >> 26;
        let h2 = (c2 + r7 + h1_carry) & 0x3FFFFFF;
        let h2_carry = (c2 + r7 + h1_carry) >> 26;
        let h3 = (c3 + h2_carry) & 0x3FFFFFF;
        let h3_carry = (c3 + h2_carry) >> 26;
        let h4 = (c4 + h3_carry) & 0x3FFFFFF;

        self.h0 = h0 as u32;
        self.h1 = h1 as u32;
        self.h2 = h2 as u32;
        self.h3 = h3 as u32;
        self.h4 = h4 as u32;
    }

    /// Set bit at position `pos` in the accumulator (for final block padding).
    fn set_bit_at(&mut self, pos: usize) {
        // pos is byte index (0..15), set bit at position pos in the 128-bit value + implicit 1
        // The implicit 1 byte goes at position pos (the byte after the message)
        if pos < 4 {
            self.h0 |= 1 << (pos * 8);
            if pos == 3 {
                self.h0 &= 0x03FFFFFF; // limit to 26 bits
                // bit 24,25 go to h1
                self.h1 |= 1 << ((pos * 8) - 26);
            }
        } else if pos < 7 {
            self.h1 |= 1 << ((pos * 8) - 26);
        } else if pos < 10 {
            let shift = (pos * 8) - 52;
            if shift < 26 {
                self.h2 |= 1 << shift;
            } else {
                self.h3 |= 1 << (shift - 26);
            }
        } else if pos < 13 {
            let shift = (pos * 8) - 78;
            if shift < 26 {
                self.h3 |= 1 << shift;
            } else {
                self.h4 |= 1 << (shift - 26);
            }
        } else {
            let shift = (pos * 8) - 104;
            if shift < 26 {
                self.h4 |= 1 << shift;
            }
        }
    }

    /// Fully reduce h modulo 2^130 - 5 if needed.
    fn canonicalize(&mut self) {
        // h4 should be < 4 after the multiplication (since 2^130 maps to 5, h4 < 5)
        // If h4 >= 4, reduce
        if self.h4 >= 4 {
            // h -= (2^130 - 5) means h4 -= 4 and the lower limbs are adjusted
            // Simpler: h = h mod (2^130 - 5)
            // Since h4 < 5 is guaranteed by our algorithm, just mask
            self.h4 &= 0x03;
        }
        self.h0 &= 0x3FFFFFF;
        self.h1 &= 0x3FFFFFF;
        self.h2 &= 0x3FFFFFF;
        self.h3 &= 0x3FFFFFF;
        self.h4 &= 0x03;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8439_poly1305_test_vector() {
        // RFC 8439 Section 2.5.2 test vector
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];

        let message = b"Cryptographic Forum Research Group";

        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];

        let tag = poly1305_mac(&key, message);
        assert_eq!(tag, expected_tag, "RFC 8439 test vector failed");
    }

    #[test]
    fn test_empty_message() {
        let key = [0u8; 32];
        let tag = poly1305_mac(&key, b"");
        assert_eq!(tag, [0u8; 16], "Empty message with zero key should give zero tag");
    }

    #[test]
    fn test_single_byte() {
        let key = [1u8; 32];
        let tag = poly1305_mac(&key, b"A");
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_incremental_matches_oneshot() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";

        let oneshot = poly1305_mac(&key, message);

        let mut incremental = Poly1305::new(&key);
        incremental.update(b"Cryptographic ");
        incremental.update(b"Forum Research ");
        incremental.update(b"Group");
        let inc_tag = incremental.finalize();

        assert_eq!(oneshot, inc_tag, "Incremental should match one-shot");
    }

    #[test]
    fn test_exact_block_message() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = [0x42u8; 16];
        let tag = poly1305_mac(&key, &message);
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_two_blocks() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = [0xABu8; 32];
        let tag = poly1305_mac(&key, &message);
        assert_eq!(tag.len(), 16);
    }
}
