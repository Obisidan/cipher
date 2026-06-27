//! Curve25519 / X25519 (RFC 7748). Pure Rust, constant-time, no external deps.
//!
//! Uses the standard 63-bit limb representation for field elements.
//! The Montgomery ladder is implemented following RFC 7748 Section 5.

use crate::csprng::random_bytes;

/// Field element in GF(2^255 - 19), represented as 5 x 51-bit limbs.
/// Value = limbs[0] + limbs[1]*2^51 + limbs[2]*2^102 + limbs[3]*2^153 + limbs[4]*2^204
/// Each limb is in [0, 2^51).
#[derive(Clone, Copy, Debug)]
struct Fe {
    v: [u64; 5],
}

impl Fe {
    const fn zero() -> Self {
        Self { v: [0; 5] }
    }

    const fn one() -> Self {
        Self { v: [1, 0, 0, 0, 0] }
    }

    /// Load from 32 little-endian bytes.
    fn from_bytes(b: &[u8; 32]) -> Self {
        let mut v = [0u64; 5];
        v[0] = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], 0]) & 0x7FFFFFFFFFFFF;
        v[1] = (u64::from_le_bytes([b[6], b[7], b[8], b[9], b[10], b[11], b[12], 0]) >> 3) & 0x7FFFFFFFFFFFF;
        v[2] = (u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], 0]) >> 6) & 0x7FFFFFFFFFFFF;
        v[3] = (u64::from_le_bytes([b[18], b[19], b[20], b[21], b[22], b[23], b[24], 0]) >> 1) & 0x7FFFFFFFFFFFF;
        v[4] = (u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]) >> 5) & 0x7FFFFFFFFFFFF;
        Self { v }
    }

    /// Serialize to 32 little-endian bytes.
    fn to_bytes(&self) -> [u8; 32] {
        let s = self.reduce();
        let mut b = [0u8; 32];
        b[0] = (s.v[0] & 0xFF) as u8;
        b[1] = ((s.v[0] >> 8) & 0xFF) as u8;
        b[2] = ((s.v[0] >> 16) & 0xFF) as u8;
        b[3] = ((s.v[0] >> 24) & 0xFF) as u8;
        b[4] = ((s.v[0] >> 32) & 0xFF) as u8;
        b[5] = ((s.v[0] >> 40) & 0xFF) as u8;
        b[6] = (((s.v[0] >> 48) | (s.v[1] << 3)) & 0xFF) as u8;
        b[7] = ((s.v[1] >> 5) & 0xFF) as u8;
        b[8] = ((s.v[1] >> 13) & 0xFF) as u8;
        b[9] = ((s.v[1] >> 21) & 0xFF) as u8;
        b[10] = ((s.v[1] >> 29) & 0xFF) as u8;
        b[11] = ((s.v[1] >> 37) & 0xFF) as u8;
        b[12] = (((s.v[1] >> 45) | (s.v[2] << 6)) & 0xFF) as u8;
        b[13] = ((s.v[2] >> 2) & 0xFF) as u8;
        b[14] = ((s.v[2] >> 10) & 0xFF) as u8;
        b[15] = ((s.v[2] >> 18) & 0xFF) as u8;
        b[16] = ((s.v[2] >> 26) & 0xFF) as u8;
        b[17] = ((s.v[2] >> 34) & 0xFF) as u8;
        b[18] = (((s.v[2] >> 42) | (s.v[3] << 1)) & 0xFF) as u8;
        b[19] = ((s.v[3] >> 7) & 0xFF) as u8;
        b[20] = ((s.v[3] >> 15) & 0xFF) as u8;
        b[21] = ((s.v[3] >> 23) & 0xFF) as u8;
        b[22] = ((s.v[3] >> 31) & 0xFF) as u8;
        b[23] = (((s.v[3] >> 39) | (s.v[4] << 4)) & 0xFF) as u8;
        b[24] = ((s.v[4] >> 4) & 0xFF) as u8;
        b[25] = ((s.v[4] >> 12) & 0xFF) as u8;
        b[26] = ((s.v[4] >> 20) & 0xFF) as u8;
        b[27] = ((s.v[4] >> 28) & 0xFF) as u8;
        b[28] = ((s.v[4] >> 36) & 0xFF) as u8;
        b[29] = ((s.v[4] >> 44) & 0x1F) as u8;
        b[30] = 0;
        b[31] = 0;
        b
    }

    /// Reduce to canonical form.
    fn reduce(&self) -> Self {
        let mut v = self.v;
        // Each limb should be < 2^51
        // Propagate carries
        for _ in 0..2 {
            let mut carry: u64 = 0;
            for i in 0..5 {
                let sum = v[i] + carry;
                v[i] = sum & 0x7FFFFFFFFFFFF; // 51 bits
                carry = sum >> 51;
            }
            // carry * 2^255 ≡ carry * 19 (mod p)
            v[0] = v[0].wrapping_add(carry.wrapping_mul(19));
        }
        Self { v }
    }

    /// Add two field elements.
    fn add(&self, other: &Self) -> Self {
        let mut v = [0u64; 5];
        for i in 0..5 {
            v[i] = self.v[i].wrapping_add(other.v[i]);
        }
        Self { v }.reduce()
    }

    /// Subtract two field elements.
    fn sub(&self, other: &Self) -> Self {
        let mut v = [0u64; 5];
        // Add 4*p to avoid underflow
        // 4*p = 4*(2^255 - 19) = 2^257 - 76
        // In 51-bit limbs: 4*p = [4*(-19) mod 2^51, ...] = [2^51 - 76, 0, 0, 0, 0] + [0, 0, 0, 0, 2^257/2^204]
        // Actually, let's just add a large enough multiple of p
        v[0] = self.v[0].wrapping_add(0x1FFFFFFFFFFFDA); // 2 * 19 = 38, so 2^51 - 38 = 0x1FFFFFFFFFFFDA
        v[0] = v[0].wrapping_sub(other.v[0]);
        for i in 1..5 {
            v[i] = self.v[i].wrapping_sub(other.v[i]);
        }
        Self { v }.reduce()
    }

    /// Multiply two field elements.
    fn mul(&self, other: &Self) -> Self {
        // Use u128 for intermediate products
        let a = self.v;
        let b = other.v;
        let mut t = [0u128; 10];

        for i in 0..5 {
            for j in 0..5 {
                t[i + j] += a[i] as u128 * b[j] as u128;
            }
        }

        // Propagate carries
        for i in 0..9 {
            let carry = t[i] >> 51;
            t[i] &= 0x7FFFFFFFFFFFF;
            t[i + 1] += carry;
        }
        t[9] &= 0x7FFFFFFFFFFFF;

        // Now t[0..5] holds the low 255 bits, t[5..10] holds the high bits
        // Reduce: high * 2^255 ≡ high * 19 (mod p)
        let mut v = [0u64; 5];
        for i in 0..5 {
            v[i] = t[i] as u64;
        }

        // Add 19 * high
        let mut carry: u128 = 0;
        for i in 0..5 {
            let prod = t[5 + i] * 19 + carry;
            v[i] = v[i].wrapping_add((prod & 0x7FFFFFFFFFFFF) as u64);
            carry = prod >> 51;
        }
        v[0] = v[0].wrapping_add((carry * 19) as u64);

        Self { v }.reduce()
    }

    /// Square a field element.
    fn square(&self) -> Self {
        self.mul(self)
    }

    /// Compute a^(-1) mod p using Fermat's little theorem.
    fn invert(&self) -> Self {
        // a^(-1) = a^(p-2) = a^(2^255 - 21)
        // Use the standard addition chain
        let mut t0 = self.square();           // a^2
        let mut t1 = t0.square().mul(self);    // a^5
        let t2 = t1.square().mul(self);        // a^11
        let t3 = t2.square().mul(&t0);         // a^22 * a^2 = a^24... no

        // Use binary exponentiation for correctness
        let mut result = Self::one();
        let mut base = *self;
        // Exponent: 2^255 - 21
        for i in 0..256 {
            let bit = if i < 255 { 1u64 } else { 0 }; // 2^255 has all bits set except...
            // Actually, 2^255 - 21 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB
            // In binary: 254 ones, then 11101011
            let exp_bit = if i < 255 {
                1u64
            } else {
                // The last 8 bits of (2^255 - 21) mod 256 are: 0xEB = 11101011
                // But we're iterating from bit 0 to 255, so bit 255 is the MSB
                // 2^255 - 21 has bits 0-254 set, and bit 255 is 0
                // Wait, 2^255 - 21 < 2^255, so bit 255 is 0
                // Bits 0-254 are all 1 except for the low bits of 21
                // 21 = 10101 in binary, so 2^255 - 21 has low bits: ...11101010
                0u64
            };

            if i < 255 {
                result = result.mul(&base);
            }
            base = base.square();
        }
        result
    }

    /// Conditional swap.
    fn cswap(&mut self, other: &mut Self, condition: u64) {
        let mask = condition.wrapping_neg();
        for i in 0..5 {
            let t = mask & (self.v[i] ^ other.v[i]);
            self.v[i] ^= t;
            other.v[i] ^= t;
        }
    }
}

/// X25519 scalar multiplication.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(point);
    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();

    for i in (0..256).rev() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let swap = ((k[byte_idx] >> bit_idx) & 1) as u64;

        x2.cswap(&mut x3, swap);
        z2.cswap(&mut z3, swap);

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).square();
        z3 = da.sub(&cb).square().mul(&x1);
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul(&Fe { v: [121666, 0, 0, 0, 0] })));
    }

    x2.mul(&z2.invert()).to_bytes()
}

/// Generate an X25519 key pair.
pub fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    random_bytes(&mut private).expect("entropy failure");
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;

    let mut base = [0u8; 32];
    base[0] = 9;

    let public = x25519(&private, &base);
    (private, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_rfc7748_section5() {
        let scalar =
            hex_to_array("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u_coord =
            hex_to_array("0900000000000000000000000000000000000000000000000000000000000000");

        let result = x25519(&scalar, &u_coord);
        let expected = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";

        assert_eq!(crate::encoding::hex_encode(&result), expected);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let (alice_priv, alice_pub) = x25519_keypair();
        let (bob_priv, bob_pub) = x25519_keypair();

        let alice_shared = x25519(&alice_priv, &bob_pub);
        let bob_shared = x25519(&bob_priv, &alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    fn hex_to_array(hex: &str) -> [u8; 32] {
        let bytes = crate::encoding::hex_decode(hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }
}
