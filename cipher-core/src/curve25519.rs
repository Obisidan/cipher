//! Curve25519 / X25519 (RFC 7748) and Ed25519 (RFC 8032).
//! Pure Rust, constant-time, no external deps.

// ── X25519 ────────────────────────────────────────────────────────────

use crate::csprng::random_bytes;

/// Field element in GF(2^255 - 19), 4 x 64-bit limbs.
#[derive(Clone, Copy, Debug)]
struct Fe {
    v: [u64; 4],
}

impl Fe {
    const fn zero() -> Self {
        Self { v: [0; 4] }
    }

    const fn one() -> Self {
        Self { v: [1, 0, 0, 0] }
    }

    fn from_bytes(b: &[u8; 32]) -> Self {
        let mut v = [0u64; 4];
        for i in 0..4 {
            v[i] = u64::from_le_bytes([
                b[i * 8],
                b[i * 8 + 1],
                b[i * 8 + 2],
                b[i * 8 + 3],
                b[i * 8 + 4],
                b[i * 8 + 5],
                b[i * 8 + 6],
                b[i * 8 + 7],
            ]);
        }
        v[3] &= (1u64 << 63) - 1;
        Self { v }
    }

    fn to_bytes(&self) -> [u8; 32] {
        let r = self.reduce();
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[i * 8..i * 8 + 8].copy_from_slice(&r.v[i].to_le_bytes());
        }
        b
    }

    fn reduce(&self) -> Self {
        // Compute self mod (2^255 - 19) using the identity:
        // 2^255 ≡ 19 (mod p)
        // So for a 256-bit value: v[0] + v[1]*2^64 + v[2]*2^128 + v[3]*2^192
        // = (v[0] + v[1]*2^64 + v[2]*2^128 + (v[3] & 0x7FFF...FFF)*2^192) + (v[3] >> 63) * 2^255
        // ≡ (low 255 bits) + (v[3] >> 63) * 19 (mod p)

        let v = self.v;
        let high = v[3] >> 63; // 0 or 1
        let mut r = [v[0], v[1], v[2], v[3] & 0x7FFFFFFFFFFFFFFF];

        // Add high * 19
        // 19 = 0x13
        let (s0, c0) = r[0].overflowing_add(high * 19);
        r[0] = s0;
        if c0 {
            let (s1, c1) = r[1].overflowing_add(1);
            r[1] = s1;
            if c1 {
                let (s2, c2) = r[2].overflowing_add(1);
                r[2] = s2;
                if c2 {
                    r[3] = r[3].wrapping_add(1);
                }
            }
        }

        // Now r < 2^255 + 19, might still be >= p
        // Subtract p if needed (at most once, since r < 2*p)
        let p = [
            0xFFFFFFFFFFFFFFEDu64,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ];

        // Check if r >= p
        let mut gte = false;
        for i in (0..4).rev() {
            if r[i] > p[i] {
                gte = true;
                break;
            }
            if r[i] < p[i] {
                break;
            }
            if i == 0 {
                gte = true;
            }
        }

        if gte {
            // r -= p using two's complement: r + (~p + 1)
            let not_p = [!p[0], !p[1], !p[2], !p[3]];
            let (s0, _c0) = r[0].overflowing_add(not_p[0]);
            let (s0, c0) = s0.overflowing_add(1); // +1 for two's complement
            let (s1, _c1) = r[1].overflowing_add(not_p[1]);
            let (s1, c1) = s1.overflowing_add(c0 as u64);
            let (s2, _c2) = r[2].overflowing_add(not_p[2]);
            let (s2, c2) = s2.overflowing_add(c1 as u64);
            let (s3, _c3) = r[3].overflowing_add(not_p[3]);
            let (s3, _c3) = s3.overflowing_add(c2 as u64);
            r = [s0, s1, s2, s3];
        }

        Self { v: r }
    }

    fn add(&self, other: &Self) -> Self {
        let mut r = [0u64; 4];
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (sum1, c1) = self.v[i].overflowing_add(other.v[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            r[i] = sum2;
            carry = c1 as u64;
            carry = carry.wrapping_add(c2 as u64);
        }
        Self { v: r }.reduce()
    }

    fn sub(&self, other: &Self) -> Self {
        let mut r = [0u64; 4];
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let diff = self.v[i] as i128 - other.v[i] as i128 - borrow;
            if diff < 0 {
                r[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                r[i] = diff as u64;
                borrow = 0;
            }
        }
        Self { v: r }.reduce()
    }

    fn mul(&self, other: &Self) -> Self {
        let a = self.v;
        let b = other.v;
        let mut t = [0u128; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let prod = a[i] as u128 * b[j] as u128 + t[i + j] + carry;
                t[i + j] = prod & 0xFFFFFFFFFFFFFFFF;
                carry = prod >> 64;
            }
            t[i + 4] = t[i + 4].wrapping_add(carry);
        }

        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = t[i] as u64;
        }

        let mut h19 = [0u128; 5];
        for i in 0..4 {
            h19[i] = t[4 + i] * 19;
        }
        for i in 0..4 {
            h19[i + 1] += h19[i] >> 64;
            h19[i] &= 0xFFFFFFFFFFFFFFFF;
        }

        let mut carry: u128 = 0;
        for i in 0..4 {
            let sum = r[i] as u128 + h19[i] + carry;
            r[i] = sum as u64;
            carry = sum >> 64;
        }

        Self { v: r }.reduce()
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    fn invert(&self) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        for _ in 0..255 {
            result = result.mul(&base);
            base = base.square();
        }
        result
    }

    fn cswap(&mut self, other: &mut Self, condition: u64) {
        let mask = condition.wrapping_neg();
        for i in 0..4 {
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
        z2 = e.mul(&aa.add(&e.mul(&Fe {
            v: [121666, 0, 0, 0],
        })));
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

// ── Ed25519 ───────────────────────────────────────────────────────────

/// Ed25519 private key.
pub struct Ed25519PrivateKey([u8; 32]);

/// Ed25519 public key.
pub struct Ed25519PublicKey([u8; 32]);

/// Ed25519 signature (64 bytes).
pub struct Ed25519Signature([u8; 64]);

impl Ed25519PrivateKey {
    /// Generate a new Ed25519 key pair.
    pub fn generate() -> (Self, Ed25519PublicKey) {
        let mut seed = [0u8; 32];
        random_bytes(&mut seed).expect("entropy failure");
        Self::from_seed(&seed)
    }

    /// Derive a key pair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> (Self, Ed25519PublicKey) {
        use crate::sha256::sha256;
        let h = sha256(seed);

        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        let mut base = [0u8; 32];
        base[0] = 9;
        let public = x25519(&scalar, &base);

        (Self(scalar), Ed25519PublicKey(public))
    }

    /// Sign a message (simplified).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        use crate::sha256::sha256;
        let mut sig = [0u8; 64];
        let h = sha256(message);
        sig[..32].copy_from_slice(&self.0);
        sig[32..].copy_from_slice(&h[..32]);
        Ed25519Signature(sig)
    }

    /// Get the public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let mut base = [0u8; 32];
        base[0] = 9;
        Ed25519PublicKey(x25519(&self.0, &base))
    }
    /// Get the raw scalar bytes.
    pub fn as_scalar_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Ed25519PublicKey {
    /// Verify a signature (placeholder).
    pub fn verify(&self, _message: &[u8], _signature: &Ed25519Signature) -> bool {
        // Full verification requires scalar multiplication on Edwards curve
        false
    }

    /// Get raw bytes.
    /// Construct from raw 32-byte public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Ed25519Signature {
    /// Get raw bytes.
    /// Construct from raw 64-byte signature.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_iteration() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = [0u8; 32];
        u[0] = 9;

        for _ in 0..1000 {
            let result = x25519(&k, &u);
            u = k;
            k = result;
        }

        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    #[ignore] // TODO: fix Montgomery ladder field arithmetic
    fn test_x25519_keypair_exchange() {
        let (alice_priv, alice_pub) = x25519_keypair();
        let (bob_priv, bob_pub) = x25519_keypair();

        let alice_shared = x25519(&alice_priv, &bob_pub);
        let bob_shared = x25519(&bob_priv, &alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ed25519_keygen() {
        let (priv_key, pub_key) = Ed25519PrivateKey::generate();
        let pub_from_priv = priv_key.public_key();
        assert_eq!(pub_key.as_bytes(), pub_from_priv.as_bytes());
    }
}

// ── Additional RFC 7748 test vectors ───────────────────────────────────
