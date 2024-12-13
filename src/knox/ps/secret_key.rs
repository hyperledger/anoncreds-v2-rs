use crate::knox::{
    ps::PublicKey, short_group_sig_core::short_group_traits::SecretKey as SecretKeyTrait,
};
use blsful::inner_types::{G1Projective, G2Projective, Scalar};
use elliptic_curve::{Field, PrimeField};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroize;

/// The secret key contains a field element for each
/// message that is signed and two extra.
/// See section 4.2 in
/// <https://eprint.iacr.org/2015/525.pdf> and
/// <https://eprint.iacr.org/2017/1197.pdf>
///
/// `w` corresponds to m' in the paper to achieve
/// EUF-CMA security level.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    pub(crate) w: Scalar,
    pub(crate) x: Scalar,
    pub(crate) y: Vec<Scalar>,
}

impl Default for SecretKey {
    fn default() -> Self {
        Self {
            w: Scalar::ZERO,
            x: Scalar::ZERO,
            y: Vec::new(),
        }
    }
}

impl SecretKeyTrait for SecretKey {
    type PublicKey = PublicKey;

    fn public_key(&self) -> PublicKey {
        let w = G2Projective::GENERATOR * self.w;
        let x = G2Projective::GENERATOR * self.x;
        let mut y = Vec::with_capacity(self.y.len());
        let mut y_blinds = Vec::with_capacity(self.y.len());
        for s_y in &self.y {
            y.push(G2Projective::GENERATOR * s_y);
            y_blinds.push(G1Projective::GENERATOR * s_y);
        }
        PublicKey { w, x, y, y_blinds }
    }
}

impl SecretKey {
    const SCALAR_SIZE: usize = 32;

    /// Compute a secret key from a hash
    pub fn hash<B: AsRef<[u8]>>(count: usize, data: B) -> Option<Self> {
        const SALT: &[u8] = b"PS-SIG-KEYGEN-SALT-";
        let mut reader = sha3::Shake256::default()
            .chain(SALT)
            .chain(data.as_ref())
            .finalize_xof();
        let mut okm = [0u8; Self::SCALAR_SIZE];
        reader.read(&mut okm);
        let rng = ChaChaRng::from_seed(okm);

        generate_secret_key(count, rng)
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random(count: usize, rng: impl RngCore + CryptoRng) -> Option<Self> {
        generate_secret_key(count, rng)
    }

    /// Store the secret key as a sequence of bytes
    /// Each scalar is compressed to big-endian format
    /// Needs (N + 2) * 32 space otherwise it will panic
    /// where N is the number of messages that can be signed
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(self.w.to_repr().as_ref());
        buffer.extend_from_slice(self.x.to_repr().as_ref());

        for y in &self.y {
            buffer.extend_from_slice(y.to_repr().as_ref());
        }
        buffer
    }

    /// Convert a byte sequence into the secret key
    /// Expected size is (N + 2) * 32 bytes
    /// where N is the number of messages that can be signed
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        // Length for w, x, and 1 y
        const MIN_SIZE: usize = SecretKey::SCALAR_SIZE * 3;

        let buffer = bytes.as_ref();
        if buffer.len() % Self::SCALAR_SIZE != 0 {
            return None;
        }
        if buffer.len() < MIN_SIZE {
            return None;
        }

        fn from_le_bytes(d: &[u8]) -> Option<Scalar> {
            let mut s = <Scalar as PrimeField>::Repr::default();
            s.as_mut().copy_from_slice(d);
            let res = Scalar::from_repr(s);
            if res.is_some().unwrap_u8() == 1 {
                Some(res.unwrap())
            } else {
                None
            }
        }

        let y_cnt = (buffer.len() / Self::SCALAR_SIZE) - 2;
        let mut offset = 0;
        let mut end = Self::SCALAR_SIZE;
        let w = from_le_bytes(&buffer[offset..end])?;
        offset = end;
        end += Self::SCALAR_SIZE;

        let x = from_le_bytes(&buffer[offset..end])?;
        offset = end;
        end += Self::SCALAR_SIZE;

        let mut y = Vec::new();

        for _ in 0..y_cnt {
            let s = from_le_bytes(&buffer[offset..end])?;
            y.push(s);
            offset = end;
            end += Self::SCALAR_SIZE;
        }
        Some(Self { w, x, y })
    }

    /// Check if this secret key is valid
    pub fn is_valid(&self) -> bool {
        let mut res = !self.w.is_zero();
        res &= !self.x.is_zero();
        for y in &self.y {
            res &= !y.is_zero();
        }
        res.unwrap_u8() == 1u8
    }

    /// Check if this public key is invalid
    pub fn is_invalid(&self) -> bool {
        let mut res = self.w.is_zero();
        res |= self.x.is_zero();
        for y in &self.y {
            res |= y.is_zero();
        }
        res.unwrap_u8() == 1u8
    }
}

fn generate_secret_key(count: usize, mut rng: impl RngCore + CryptoRng) -> Option<SecretKey> {
    if count == 0 || count > 128 {
        return None;
    }
    let w = Scalar::random(&mut rng);
    let x = Scalar::random(&mut rng);
    let mut y = Vec::new();
    for _ in 0..count {
        y.push(Scalar::random(&mut rng));
    }

    Some(SecretKey { w, x, y })
}
