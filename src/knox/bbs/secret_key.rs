use super::PublicKey;
use crate::knox::short_group_sig_core::short_group_traits::SecretKey as SecretKeyTrait;

use blsful::inner_types::{Field, G2Projective, PrimeField, Scalar};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake128,
};
use zeroize::Zeroize;

/// The secret key for BBS signatures
///
/// See <https://eprint.iacr.org/2023/275.pdf>
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct SecretKey(pub(crate) Scalar);

impl SecretKeyTrait for SecretKey {
    type PublicKey = PublicKey;

    fn public_key(&self) -> PublicKey {
        PublicKey(G2Projective::GENERATOR * self.0)
    }
}

impl SecretKey {
    /// Compute a secret key from a hash
    pub fn hash<B: AsRef<[u8]>>(data: B) -> Self {
        const SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
        let mut okm = [0u8; 32];
        Shake128::default()
            .chain(SALT)
            .chain(data.as_ref())
            .finalize_xof_into(&mut okm);
        let rng = ChaChaRng::from_seed(okm);
        Self(Scalar::random(rng))
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Convert the secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    /// Convert a byte sequence into the secret key
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Option::from(Scalar::from_repr(arr).map(Self))
    }

    /// Check if the secret key is valid
    pub fn is_valid(&self) -> bool {
        self.0.is_zero().unwrap_u8() == 0
    }

    /// Check if the secret key is invalid
    pub fn is_invalid(&self) -> bool {
        self.0.is_zero().unwrap_u8() == 1
    }
}
