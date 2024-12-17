use super::PublicKey;
use crate::knox::short_group_sig_core::short_group_traits::SecretKey as SecretKeyTrait;
use std::num::NonZeroUsize;

use blsful::inner_types::{Field, Scalar};
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
pub struct SecretKey {
    pub(crate) x: Scalar,
    pub(crate) max_messages: usize,
}

impl SecretKeyTrait for SecretKey {
    type PublicKey = PublicKey;

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self)
    }
}

impl SecretKey {
    /// Compute a secret key from a hash
    pub fn hash<B: AsRef<[u8]>>(data: B, max_messages: NonZeroUsize) -> Self {
        const SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
        let mut okm = [0u8; 32];
        Shake128::default()
            .chain(SALT)
            .chain(data.as_ref())
            .finalize_xof_into(&mut okm);
        let rng = ChaChaRng::from_seed(okm);
        Self {
            x: Scalar::random(rng),
            max_messages: max_messages.get(),
        }
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random(max_messages: NonZeroUsize, rng: impl RngCore + CryptoRng) -> Self {
        Self {
            x: Scalar::random(rng),
            max_messages: max_messages.get(),
        }
    }

    /// Convert the secret key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_bare::to_vec(self).expect("to serialize SecretKey")
    }

    /// Convert a byte sequence into the secret key
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        serde_bare::from_slice(bytes.as_ref()).ok()
    }

    /// Check if the secret key is valid
    pub fn is_valid(&self) -> bool {
        self.x.is_zero().unwrap_u8() == 0
    }

    /// Check if the secret key is invalid
    pub fn is_invalid(&self) -> bool {
        self.x.is_zero().unwrap_u8() == 1
    }
}
