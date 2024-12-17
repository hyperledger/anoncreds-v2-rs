use super::{MessageGenerators, SecretKey};
use crate::{
    error::Error, knox::short_group_sig_core::short_group_traits::PublicKey as PublicKeyTrait,
};
use blsful::inner_types::*;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use subtle::Choice;

/// BBS compressed public key
///
/// See <https://eprint.iacr.org/2023/275.pdf>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct CompressedPublicKey {
    pub(crate) x: G2Projective,
    pub(crate) max_messages: usize,
}

impl From<&SecretKey> for CompressedPublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self {
            x: G2Projective::GENERATOR * sk.x,
            max_messages: sk.max_messages,
        }
    }
}

impl PublicKeyTrait for CompressedPublicKey {
    type MessageGenerator = G1Projective;
    type BlindMessageGenerator = G1Projective;
}

impl From<CompressedPublicKey> for Vec<u8> {
    fn from(pk: CompressedPublicKey) -> Self {
        pk.to_bytes()
    }
}

impl TryFrom<Vec<u8>> for CompressedPublicKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&Vec<u8>> for CompressedPublicKey {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for CompressedPublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes).ok_or(Error::General("Invalid public key"))
    }
}

impl TryFrom<Box<[u8]>> for CompressedPublicKey {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl CompressedPublicKey {
    /// Check if this public key is valid
    pub fn is_valid(&self) -> Choice {
        !self.x.is_identity()
    }

    /// Check if this public key is invalid
    pub fn is_invalid(&self) -> Choice {
        self.x.is_identity()
    }

    /// Convert a byte sequence into the public key
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let bytes = bytes.as_ref();
        serde_bare::from_slice(bytes).ok()
    }

    /// Decompress into the public key
    pub fn decompress(&self) -> PublicKey {
        PublicKey::new(*self)
    }
}

/// Public key which includes the generators for each message
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKey {
    pub(crate) y: Vec<G1Projective>,
    pub(crate) w: G2Projective,
}

impl PublicKeyTrait for PublicKey {
    type MessageGenerator = G1Projective;
    type BlindMessageGenerator = G1Projective;
}

impl From<&PublicKey> for CompressedPublicKey {
    fn from(pk: &PublicKey) -> Self {
        pk.compress()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self::with_secret_key(sk)
    }
}

impl PublicKey {
    /// Create a new public key
    pub fn new(public_key: CompressedPublicKey) -> Self {
        let count = NonZeroUsize::new(public_key.max_messages).expect("non-zero");
        let y = MessageGenerators::with_api_id(count, Some(&public_key.x.to_compressed())).0;
        Self { y, w: public_key.x }
    }

    /// Create a new public key from a secret key
    pub fn with_secret_key(secret_key: &SecretKey) -> Self {
        let public_key = CompressedPublicKey::from(secret_key);
        Self::new(public_key)
    }

    /// Compress this public key
    pub fn compress(&self) -> CompressedPublicKey {
        CompressedPublicKey {
            x: self.w,
            max_messages: self.y.len(),
        }
    }

    /// Check if this public key is invalid
    pub fn is_invalid(&self) -> Choice {
        self.w.is_identity()
            | self
                .y
                .iter()
                .map(|y| y.is_identity())
                .fold(Choice::from(0u8), |acc, x| acc | x)
    }

    /// The raw bytes of this public key
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_bare::to_vec(&self).expect("to serialize public key")
    }

    /// Convert a byte sequence into the public key
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_bare::from_slice(bytes).ok()
    }
}
