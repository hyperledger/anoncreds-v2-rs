use super::SecretKey;
use crate::{
    error::Error, knox::short_group_sig_core::short_group_traits::PublicKey as PublicKeyTrait,
};
use blsful::inner_types::*;
use serde::{Deserialize, Serialize};
use subtle::Choice;

/// BBS public key
///
/// See <https://eprint.iacr.org/2023/275.pdf>
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKey(pub(crate) G2Projective);

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self(G2Projective::GENERATOR * sk.0)
    }
}

impl PublicKeyTrait for PublicKey {
    type MessageGenerator = G2Projective;
    type BlindMessageGenerator = G1Projective;
}

impl From<PublicKey> for Vec<u8> {
    fn from(pk: PublicKey) -> Self {
        pk.0.to_compressed().to_vec()
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&Vec<u8>> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes).ok_or(Error::General("Invalid public key"))
    }
}

impl TryFrom<Box<[u8]>> for PublicKey {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl PublicKey {
    /// Check if this public key is valid
    pub fn is_valid(&self) -> Choice {
        !self.0.is_identity()
    }

    /// Check if this public key is invalid
    pub fn is_invalid(&self) -> Choice {
        self.0.is_identity()
    }

    /// Get the bytes of this public key
    pub fn to_bytes(&self) -> [u8; G2Projective::COMPRESSED_BYTES] {
        self.0.to_compressed()
    }

    /// Convert a byte sequence into the public key
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != G2Projective::COMPRESSED_BYTES {
            return None;
        }
        let bytes = bytes.try_into().ok()?;
        Option::from(G2Projective::from_compressed(&bytes).map(Self))
    }
}
