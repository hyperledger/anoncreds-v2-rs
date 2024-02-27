use super::SecretKey;
use crate::{
    error::Error, knox::short_group_sig_core::short_group_traits::PublicKey as PublicKeyTrait,
};
use blsful::inner_types::*;
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use subtle::Choice;

/// The public key contains a generator point for each
/// message that is signed and two extra.
/// See section 4.2 in
/// <https://eprint.iacr.org/2015/525.pdf> and
/// <https://eprint.iacr.org/2017/1197.pdf>
///
/// `w` corresponds to m' in the paper to achieve
/// EUF-CMA security level.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKey {
    /// The secret for m'
    pub w: G2Projective,
    /// The blinding secret
    pub x: G2Projective,
    /// The secrets for each signed message
    pub y: Vec<G2Projective>,
    /// The secrets for each signed message for blinding purposes
    pub y_blinds: Vec<G1Projective>,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            w: G2Projective::IDENTITY,
            x: G2Projective::IDENTITY,
            y: Vec::new(),
            y_blinds: Vec::new(),
        }
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let w = G2Projective::GENERATOR * sk.w;
        let x = G2Projective::GENERATOR * sk.x;
        let mut y = Vec::new();
        let mut y_blinds = Vec::new();
        for s_y in &sk.y {
            y.push(G2Projective::GENERATOR * s_y);
            y_blinds.push(G1Projective::GENERATOR * s_y);
        }
        Self { w, x, y, y_blinds }
    }
}

impl PublicKeyTrait for PublicKey {
    type MessageGenerator = G2Projective;
    type BlindMessageGenerator = G1Projective;
}

impl From<PublicKey> for Vec<u8> {
    fn from(pk: PublicKey) -> Self {
        Self::from(&pk)
    }
}

impl From<&PublicKey> for Vec<u8> {
    fn from(pk: &PublicKey) -> Self {
        pk.to_bytes()
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
        let mut res = !self.w.is_identity();
        res &= !self.x.is_identity();
        for y in &self.y {
            res &= !y.is_identity();
        }
        for y in &self.y_blinds {
            res &= !y.is_identity();
        }
        res
    }

    /// Check if this public key is invalid
    pub fn is_invalid(&self) -> Choice {
        let mut res = self.w.is_identity();
        res |= self.x.is_identity();
        for y in &self.y {
            res |= y.is_identity();
        }
        for y in &self.y_blinds {
            res |= y.is_identity();
        }
        res
    }

    /// Store the public key as a sequence of bytes
    /// Each scalar is compressed to big-endian format
    /// Needs (N + 2) * P space otherwise it will panic
    /// where N is the number of messages that can be signed
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.w.to_affine().to_compressed()[..]);
        buffer.extend_from_slice(&self.x.to_affine().to_compressed()[..]);
        buffer.extend_from_slice(&(self.y.len() as u32).to_be_bytes()[..]);
        for y in &self.y {
            buffer.extend_from_slice(&y.to_affine().to_compressed()[..]);
        }
        buffer.extend_from_slice(&(self.y_blinds.len() as u32).to_be_bytes()[..]);
        for y in &self.y_blinds {
            buffer.extend_from_slice(&y.to_affine().to_compressed()[..]);
        }
        buffer
    }

    /// Convert a byte sequence into the public key
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        const SIZE: usize = 48;
        // Length for w, x, and 1 y in g1 and 1 y in g2
        const MIN_SIZE: usize = SIZE * 5 + 8;

        let buffer = bytes.as_ref();
        if buffer.len() < MIN_SIZE {
            return None;
        }

        fn from_be_bytes(d: &[u8]) -> G2Projective {
            let mut tv = <G2Projective as GroupEncoding>::Repr::default();
            tv.as_mut().copy_from_slice(d);
            G2Projective::from_bytes(&tv).unwrap()
        }

        let mut offset = 0;
        let mut end = SIZE;
        let w = from_be_bytes(&buffer[offset..end]);
        offset = end;
        end += SIZE;

        let x = from_be_bytes(&buffer[offset..end]);
        offset = end;
        end += 4;

        let y_cnt = u32::from_be_bytes(<[u8; 4]>::try_from(&buffer[offset..end]).unwrap()) as usize;
        offset = end;
        end += SIZE * 2;

        let mut y = Vec::new();

        for _ in 0..y_cnt {
            y.push(from_be_bytes(&buffer[offset..end]));
            offset = end;
            end += SIZE * 2;
        }

        offset = end;
        end += 4;

        let mut y_blinds = Vec::new();
        let y_blind_cnt =
            u32::from_be_bytes(<[u8; 4]>::try_from(&buffer[offset..end]).unwrap()) as usize;

        offset = end;
        end += SIZE;

        for _ in 0..y_blind_cnt {
            let mut tv = <G1Projective as GroupEncoding>::Repr::default();
            tv.as_mut().copy_from_slice(&buffer[offset..end]);
            y_blinds.push(G1Projective::from_bytes(&tv).unwrap());
            offset = end;
            end += SIZE;
        }
        Some(Self { w, x, y, y_blinds })
    }
}
