use super::SecretKey;
use crate::CredxResult;
use blsful::bls12_381_plus::{group::Curve, G1Affine, G1Projective, Scalar};
use core::convert::TryFrom;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureContext {
    /// The blinded signature commitment
    pub commitment: G1Projective,
    /// The challenge hash for the Fiat-Shamir heuristic
    pub challenge: Scalar,
    /// The proofs for the hidden messages
    pub proofs: Vec<Scalar>,
}

impl BlindSignatureContext {
    /// Store the generators as a sequence of bytes
    /// Each point is compressed to big-endian format
    /// Needs (N + 1) * 32 + 48 * 2 space otherwise it will panic
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(self.commitment.to_affine().to_compressed().as_ref());
        buffer.extend_from_slice(&self.challenge.to_bytes());

        for i in 0..self.proofs.len() {
            buffer.extend_from_slice(&self.proofs[i].to_bytes());
        }
        buffer
    }

    /// Convert a byte sequence into the blind signature context
    /// Expected size is (N + 1) * 32 + 48 bytes
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let size = 32 * 2 + 48;
        let buffer = bytes.as_ref();
        if buffer.len() < size {
            return None;
        }
        if buffer.len() - 48 % 32 != 0 {
            return None;
        }

        let commitment = G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[..48]).unwrap())
            .map(G1Projective::from);
        if commitment.is_none().unwrap_u8() == 1 {
            return None;
        }
        let mut offset = 48;
        let mut end = 80;

        let challenge = Scalar::from_bytes(&<[u8; 32]>::try_from(&buffer[offset..end]).unwrap());
        if challenge.is_none().unwrap_u8() == 1 {
            return None;
        }

        let times = (buffer.len() - 48 - 32) / 32;

        offset = end;
        end += 32;

        let mut proofs = Vec::new();
        for _ in 0..times {
            let p = Scalar::from_bytes(&<[u8; 32]>::try_from(&buffer[offset..end]).unwrap());
            if p.is_none().unwrap_u8() == 1 {
                return None;
            }
            proofs.push(p.unwrap());
            offset = end;
            end += 32;
        }

        Some(Self {
            commitment: commitment.unwrap(),
            challenge: challenge.unwrap(),
            proofs,
        })
    }

    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another way
    pub fn verify(
        &self,
        known_messages: &[usize],
        sk: &SecretKey,
        nonce: Scalar,
    ) -> CredxResult<bool> {
        let mut known = BTreeSet::new();
        let mut points = Vec::new();
        for idx in known_messages {
            if *idx >= sk.y.len() {
                return Err(crate::error::Error::InvalidSignatureProofData);
            }
            known.insert(*idx);
        }
        for i in 0..sk.y.len() {
            if !known.contains(&i) {
                points.push(G1Projective::GENERATOR * sk.y[i]);
            }
        }
        points.push(G1Projective::GENERATOR);
        points.push(self.commitment);

        let mut scalars = self.proofs.clone();
        scalars.push(-self.challenge);

        let mut transcript = Transcript::new(b"new blind signature");
        let mut res = [0u8; 64];

        let commitment = G1Projective::sum_of_products_in_place(points.as_ref(), scalars.as_mut());
        transcript.append_message(
            b"random commitment",
            &commitment.to_affine().to_compressed(),
        );
        transcript.append_message(
            b"blind commitment",
            &self.commitment.to_affine().to_compressed(),
        );
        transcript.append_message(b"nonce", &nonce.to_bytes());
        transcript.challenge_bytes(b"blind signature context challenge", &mut res);
        let challenge = Scalar::from_bytes_wide(&res);

        Ok(self.challenge.ct_eq(&challenge).unwrap_u8() == 1)
    }
}
