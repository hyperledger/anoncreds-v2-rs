use super::PublicKey;
use crate::error::Error;
use crate::knox::bbs::SecretKey;
use crate::knox::short_group_sig_core::short_group_traits::BlindSignatureContext as BlindSignatureContextTrait;
use crate::CredxResult;
use blsful::inner_types::{Curve, G1Projective, Scalar};
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

impl BlindSignatureContextTrait for BlindSignatureContext {
    type SecretKey = SecretKey;

    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another way
    fn verify(
        &self,
        known_messages: &[usize],
        sk: &Self::SecretKey,
        nonce: Scalar,
    ) -> CredxResult<bool> {
        let pk = PublicKey::from(sk);
        let mut known = BTreeSet::new();
        let mut points = Vec::with_capacity(pk.y.len());
        for idx in known_messages {
            if *idx >= pk.y.len() {
                return Err(Error::InvalidSignatureProofData);
            }
            known.insert(*idx);
        }
        for i in 0..pk.y.len() {
            if !known.contains(&i) {
                points.push(pk.y[i]);
            }
        }
        points.push(self.commitment);

        let mut scalars = self.proofs.clone();
        scalars.push(-self.challenge);

        let mut transcript = Transcript::new(b"new blind signature");
        transcript.append_message(b"public key", pk.to_bytes().as_ref());
        transcript.append_message(b"generator", &G1Projective::GENERATOR.to_compressed());
        let mut res = [0u8; 64];

        let commitment = G1Projective::sum_of_products(points.as_ref(), scalars.as_ref());
        transcript.append_message(
            b"random commitment",
            &commitment.to_affine().to_compressed(),
        );
        transcript.append_message(
            b"blind commitment",
            &self.commitment.to_affine().to_compressed(),
        );
        transcript.append_message(b"nonce", &nonce.to_be_bytes());
        transcript.challenge_bytes(b"blind signature context challenge", &mut res);
        let challenge = Scalar::from_bytes_wide(&res);

        Ok(self.challenge.ct_eq(&challenge).unwrap_u8() == 1)
    }
}
