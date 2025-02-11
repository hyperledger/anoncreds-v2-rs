use super::PublicKey;
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledge;
use crate::CredxResult;
use blsful::inner_types::*;
use core::ops::BitOr;
use elliptic_curve::group::prime::PrimeCurveAffine;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The actual proof that is sent from prover to verifier.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PokSignatureProof {
    pub(crate) sigma_1: G1Projective,
    pub(crate) sigma_2: G1Projective,
    pub(crate) commitment: G2Projective,
    pub(crate) proof: Vec<Scalar>,
}

impl ProofOfSignatureKnowledge for PokSignatureProof {
    type PublicKey = PublicKey;

    /// Convert the committed values to bytes for the fiat-shamir challenge
    fn add_proof_contribution(
        &self,
        public_key: &PublicKey,
        rvl_msgs: &[(usize, Scalar)],
        challenge: Scalar,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(
            b"sigma_1",
            self.sigma_1.to_affine().to_compressed().as_ref(),
        );
        transcript.append_message(
            b"sigma_2",
            self.sigma_2.to_affine().to_compressed().as_ref(),
        );
        transcript.append_message(
            b"random commitment",
            self.commitment.to_affine().to_compressed().as_ref(),
        );

        let mut points = Vec::new();

        points.push(G2Projective::GENERATOR);
        points.push(public_key.w);

        let mut known = BTreeSet::new();
        for (idx, _) in rvl_msgs {
            known.insert(*idx);
        }

        for i in 0..public_key.y.len() {
            if known.contains(&i) {
                continue;
            }
            points.push(public_key.y[i]);
        }
        points.push(self.commitment);

        let mut scalars = self.proof.clone();
        scalars.push(-challenge);
        let commitment = G2Projective::sum_of_products(points.as_ref(), scalars.as_ref());
        transcript.append_message(
            b"blind commitment",
            commitment.to_affine().to_compressed().as_ref(),
        );
    }

    /// Validate the proof, only checks the signature proof
    /// the selective disclosure proof is checked by verifying
    /// self.challenge == computed_challenge
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
        _challenge: Scalar,
    ) -> CredxResult<()> {
        // check the signature proof
        if self
            .sigma_1
            .is_identity()
            .bitor(self.sigma_2.is_identity())
            .unwrap_u8()
            == 1
        {
            return Err(Error::General("Invalid proof - identity"));
        }

        if public_key.y.len() < revealed_messages.len() {
            return Err(Error::General(
                "Invalid key - revealed messages length is bigger than the public key",
            ));
        }
        if public_key.is_invalid().into() {
            return Err(Error::General("Invalid public key"));
        }

        let mut points = Vec::new();
        let mut scalars = Vec::new();

        for (idx, msg) in revealed_messages {
            if *idx > public_key.y.len() {
                return Err(Error::General("Invalid proof - revealed message index"));
            }
            points.push(public_key.y[*idx]);
            scalars.push(*msg);
        }
        points.push(public_key.x);
        scalars.push(Scalar::ONE);
        points.push(self.commitment);
        scalars.push(Scalar::ONE);

        let j = G2Projective::sum_of_products(points.as_ref(), scalars.as_ref());

        let res = multi_miller_loop(&[
            (&self.sigma_1.to_affine(), &G2Prepared::from(j.to_affine())),
            (
                &self.sigma_2.to_affine(),
                &G2Prepared::from(-G2Affine::generator()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1;
        if res {
            Ok(())
        } else {
            Err(Error::General("Invalid proof - signature proof"))
        }
    }

    /// Return the Schnorr proofs for all hidden messages
    fn get_hidden_message_proofs(
        &self,
        public_key: &PublicKey,
        rvl_msgs: &[(usize, Scalar)],
    ) -> CredxResult<BTreeMap<usize, Scalar>> {
        if public_key.y.len() < rvl_msgs.len() {
            return Err(Error::General("Proof error"));
        }
        if public_key.is_invalid().unwrap_u8() == 1u8 {
            return Err(Error::General("Proof error"));
        }
        let mut hidden = BTreeMap::new();
        let mut j = 0;
        for i in 0..public_key.y.len() {
            if j < rvl_msgs.len() && rvl_msgs[j].0 == i {
                j += 1;
                continue;
            }
            let message = self
                .proof
                // + 2 because ProofOfSignatureKnowledgeContribution.commit adds
                // two secrets before adding secrets for attributes
                .get(i + 2 - j)
                .ok_or(Error::General("invalid proof"))?;
            hidden.insert(i, *message);
        }

        Ok(hidden)
    }
}

impl PokSignatureProof {
    /// Store the proof as a sequence of bytes
    /// Each point is compressed to big-endian format
    /// Needs (N + 2) * 32 + 48 * 2 + 96 space otherwise it will panic
    /// where N is the number of hidden messages
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(48 * 2 + 96 + 32 * self.proof.len());
        buffer.extend_from_slice(&self.sigma_1.to_affine().to_compressed());
        buffer.extend_from_slice(&self.sigma_2.to_affine().to_compressed());
        buffer.extend_from_slice(&self.commitment.to_affine().to_compressed());

        for m in &self.proof {
            buffer.extend_from_slice(m.to_be_bytes().as_ref());
        }
        buffer
    }

    /// Convert a byte sequence into a Signature Proof of Knowledge
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        const SIZE: usize = 32 * 3 + 48 * 4;
        let buffer = bytes.as_ref();
        if buffer.len() < SIZE {
            return None;
        }
        if buffer.len() % 32 != 0 {
            return None;
        }

        let hid_msg_cnt = (buffer.len() - 48 * 4) / 32;
        let mut offset = 48;
        let mut end = 96;
        let sigma_1 = G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[..offset]).unwrap())
            .map(G1Projective::from);
        let sigma_2 =
            G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[offset..end]).unwrap())
                .map(G1Projective::from);
        offset = end;
        end += 96;
        let commitment =
            G2Affine::from_compressed(&<[u8; 96]>::try_from(&buffer[offset..end]).unwrap())
                .map(G2Projective::from);

        if sigma_1.is_none().unwrap_u8() == 1
            || sigma_2.is_none().unwrap_u8() == 1
            || commitment.is_none().unwrap_u8() == 1
        {
            return None;
        }

        offset = end;
        end += 32;

        let mut proof = Vec::new();
        for _ in 0..hid_msg_cnt {
            let c = Scalar::from_be_bytes(&<[u8; 32]>::try_from(&buffer[offset..end]).unwrap());
            offset = end;
            end = offset + 32;
            if c.is_none().unwrap_u8() == 1 {
                return None;
            }

            proof.push(c.unwrap());
        }
        Some(Self {
            sigma_1: sigma_1.unwrap(),
            sigma_2: sigma_2.unwrap(),
            commitment: commitment.unwrap(),
            proof,
        })
    }
}
