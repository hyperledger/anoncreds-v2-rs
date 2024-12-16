use crate::error::Error;
use crate::knox::bbs::ExpandedPublicKey;
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledge;
use crate::CredxResult;
use blsful::inner_types::{
    multi_miller_loop, G1Affine, G2Affine, G2Prepared, MillerLoopResult, PrimeCurveAffine, Scalar,
};
use bulletproofs::inner_types::G1Projective;
use elliptic_curve::group::Curve;
use elliptic_curve::{Group, PrimeField};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The actual proof that is sent from prover to verifier.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PokSignatureProof {
    pub(crate) a_bar: G1Projective,
    pub(crate) b_bar: G1Projective,
    pub(crate) commitment: G1Projective,
    pub(crate) proof: Vec<Scalar>,
}

impl ProofOfSignatureKnowledge for PokSignatureProof {
    type PublicKey = ExpandedPublicKey;

    fn add_proof_contribution(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
        challenge: Scalar,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"a_bar", self.a_bar.to_affine().to_compressed().as_ref());
        transcript.append_message(b"b_bar", self.b_bar.to_affine().to_compressed().as_ref());
        transcript.append_message(
            b"random commitment",
            self.commitment.to_affine().to_compressed().as_ref(),
        );
        let mut known = BTreeSet::new();
        for (idx, _) in revealed_messages {
            known.insert(*idx);
        }

        let mut points = Vec::with_capacity(public_key.y.len() + 2);
        for (idx, _) in public_key.y.iter().enumerate() {
            if known.contains(&idx) {
                continue;
            }
            points.push(public_key.y[idx]);
        }
        points.push(self.commitment);
        points.push(self.a_bar);
        points.push(self.b_bar);
        let mut scalars = self.proof.clone();
        scalars.push(-challenge);
        let commitment = G1Projective::sum_of_products(&points, &scalars);
        transcript.append_message(
            b"blind commitment",
            commitment.to_affine().to_compressed().as_ref(),
        );
    }

    fn verify(
        &self,
        revealed_messages: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
    ) -> CredxResult<()> {
        if (self.a_bar.is_identity() | self.b_bar.is_identity()).into() {
            return Err(Error::General("Invalid proof - identity"));
        }
        if public_key.is_invalid().into() {
            return Err(Error::General("Invalid public key"));
        }
        let mut points = Vec::with_capacity(public_key.y.len() + 2);
        let mut msgs = Vec::with_capacity(revealed_messages.len());
        for (idx, msg) in revealed_messages {
            if *idx >= public_key.y.len() {
                continue;
            }
            points.push(public_key.y[*idx]);
            msgs.push(*msg);
        }
        let commitment = G1Projective::GENERATOR + G1Projective::sum_of_products(&points, &msgs);
        if self.commitment != commitment {
            return Err(Error::General("Invalid proof - commitment"));
        }

        let res = multi_miller_loop(&[
            (
                &self.a_bar.to_affine(),
                &G2Prepared::from(public_key.w.to_affine()),
            ),
            (
                &self.b_bar.to_affine(),
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

    fn get_hidden_message_proofs(
        &self,
        public_key: &Self::PublicKey,
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
            let message = self.proof.get(i).ok_or(Error::General("invalid proof"))?;
            hidden.insert(i, *message);
        }

        Ok(hidden)
    }
}

impl PokSignatureProof {
    /// Store the proof as a sequence of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(48 * 3 + 32 * self.proof.len());

        buffer.extend_from_slice(&self.a_bar.to_affine().to_compressed());
        buffer.extend_from_slice(&self.b_bar.to_affine().to_compressed());
        buffer.extend_from_slice(&self.commitment.to_affine().to_compressed());
        for scalar in &self.proof {
            buffer.extend_from_slice(scalar.to_repr().as_ref());
        }
        buffer
    }

    /// Convert a byte sequence into a Signature Proof of Knowledge
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        const SIZE: usize = 32 * 3 + 48 * 3;
        let buffer = bytes.as_ref();
        if buffer.len() < SIZE {
            return None;
        }
        if buffer.len() % 32 != 0 {
            return None;
        }

        let hid_msg_cnt = (buffer.len() - 48 * 3) / 32;
        let mut offset = 48;
        let mut end = 96;
        let a_bar = G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[..offset]).unwrap())
            .map(G1Projective::from);
        let b_bar = G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[offset..end]).unwrap())
            .map(G1Projective::from);
        offset = end;
        end += 48;
        let commitment =
            G1Affine::from_compressed(&<[u8; 48]>::try_from(&buffer[offset..end]).unwrap())
                .map(G1Projective::from);

        if (a_bar.is_none() | b_bar.is_none() | commitment.is_none()).into() {
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
            a_bar: a_bar.unwrap(),
            b_bar: b_bar.unwrap(),
            commitment: commitment.unwrap(),
            proof,
        })
    }
}
