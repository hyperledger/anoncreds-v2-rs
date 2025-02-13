use crate::error::Error;
use crate::knox::bbs::PublicKey;
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
    pub(crate) t: G1Projective,
    pub(crate) proof: Vec<Scalar>,
}

impl ProofOfSignatureKnowledge for PokSignatureProof {
    type PublicKey = PublicKey;

    fn add_proof_contribution(
        &self,
        _public_key: &Self::PublicKey,
        _revealed_messages: &[(usize, Scalar)],
        _challenge: Scalar,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"a_bar", self.a_bar.to_compressed().as_ref());
        transcript.append_message(b"b_bar", self.b_bar.to_compressed().as_ref());
        transcript.append_message(b"commitment", self.t.to_compressed().as_ref());
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
        challenge: Scalar,
    ) -> CredxResult<()> {
        if (self.a_bar.is_identity() | self.b_bar.is_identity() | self.t.is_identity()).into() {
            return Err(Error::General("Invalid proof - identity"));
        }
        if public_key.is_invalid().into() {
            return Err(Error::General("Invalid public key"));
        }
        let mut points = Vec::with_capacity(public_key.y.len() + 3);
        let mut msgs = Vec::with_capacity(revealed_messages.len());
        let mut known = BTreeSet::new();
        for (idx, msg) in revealed_messages {
            if *idx >= public_key.y.len() {
                continue;
            }
            known.insert(*idx);
            points.push(public_key.y[*idx]);
            msgs.push(*msg);
        }
        let lhs = -G1Projective::sum_of_products(&points, &msgs) - G1Projective::GENERATOR;
        points.clear();
        msgs.clear();

        for (idx, y) in public_key.y.iter().enumerate() {
            if known.contains(&idx) {
                continue;
            }
            points.push(*y);
        }

        points.push(self.a_bar);
        points.push(self.b_bar);
        points.push(lhs);
        let mut scalars = self.proof.clone();
        scalars.push(-challenge);
        let commitment = G1Projective::sum_of_products(&points, &scalars);
        if self.t != commitment {
            return Err(Error::General("Invalid proof - invalid messages"));
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
            let message = self
                .proof
                .get(i - j)
                .ok_or(Error::General("invalid proof"))?;
            hidden.insert(i, *message);
        }

        Ok(hidden)
    }
}

impl PokSignatureProof {
    /// Store the proof as a sequence of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(48 * 3 + 32 * self.proof.len());

        buffer.extend_from_slice(&self.a_bar.to_compressed());
        buffer.extend_from_slice(&self.b_bar.to_compressed());
        buffer.extend_from_slice(&self.t.to_compressed());
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
            t: commitment.unwrap(),
            proof,
        })
    }
}
