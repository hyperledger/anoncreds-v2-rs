use crate::error::Error;
use crate::knox::bbs::{PokSignatureProof, PublicKey, Signature};
use crate::knox::short_group_sig_core::{
    short_group_traits::ProofOfSignatureKnowledgeContribution, *,
};
use crate::CredxResult;
use blsful::inner_types::{G1Affine, G1Projective, Scalar};
use elliptic_curve::Field;
use merlin::Transcript;
use rand_core::*;

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
pub struct PokSignature {
    proof: ProofCommittedBuilder<G1Projective, G1Affine, Scalar>,
    a_bar: G1Projective,
    b_bar: G1Projective,
    hidden_messages: Vec<Scalar>,
}

impl ProofOfSignatureKnowledgeContribution for PokSignature {
    type Signature = Signature;
    type PublicKey = PublicKey;
    type ProofOfKnowledge = PokSignatureProof;

    fn commit(
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
        messages: &[ProofMessage<Scalar>],
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self> {
        let msgs = messages.iter().map(|m| m.get_message()).collect::<Vec<_>>();

        let r = Scalar::random(&mut rng);
        let r_inv = Option::from((-r).invert()).ok_or(Error::InvalidPresentationData)?;
        let r_inv_e = r_inv * signature.e;

        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&public_key.y, &msgs);

        let a_bar = signature.a * r;
        let b_bar = b * r - a_bar * signature.e;

        let mut proof = ProofCommittedBuilder::new(G1Projective::sum_of_products);
        let mut hidden_messages = Vec::with_capacity(msgs.len());

        for (i, m) in messages.iter().enumerate() {
            match m {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(msg)) => {
                    proof.commit_random(public_key.y[i], &mut rng);
                    hidden_messages.push(*msg);
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(msg, n)) => {
                    proof.commit(public_key.y[i], *n);
                    hidden_messages.push(*msg);
                }
                ProofMessage::Revealed(_) => {}
            }
        }
        proof.commit_random(a_bar, &mut rng);
        hidden_messages.push(r_inv_e);
        proof.commit_random(b_bar, &mut rng);
        hidden_messages.push(r_inv);
        Ok(Self {
            proof,
            a_bar,
            b_bar,
            hidden_messages,
        })
    }

    fn add_proof_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"a_bar", self.a_bar.to_compressed().as_ref());
        transcript.append_message(b"b_bar", self.b_bar.to_compressed().as_ref());
        self.proof
            .add_challenge_contribution(b"commitment", transcript);
    }

    fn generate_proof(self, challenge: Scalar) -> CredxResult<Self::ProofOfKnowledge> {
        let proof = self
            .proof
            .generate_proof(challenge, &self.hidden_messages)?;
        Ok(PokSignatureProof {
            a_bar: self.a_bar,
            b_bar: self.b_bar,
            t: self.proof.commitment(),
            proof,
        })
    }
}
