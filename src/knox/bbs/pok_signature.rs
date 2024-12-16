use crate::knox::bbs::{ExpandedPublicKey, PokSignatureProof, Signature};
use crate::knox::short_group_sig_core::{
    short_group_traits::ProofOfSignatureKnowledgeContribution, *,
};
use crate::CredxResult;
use blsful::inner_types::{G1Affine, G1Projective, Scalar};
use elliptic_curve::{group::Curve, Field};
use merlin::Transcript;
use rand_core::*;

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
pub struct PokSignature {
    proof: ProofCommittedBuilder<G1Projective, G1Affine, Scalar>,
    a_bar: G1Projective,
    b_bar: G1Projective,
    commitment: G1Projective,
    hidden_messages: Vec<Scalar>,
}

impl ProofOfSignatureKnowledgeContribution for PokSignature {
    type Signature = Signature;
    type PublicKey = ExpandedPublicKey;
    type ProofOfKnowledge = PokSignatureProof;

    fn commit(
        signature: Self::Signature,
        public_key: &Self::PublicKey,
        messages: &[ProofMessage<Scalar>],
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self> {
        let msgs = messages.iter().map(|m| m.get_message()).collect::<Vec<_>>();

        let signature_randomizer = Scalar::random(&mut rng);
        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&public_key.y, &msgs);

        let a_bar = signature.a * signature_randomizer;
        let b_bar = b * signature_randomizer - a_bar * signature.e;

        let mut proof = ProofCommittedBuilder::new(G1Projective::sum_of_products);
        let mut points = Vec::with_capacity(msgs.len());
        let mut hidden_messages = Vec::with_capacity(msgs.len());
        let mut revealed_messages = Vec::with_capacity(msgs.len());

        for (i, m) in messages.iter().enumerate() {
            match m {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(msg)) => {
                    proof.commit_random(public_key.y[i], &mut rng);
                    hidden_messages.push(*msg * signature_randomizer);
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(msg, n)) => {
                    proof.commit(public_key.y[i], *n);
                    hidden_messages.push(*msg * signature_randomizer);
                }
                ProofMessage::Revealed(msg) => {
                    points.push(public_key.y[i]);
                    revealed_messages.push(*msg);
                }
            }
        }
        let commitment =
            G1Projective::GENERATOR + G1Projective::sum_of_products(&points, &revealed_messages);
        proof.commit_random(commitment, &mut rng);
        hidden_messages.push(signature_randomizer);
        proof.commit_random(a_bar, &mut rng);
        hidden_messages.push(-signature.e);
        Ok(Self {
            proof,
            a_bar,
            b_bar,
            commitment,
            hidden_messages,
        })
    }

    fn add_proof_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"a_bar", self.a_bar.to_affine().to_compressed().as_ref());
        transcript.append_message(b"b_bar", self.b_bar.to_affine().to_compressed().as_ref());
        transcript.append_message(
            b"random commitment",
            self.commitment.to_affine().to_compressed().as_ref(),
        );
        self.proof
            .add_challenge_contribution(b"blind commitment", transcript);
    }

    fn generate_proof(self, challenge: Scalar) -> CredxResult<Self::ProofOfKnowledge> {
        let proof = self
            .proof
            .generate_proof(challenge, &self.hidden_messages)?;
        Ok(PokSignatureProof {
            a_bar: self.a_bar,
            b_bar: self.b_bar,
            commitment: self.commitment,
            proof,
        })
    }
}
