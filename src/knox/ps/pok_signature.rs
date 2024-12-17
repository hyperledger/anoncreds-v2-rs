use super::{PokSignatureProof, PublicKey, Signature};
use crate::knox::short_group_sig_core::{
    short_group_traits::ProofOfSignatureKnowledgeContribution, *,
};
use crate::CredxResult;
use blsful::inner_types::{G1Projective, G2Affine, G2Projective, Scalar};
use elliptic_curve::{group::Curve, Field};
use merlin::Transcript;
use rand_core::*;

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
pub struct PokSignature {
    secrets: Vec<Scalar>,
    proof: ProofCommittedBuilder<G2Projective, G2Affine, Scalar>,
    commitment: G2Projective,
    sigma_1: G1Projective,
    sigma_2: G1Projective,
}

impl ProofOfSignatureKnowledgeContribution for PokSignature {
    type Signature = Signature;
    type PublicKey = PublicKey;
    type ProofOfKnowledge = PokSignatureProof;

    /// Creates the initial proof data before a Fiat-Shamir calculation
    fn commit(
        signature: &Signature,
        public_key: &PublicKey,
        messages: &[ProofMessage<Scalar>],
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self> {
        if public_key.y.len() < messages.len() {
            return Err(crate::error::Error::General("ProofCommitmentError"));
        }

        let r = Scalar::random(&mut rng);
        let t = Scalar::random(&mut rng);

        // ZKP for signature
        let sigma_1 = signature.sigma_1 * r;
        let sigma_2 = (signature.sigma_2 + (signature.sigma_1 * t)) * r;

        // Prove knowledge of m_tick, m_1, m_2, ... for all hidden m_i and t in J = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t
        let mut proof = ProofCommittedBuilder::new(G2Projective::sum_of_products);
        let mut points = Vec::new();
        let mut secrets = Vec::new();

        proof.commit_random(G2Projective::GENERATOR, &mut rng);
        points.push(G2Projective::GENERATOR);
        secrets.push(t);

        proof.commit_random(public_key.w, &mut rng);
        points.push(public_key.w);
        secrets.push(signature.m_tick);

        for (i, m) in messages.iter().enumerate() {
            match m {
                ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(msg)) => {
                    proof.commit_random(public_key.y[i], &mut rng);
                    points.push(public_key.y[i]);
                    secrets.push(*msg);
                }
                ProofMessage::Hidden(HiddenMessage::ExternalBlinding(msg, n)) => {
                    proof.commit(public_key.y[i], *n);
                    points.push(public_key.y[i]);
                    secrets.push(*msg);
                }
                ProofMessage::Revealed(_) => {}
            }
        }
        let commitment = G2Projective::sum_of_products(points.as_ref(), secrets.as_ref());
        Ok(Self {
            secrets,
            proof,
            commitment,
            sigma_1,
            sigma_2,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    fn add_proof_contribution(&self, transcript: &mut Transcript) {
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
        self.proof
            .add_challenge_contribution(b"blind commitment", transcript);
    }

    /// Generate the Schnorr challenges for the selective disclosure proofs
    fn generate_proof(self, challenge: Scalar) -> CredxResult<PokSignatureProof> {
        let proof = self
            .proof
            .generate_proof(challenge, self.secrets.as_ref())?;
        Ok(PokSignatureProof {
            sigma_1: self.sigma_1,
            sigma_2: self.sigma_2,
            commitment: self.commitment,
            proof,
        })
    }
}
