use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::CommitmentStatement;
use crate::CredxResult;
use blsful::inner_types::{ff::Field, group::Curve, G1Projective, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A commitment builder
pub(crate) struct CommitmentBuilder<'a> {
    pub(crate) commitment: G1Projective,
    pub(crate) statement: &'a CommitmentStatement<G1Projective>,
    pub(crate) message: Scalar,
    pub(crate) b: Scalar,
    pub(crate) r: Scalar,
}

impl<'a> PresentationBuilder for CommitmentBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let message_proof = self.b + challenge * self.message;
        let blinder_proof = self.r + challenge * self.b;
        CommitmentProof {
            id: self.statement.id.clone(),
            commitment: self.commitment,
            message_proof,
            blinder_proof,
        }
        .into()
    }
}

impl<'a> CommitmentBuilder<'a> {
    /// Creates a commitment builder
    pub fn commit(
        statement: &'a CommitmentStatement<G1Projective>,
        message: Scalar,
        b: Scalar,
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let r = Scalar::random(&mut rng);

        let commitment = statement.message_generator * message + statement.blinder_generator * b;
        let blind_commitment = statement.message_generator * b + statement.blinder_generator * r;

        transcript.append_message(b"", statement.id.as_bytes());
        transcript.append_message(
            b"commitment",
            commitment.to_affine().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"blind commitment",
            blind_commitment.to_affine().to_compressed().as_slice(),
        );
        Ok(Self {
            commitment,
            statement,
            message,
            b,
            r,
        })
    }
}

/// A commitment proof
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitmentProof {
    /// The statement identifier
    pub id: String,
    /// The commitment
    pub commitment: G1Projective,
    /// The schnorr message proof
    pub message_proof: Scalar,
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
}
