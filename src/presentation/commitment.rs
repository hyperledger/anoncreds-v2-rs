use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::CommitmentStatement;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use elliptic_curve::{group::Curve, Field};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A commitment builder
#[derive(Debug)]
pub(crate) struct CommitmentBuilder<'a> {
    pub(crate) commitment: G1Projective,
    pub(crate) statement: &'a CommitmentStatement<G1Projective>,
    pub(crate) b: Scalar,
    pub(crate) r: Scalar,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S> for CommitmentBuilder<'_> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        let blinder_proof = self.r + challenge * self.b;
        CommitmentProof {
            id: self.statement.id.clone(),
            commitment: self.commitment,
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
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
}
