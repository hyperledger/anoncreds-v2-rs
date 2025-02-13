use crate::presentation::CommitmentProof;
use crate::statement::CommitmentStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use elliptic_curve::group::Curve;
use merlin::Transcript;

pub struct CommitmentVerifier<'a, 'b> {
    pub statement: &'a CommitmentStatement<G1Projective>,
    pub proof: &'b CommitmentProof,
    pub message_proof: Scalar,
}

impl ProofVerifier for CommitmentVerifier<'_, '_> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let blind_commitment = self.proof.commitment * -challenge
            + self.statement.message_generator * self.message_proof
            + self.statement.blinder_generator * self.proof.blinder_proof;

        transcript.append_message(b"", self.statement.id.as_bytes());
        transcript.append_message(
            b"commitment",
            self.proof.commitment.to_affine().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"blind commitment",
            blind_commitment.to_affine().to_compressed().as_slice(),
        );
        Ok(())
    }

    fn verify(&self, _challenge: Scalar) -> CredxResult<()> {
        Ok(())
    }
}
