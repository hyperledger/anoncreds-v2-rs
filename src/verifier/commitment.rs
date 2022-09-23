use crate::presentation::CommitmentProof;
use crate::statement::CommitmentStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use group::Curve;
use merlin::Transcript;
use yeti::knox::bls12_381_plus::{G1Projective, Scalar};

pub struct CommitmentVerifier<'a, 'b> {
    pub statement: &'a CommitmentStatement<G1Projective>,
    pub proof: &'b CommitmentProof,
}

impl<'a, 'b> ProofVerifier for CommitmentVerifier<'a, 'b> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let blind_commitment = self.proof.commitment * -challenge
            + self.statement.message_generator * self.proof.message_proof
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

    fn verify(&self, _challenge: Scalar, _transcript: &mut Transcript) -> CredxResult<()> {
        Ok(())
    }
}
