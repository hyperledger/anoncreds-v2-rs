use crate::presentation::VerifiableEncryptionProof;
use crate::statement::VerifiableEncryptionStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use group::Curve;
use merlin::Transcript;
use signature_bls::bls12_381_plus::{G1Projective, Scalar};

pub struct VerifiableEncryptionVerifier<'a, 'b> {
    pub statement: &'a VerifiableEncryptionStatement<G1Projective>,
    pub proof: &'b VerifiableEncryptionProof,
}

impl<'a, 'b> ProofVerifier for VerifiableEncryptionVerifier<'a, 'b> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let challenge = -challenge;
        let r1 = self.proof.c1 * challenge + G1Projective::GENERATOR * self.proof.blinder_proof;
        let r2 = self.proof.c2 * challenge
            + self.statement.message_generator * self.proof.message_proof
            + self.statement.encryption_key.0 * self.proof.blinder_proof;

        transcript.append_message(b"", self.statement.id.as_bytes());
        transcript.append_message(b"c1", self.proof.c1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"c2", self.proof.c2.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_affine().to_compressed().as_slice());
        Ok(())
    }

    fn verify(&self, _challenge: Scalar) -> CredxResult<()> {
        Ok(())
    }
}
