use crate::error::Error;
use crate::knox::accumulator::vb20::{Element, ProofParams};
use crate::presentation::RevocationProof;
use crate::statement::RevocationStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use merlin::Transcript;

pub struct RevocationVerifier<'a, 'b> {
    statement: &'a RevocationStatement,
    accumulator_proof: &'b RevocationProof,
    params: ProofParams,
    message_proof: Scalar,
}

impl<'a, 'b> RevocationVerifier<'a, 'b> {
    pub fn new(
        statement: &'a RevocationStatement,
        accumulator_proof: &'b RevocationProof,
        nonce: &[u8],
        message_proof: Scalar,
    ) -> Self {
        let params = ProofParams::new(statement.verification_key, Some(nonce));
        Self {
            statement,
            accumulator_proof,
            params,
            message_proof,
        }
    }
}

impl ProofVerifier for RevocationVerifier<'_, '_> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        self.params.add_to_transcript(transcript);
        let finalized = self.accumulator_proof.proof.finalize(
            self.statement.accumulator,
            self.params,
            self.statement.verification_key,
            Element(challenge),
        );
        finalized.get_bytes_for_challenge(transcript);
        Ok(())
    }

    fn verify(&self, _challenge: Scalar) -> CredxResult<()> {
        if self.accumulator_proof.proof.s_y != self.message_proof {
            return Err(Error::InvalidPresentationData(format!(
                "revocation claim proof '{}' does not match the signature's same claim proof '{}'",
                hex::encode(self.accumulator_proof.proof.s_y.to_be_bytes()),
                hex::encode(self.message_proof.to_be_bytes())
            )));
        }
        Ok(())
    }
}
