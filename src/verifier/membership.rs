use crate::error::Error;
use crate::knox::accumulator::vb20::{Element, ProofParams};
use crate::presentation::MembershipProof;
use crate::statement::MembershipStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use merlin::Transcript;

pub struct MembershipVerifier<'a, 'b> {
    statement: &'a MembershipStatement,
    accumulator_proof: &'b MembershipProof,
    params: ProofParams,
    message_proof: Scalar,
}

impl<'a, 'b> MembershipVerifier<'a, 'b> {
    pub fn new(
        statement: &'a MembershipStatement,
        accumulator_proof: &'b MembershipProof,
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

impl ProofVerifier for MembershipVerifier<'_, '_> {
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
            return Err(Error::InvalidPresentationData);
        }
        Ok(())
    }
}
