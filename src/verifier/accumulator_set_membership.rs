use crate::presentation::AccumulatorSetMembershipProof;
use crate::statement::AccumulatorSetMembershipStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use merlin::Transcript;
use yeti::knox::accumulator::vb20::{Element, ProofParams};
use yeti::knox::bls12_381_plus::Scalar;

pub struct AccumulatorSetMembershipVerifier<'a, 'b> {
    statement: &'a AccumulatorSetMembershipStatement,
    accumulator_proof: &'b AccumulatorSetMembershipProof,
    params: ProofParams,
}

impl<'a, 'b> AccumulatorSetMembershipVerifier<'a, 'b> {
    pub fn new(
        statement: &'a AccumulatorSetMembershipStatement,
        accumulator_proof: &'b AccumulatorSetMembershipProof,
        nonce: &[u8],
    ) -> Self {
        let params = ProofParams::new(statement.verification_key, Some(nonce));
        Self {
            statement,
            accumulator_proof,
            params,
        }
    }
}

impl<'a, 'b> ProofVerifier for AccumulatorSetMembershipVerifier<'a, 'b> {
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

    fn verify(&self, _challenge: Scalar, _transcript: &mut Transcript) -> CredxResult<()> {
        Ok(())
    }
}
