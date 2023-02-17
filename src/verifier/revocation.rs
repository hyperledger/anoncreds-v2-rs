use crate::presentation::RevocationProof;
use crate::statement::RevocationStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use merlin::Transcript;
use crate::knox::accumulator::vb20::{Element, ProofParams};
use signature_bls::bls12_381_plus::Scalar;

pub struct RevocationVerifier<'a, 'b> {
    statement: &'a RevocationStatement,
    accumulator_proof: &'b RevocationProof,
    params: ProofParams,
}

impl<'a, 'b> RevocationVerifier<'a, 'b> {
    pub fn new(
        statement: &'a RevocationStatement,
        accumulator_proof: &'b RevocationProof,
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

impl<'a, 'b> ProofVerifier for RevocationVerifier<'a, 'b> {
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
        Ok(())
    }
}
