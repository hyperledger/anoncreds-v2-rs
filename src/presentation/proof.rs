use crate::presentation::PresentationSchema;
use crate::CredxResult;

/// The methods for proofs given in the presentation
pub trait PresentationProof {
    /// Recreate the proof contributions for schnorr proofs
    fn get_proof_contribution(
        &self,
        schema: &PresentationSchema,
        transcript: &mut merlin::Transcript,
    );
    /// Verify this proof if separate from schnorr
    fn verify(&self, schema: &PresentationSchema) -> CredxResult<()>;
}
