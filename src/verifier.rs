mod signature;

use crate::CredxResult;
use merlin::Transcript;
pub use signature::*;
use yeti::knox::bls12_381_plus::Scalar;

/// A trait for indication of proof verifier logic
pub(crate) trait ProofVerifier {
    /// Recompute the challenge contribution
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()>;
    /// Verify any additional proof material
    fn verify(&self, challenge: Scalar, transcript: &mut Transcript) -> CredxResult<()>;
}

pub(crate) enum ProofVerifiers<'a, 'b, 'c> {
    Signature(SignatureVerifier<'a, 'b, 'c>),
    AccumulatorSetMembership,
    Equality,
    Commitment,
    VerifiableEncryption,
}
