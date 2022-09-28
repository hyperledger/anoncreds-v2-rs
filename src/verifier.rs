mod accumulator_set_membership;
mod commitment;
mod equality;
mod range;
mod signature;
mod verifiable_encryption;

pub use accumulator_set_membership::*;
pub use commitment::*;
pub use equality::*;
pub use range::*;
pub use signature::*;
pub use verifiable_encryption::*;

use crate::CredxResult;
use merlin::Transcript;
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
    fn verify(&self, challenge: Scalar) -> CredxResult<()>;
}

pub(crate) enum ProofVerifiers<'a, 'b, 'c> {
    Signature(SignatureVerifier<'a, 'b>),
    AccumulatorSetMembership(AccumulatorSetMembershipVerifier<'a, 'b>),
    Equality(EqualityVerifier<'a, 'b, 'c>),
    Commitment(CommitmentVerifier<'a, 'b>),
    VerifiableEncryption(VerifiableEncryptionVerifier<'a, 'b>),
    Range(RangeProofVerifier<'a, 'b, 'c>),
}

impl<'a, 'b, 'c> ProofVerifiers<'a, 'b, 'c> {
    /// Verify any additional proof material
    pub fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        match self {
            Self::Signature(s) => s.verify(challenge),
            Self::AccumulatorSetMembership(a) => a.verify(challenge),
            Self::Equality(e) => e.verify(challenge),
            Self::Commitment(c) => c.verify(challenge),
            Self::VerifiableEncryption(v) => v.verify(challenge),
            Self::Range(r) => r.verify(challenge),
        }
    }
}
