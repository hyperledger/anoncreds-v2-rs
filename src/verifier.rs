mod accumulator_set_membership;
mod commitment;
mod equality;
mod signature;
mod verifiable_encryption;

pub use accumulator_set_membership::*;
pub use commitment::*;
pub use equality::*;
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
    fn verify(&self, challenge: Scalar, transcript: &mut Transcript) -> CredxResult<()>;
}

pub(crate) enum ProofVerifiers<'a, 'b, 'c> {
    Signature(SignatureVerifier<'a, 'b>),
    AccumulatorSetMembership(AccumulatorSetMembershipVerifier<'a, 'b>),
    Equality(EqualityVerifier<'a, 'b, 'c>),
    Commitment(CommitmentVerifier<'a, 'b>),
    VerifiableEncryption(VerifiableEncryptionVerifier<'a, 'b>),
}

impl<'a, 'b, 'c> ProofVerifiers<'a, 'b, 'c> {
    /// Verify any additional proof material
    pub fn verify(&self, challenge: Scalar, transcript: &mut Transcript) -> CredxResult<()> {
        match self {
            Self::Signature(s) => s.verify(challenge, transcript),
            Self::AccumulatorSetMembership(a) => a.verify(challenge, transcript),
            Self::Equality(e) => e.verify(challenge, transcript),
            Self::Commitment(c) => c.verify(challenge, transcript),
            Self::VerifiableEncryption(v) => v.verify(challenge, transcript),
        }
    }
}
