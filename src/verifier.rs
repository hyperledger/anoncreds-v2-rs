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
    Signature(Box<SignatureVerifier<'a, 'b>>),
    AccumulatorSetMembership(Box<AccumulatorSetMembershipVerifier<'a, 'b>>),
    Equality(Box<EqualityVerifier<'a, 'b, 'c>>),
    Commitment(Box<CommitmentVerifier<'a, 'b>>),
    VerifiableEncryption(Box<VerifiableEncryptionVerifier<'a, 'b>>),
    Range(Box<RangeProofVerifier<'a, 'b, 'c>>),
}

impl<'a, 'b, 'c> From<SignatureVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(s: SignatureVerifier<'a, 'b>) -> Self {
        Self::Signature(Box::new(s))
    }
}

impl<'a, 'b, 'c> From<AccumulatorSetMembershipVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: AccumulatorSetMembershipVerifier<'a, 'b>) -> Self {
        Self::AccumulatorSetMembership(Box::new(a))
    }
}

impl<'a, 'b, 'c> From<EqualityVerifier<'a, 'b, 'c>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(e: EqualityVerifier<'a, 'b, 'c>) -> Self {
        Self::Equality(Box::new(e))
    }
}

impl<'a, 'b, 'c> From<CommitmentVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: CommitmentVerifier<'a, 'b>) -> Self {
        Self::Commitment(Box::new(a))
    }
}

impl<'a, 'b, 'c> From<VerifiableEncryptionVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: VerifiableEncryptionVerifier<'a, 'b>) -> Self {
        Self::VerifiableEncryption(Box::new(a))
    }
}

impl<'a, 'b, 'c> From<RangeProofVerifier<'a, 'b, 'c>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: RangeProofVerifier<'a, 'b, 'c>) -> Self {
        Self::Range(Box::new(a))
    }
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
