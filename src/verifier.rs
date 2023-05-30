mod commitment;
mod equality;
mod membership;
mod range;
mod revocation;
mod signature;
mod verifiable_encryption;

pub use commitment::*;
pub use equality::*;
pub use membership::*;
pub use range::*;
pub use revocation::*;
pub use signature::*;
pub use verifiable_encryption::*;

use crate::CredxResult;
use blsful::inner_types::Scalar;
use merlin::Transcript;

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
    Revocation(Box<RevocationVerifier<'a, 'b>>),
    Equality(Box<EqualityVerifier<'a, 'b, 'c>>),
    Commitment(Box<CommitmentVerifier<'a, 'b>>),
    VerifiableEncryption(Box<VerifiableEncryptionVerifier<'a, 'b>>),
    Range(Box<RangeProofVerifier<'a, 'b, 'c>>),
    Membership(Box<MembershipVerifier<'a, 'b>>),
}

impl<'a, 'b, 'c> From<SignatureVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(s: SignatureVerifier<'a, 'b>) -> Self {
        Self::Signature(Box::new(s))
    }
}

impl<'a, 'b, 'c> From<RevocationVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: RevocationVerifier<'a, 'b>) -> Self {
        Self::Revocation(Box::new(a))
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

impl<'a, 'b, 'c> From<MembershipVerifier<'a, 'b>> for ProofVerifiers<'a, 'b, 'c> {
    fn from(a: MembershipVerifier<'a, 'b>) -> Self {
        Self::Membership(Box::new(a))
    }
}

impl<'a, 'b, 'c> ProofVerifiers<'a, 'b, 'c> {
    /// Verify any additional proof material
    pub fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        match self {
            Self::Signature(s) => s.verify(challenge),
            Self::Revocation(a) => a.verify(challenge),
            Self::Equality(e) => e.verify(challenge),
            Self::Commitment(c) => c.verify(challenge),
            Self::VerifiableEncryption(v) => v.verify(challenge),
            Self::Range(r) => r.verify(challenge),
            Self::Membership(m) => m.verify(challenge),
        }
    }
}
