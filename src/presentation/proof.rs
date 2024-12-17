use super::SignatureProof;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::presentation::{
    CommitmentProof, EqualityProof, MembershipProof, RangeProof, RevocationProof,
    VerifiableEncryptionProof,
};
use serde::{Deserialize, Serialize};

/// The types of presentation proofs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PresentationProofs<S: ShortGroupSignatureScheme> {
    /// Signature proofs of knowledge
    #[serde(bound(
        serialize = "SignatureProof<S>: Serialize",
        deserialize = "SignatureProof<S>: Deserialize<'de>"
    ))]
    Signature(Box<SignatureProof<S>>),
    /// Accumulator set membership proof
    Revocation(Box<RevocationProof>),
    /// Equality proof
    Equality(Box<EqualityProof>),
    /// Commitment proof
    Commitment(Box<CommitmentProof>),
    /// Verifiable Encryption proof
    VerifiableEncryption(Box<VerifiableEncryptionProof>),
    /// Range proof
    Range(Box<RangeProof>),
    /// Membership Proofs
    Membership(Box<MembershipProof>),
}

impl<S: ShortGroupSignatureScheme> From<SignatureProof<S>> for PresentationProofs<S> {
    fn from(p: SignatureProof<S>) -> Self {
        Self::Signature(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<RevocationProof> for PresentationProofs<S> {
    fn from(p: RevocationProof) -> Self {
        Self::Revocation(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<EqualityProof> for PresentationProofs<S> {
    fn from(p: EqualityProof) -> Self {
        Self::Equality(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<CommitmentProof> for PresentationProofs<S> {
    fn from(p: CommitmentProof) -> Self {
        Self::Commitment(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<VerifiableEncryptionProof> for PresentationProofs<S> {
    fn from(p: VerifiableEncryptionProof) -> Self {
        Self::VerifiableEncryption(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<RangeProof> for PresentationProofs<S> {
    fn from(p: RangeProof) -> Self {
        Self::Range(Box::new(p))
    }
}

impl<S: ShortGroupSignatureScheme> From<MembershipProof> for PresentationProofs<S> {
    fn from(value: MembershipProof) -> Self {
        Self::Membership(Box::new(value))
    }
}

impl<S: ShortGroupSignatureScheme> PresentationProofs<S> {
    /// Get the underlying statement identifier
    pub fn id(&self) -> &String {
        match self {
            Self::Signature(s) => &s.id,
            Self::Revocation(a) => &a.id,
            Self::Equality(e) => &e.id,
            Self::Commitment(c) => &c.id,
            Self::VerifiableEncryption(v) => &v.id,
            Self::Range(r) => &r.id,
            Self::Membership(m) => &m.id,
        }
    }
}
