use super::SignatureProof;
use crate::presentation::{CommitmentProof, EqualityProof, MembershipProof, RangeProof, RevocationProof, VerifiableEncryptionProof};
use serde::{Deserialize, Serialize};

/// The types of presentation proofs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PresentationProofs {
    /// Signature proofs of knowledge
    Signature(Box<SignatureProof>),
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
    Membership(Box<MembershipProof>)
}

impl From<SignatureProof> for PresentationProofs {
    fn from(p: SignatureProof) -> Self {
        Self::Signature(Box::new(p))
    }
}

impl From<RevocationProof> for PresentationProofs {
    fn from(p: RevocationProof) -> Self {
        Self::Revocation(Box::new(p))
    }
}

impl From<EqualityProof> for PresentationProofs {
    fn from(p: EqualityProof) -> Self {
        Self::Equality(Box::new(p))
    }
}

impl From<CommitmentProof> for PresentationProofs {
    fn from(p: CommitmentProof) -> Self {
        Self::Commitment(Box::new(p))
    }
}

impl From<VerifiableEncryptionProof> for PresentationProofs {
    fn from(p: VerifiableEncryptionProof) -> Self {
        Self::VerifiableEncryption(Box::new(p))
    }
}

impl From<RangeProof> for PresentationProofs {
    fn from(p: RangeProof) -> Self {
        Self::Range(Box::new(p))
    }
}

impl From<MembershipProof> for PresentationProofs {
    fn from(value: MembershipProof) -> Self {
        Self::Membership(Box::new(value))
    }
}

impl PresentationProofs {
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
