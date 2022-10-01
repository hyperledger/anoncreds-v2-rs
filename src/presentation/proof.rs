use super::SignatureProof;
use crate::presentation::{
    AccumulatorSetMembershipProof, CommitmentProof, EqualityProof, RangeProof,
    VerifiableEncryptionProof,
};
use serde::{Deserialize, Serialize};

/// The types of presentation proofs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PresentationProofs {
    /// Signature proofs of knowledge
    Signature(Box<SignatureProof>),
    /// Accumulator set membership proof
    AccumulatorSetMembership(Box<AccumulatorSetMembershipProof>),
    /// Equality proof
    Equality(Box<EqualityProof>),
    /// Commitment proof
    Commitment(Box<CommitmentProof>),
    /// Verifiable Encryption proof
    VerifiableEncryption(Box<VerifiableEncryptionProof>),
    /// Range proof
    Range(Box<RangeProof>),
}

impl From<SignatureProof> for PresentationProofs {
    fn from(p: SignatureProof) -> Self {
        Self::Signature(Box::new(p))
    }
}

impl From<AccumulatorSetMembershipProof> for PresentationProofs {
    fn from(p: AccumulatorSetMembershipProof) -> Self {
        Self::AccumulatorSetMembership(Box::new(p))
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

impl PresentationProofs {
    /// Get the underlying statement identifier
    pub fn id(&self) -> &String {
        match self {
            Self::Signature(s) => &s.id,
            Self::AccumulatorSetMembership(a) => &a.id,
            Self::Equality(e) => &e.id,
            Self::Commitment(c) => &c.id,
            Self::VerifiableEncryption(v) => &v.id,
            Self::Range(r) => &r.id,
        }
    }
}
