use super::SignatureProof;
use crate::presentation::{
    AccumulatorSetMembershipProof, CommitmentProof, EqualityProof, VerifiableEncryptionProof,
};
use serde::{Deserialize, Serialize};

/// The types of presentation proofs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PresentationProofs {
    /// Signature proofs of knowledge
    Signature(SignatureProof),
    /// Accumulator set membership proof
    AccumulatorSetMembership(AccumulatorSetMembershipProof),
    /// Equality proof
    Equality(EqualityProof),
    /// Commitment proof
    Commitment(CommitmentProof),
    /// Verifiable Encryption proof
    VerifiableEncryption(VerifiableEncryptionProof),
}

impl PresentationProofs {
    pub fn id(&self) -> &String {
        match self {
            Self::Signature(s) => &s.id,
            Self::AccumulatorSetMembership(a) => &a.id,
            Self::Equality(e) => &e.id,
            Self::Commitment(c) => &c.id,
            Self::VerifiableEncryption(v) => &v.id,
        }
    }
}
