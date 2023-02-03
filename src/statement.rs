mod revocation;
mod commitment;
mod equality;
mod range;
mod signature;
mod verifiable_encryption;

pub use revocation::*;
pub use commitment::*;
pub use equality::*;
pub use range::*;
pub use signature::*;
pub use verifiable_encryption::*;

use serde::{Deserialize, Serialize};
use yeti::knox::bls12_381_plus::G1Projective;

/// Statement methods
pub trait Statement {
    /// Return this statement unique identifier
    fn id(&self) -> String;
    /// Any statements that this statement references
    fn reference_ids(&self) -> Vec<String>;
    /// Add the public statement data to the transcript
    fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript);
    /// Get the claim index to which this statement refers
    fn get_claim_index(&self, reference_id: &str) -> usize;
}

/// The various statement types
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Statements {
    /// Signature statements
    Signature(Box<SignatureStatement>),
    /// Equality statements
    Equality(Box<EqualityStatement>),
    /// Accumulator set membership statements
    Revocation(Box<RevocationStatement>),
    /// Commitment statements
    Commitment(Box<CommitmentStatement<G1Projective>>),
    /// Verifiable Encryption statements
    VerifiableEncryption(Box<VerifiableEncryptionStatement<G1Projective>>),
    /// Range statements
    Range(Box<RangeStatement>),
}

impl From<SignatureStatement> for Statements {
    fn from(s: SignatureStatement) -> Self {
        Self::Signature(Box::new(s))
    }
}

impl From<EqualityStatement> for Statements {
    fn from(e: EqualityStatement) -> Self {
        Self::Equality(Box::new(e))
    }
}

impl From<RevocationStatement> for Statements {
    fn from(a: RevocationStatement) -> Self {
        Self::Revocation(Box::new(a))
    }
}

impl From<CommitmentStatement<G1Projective>> for Statements {
    fn from(c: CommitmentStatement<G1Projective>) -> Self {
        Self::Commitment(Box::new(c))
    }
}

impl From<VerifiableEncryptionStatement<G1Projective>> for Statements {
    fn from(c: VerifiableEncryptionStatement<G1Projective>) -> Self {
        Self::VerifiableEncryption(Box::new(c))
    }
}

impl From<RangeStatement> for Statements {
    fn from(c: RangeStatement) -> Self {
        Self::Range(Box::new(c))
    }
}

impl Statements {
    /// Return the statement id
    pub fn id(&self) -> String {
        match self {
            Self::Signature(s) => s.id(),
            Self::Equality(e) => e.id(),
            Self::Revocation(a) => a.id(),
            Self::Commitment(c) => c.id(),
            Self::VerifiableEncryption(v) => v.id(),
            Self::Range(r) => r.id(),
        }
    }

    /// Return any references to other statements
    pub fn reference_ids(&self) -> Vec<String> {
        match self {
            Self::Signature(s) => s.reference_ids(),
            Self::Equality(e) => e.reference_ids(),
            Self::Revocation(a) => a.reference_ids(),
            Self::Commitment(c) => c.reference_ids(),
            Self::VerifiableEncryption(v) => v.reference_ids(),
            Self::Range(r) => r.reference_ids(),
        }
    }

    /// Add the data to the challenge hash
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        match self {
            Self::Signature(s) => s.add_challenge_contribution(transcript),
            Self::Equality(e) => e.add_challenge_contribution(transcript),
            Self::Revocation(a) => a.add_challenge_contribution(transcript),
            Self::Commitment(c) => c.add_challenge_contribution(transcript),
            Self::VerifiableEncryption(v) => v.add_challenge_contribution(transcript),
            Self::Range(r) => r.add_challenge_contribution(transcript),
        }
    }

    /// Return the index associated with the claim label
    pub fn get_claim_index(&self, reference_id: &str) -> usize {
        match self {
            Self::Signature(s) => s.get_claim_index(reference_id),
            Self::Equality(e) => e.get_claim_index(reference_id),
            Self::Revocation(a) => a.get_claim_index(reference_id),
            Self::Commitment(c) => c.get_claim_index(reference_id),
            Self::VerifiableEncryption(v) => v.get_claim_index(reference_id),
            Self::Range(r) => r.get_claim_index(reference_id),
        }
    }
}
