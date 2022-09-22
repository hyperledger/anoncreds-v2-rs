mod accumulator_set_membership;
mod commitment;
mod equality;
mod signature;
mod r#type;
mod verifiable_encryption;

pub use accumulator_set_membership::*;
pub use commitment::*;
pub use equality::*;
pub use r#type::*;
pub use signature::*;
pub use verifiable_encryption::*;

use serde::{Deserialize, Serialize};
use yeti::knox::bls12_381_plus::G1Projective;

/// Statement methods
pub trait Statement {
    /// Return this statement unique identifier
    fn id(&self) -> String;
    /// Get the statement type
    fn r#type(&self) -> StatementType;
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
    Signature(SignatureStatement),
    /// Equality statements
    Equality(EqualityStatement),
    /// Accumulator set membership statements
    AccumulatorSetMembership(AccumulatorSetMembershipStatement),
    /// Commitment statements
    Commitment(CommitmentStatement<G1Projective>),
    /// Verifiable Encryption statements
    VerifiableEncryption(VerifiableEncryptionStatement<G1Projective>),
}

impl Statements {
    /// Return the statement id
    pub fn id(&self) -> String {
        match self {
            Self::Signature(s) => s.id(),
            Self::Equality(e) => e.id(),
            Self::AccumulatorSetMembership(a) => a.id(),
            Self::Commitment(c) => c.id(),
            Self::VerifiableEncryption(v) => v.id(),
        }
    }

    /// Return the statement type
    pub fn r#type(&self) -> StatementType {
        match self {
            Self::Signature(s) => s.r#type(),
            Self::AccumulatorSetMembership(a) => a.r#type(),
            Self::Equality(e) => e.r#type(),
            Self::Commitment(c) => c.r#type(),
            Self::VerifiableEncryption(v) => v.r#type(),
        }
    }

    /// Return any references to other statements
    pub fn reference_ids(&self) -> Vec<String> {
        match self {
            Self::Signature(s) => s.reference_ids(),
            Self::Equality(e) => e.reference_ids(),
            Self::AccumulatorSetMembership(a) => a.reference_ids(),
            Self::Commitment(c) => c.reference_ids(),
            Self::VerifiableEncryption(v) => v.reference_ids(),
        }
    }

    /// Add the data to the challenge hash
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        match self {
            Self::Signature(s) => s.add_challenge_contribution(transcript),
            Self::Equality(e) => e.add_challenge_contribution(transcript),
            Self::AccumulatorSetMembership(a) => a.add_challenge_contribution(transcript),
            Self::Commitment(c) => c.add_challenge_contribution(transcript),
            Self::VerifiableEncryption(v) => v.add_challenge_contribution(transcript),
        }
    }

    /// Return the index associated with the claim label
    pub fn get_claim_index(&self, reference_id: &str) -> usize {
        match self {
            Self::Signature(s) => s.get_claim_index(reference_id),
            Self::Equality(e) => e.get_claim_index(reference_id),
            Self::AccumulatorSetMembership(a) => a.get_claim_index(reference_id),
            Self::Commitment(c) => c.get_claim_index(reference_id),
            Self::VerifiableEncryption(v) => v.get_claim_index(reference_id),
        }
    }
}
