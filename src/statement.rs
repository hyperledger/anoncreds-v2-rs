mod commitment;
mod equality;
mod signature;
mod r#type;
mod verifiable_encryption;

pub use commitment::*;
pub use equality::*;
pub use r#type::*;
pub use signature::*;
pub use verifiable_encryption::*;

use serde::{Deserialize, Serialize};

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
}

impl Statements {
    /// Return the statement id
    pub fn id(&self) -> String {
        match self {
            Self::Signature(s) => s.id(),
        }
    }

    /// Return the statement type
    pub fn r#type(&self) -> StatementType {
        match self {
            Self::Signature(s) => s.r#type(),
        }
    }

    /// Return any references to other statements
    pub fn reference_ids(&self) -> Vec<String> {
        match self {
            Self::Signature(s) => s.reference_ids(),
        }
    }

    /// Add the data to the challenge hash
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        match self {
            Self::Signature(s) => s.add_challenge_contribution(transcript),
        }
    }

    /// Return the index associated with the claim label
    pub fn get_claim_index(&self, reference_id: &str) -> usize {
        match self {
            Self::Signature(s) => s.get_claim_index(reference_id),
        }
    }
}
