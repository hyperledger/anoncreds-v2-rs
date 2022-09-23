use crate::random_string;
use crate::statement::Statements;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uint_zigzag::Uint;

/// A description of the proofs to be created by the verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSchema {
    /// The unique presentation context id
    pub id: String,
    /// The statements associated with this presentation
    pub statements: BTreeMap<String, Statements>,
}

impl PresentationSchema {
    /// Create a new presentation schema
    pub fn new(statements: &[Statements]) -> Self {
        let id = random_string(16, rand::thread_rng());
        let statements = statements.iter().map(|s| (s.id(), s.clone())).collect();
        Self { id, statements }
    }

    /// Add challenge contribution
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(b"presentation schema id", self.id.as_bytes());
        transcript.append_message(
            b"presentation statement length",
            &Uint::from(self.statements.len()).to_vec(),
        );
        for (id, statement) in &self.statements {
            transcript.append_message(b"presentation statement id", id.as_bytes());
            statement.add_challenge_contribution(transcript);
        }
    }
}
