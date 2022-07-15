use crate::statement::Statements;
use crate::uint::Uint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A description of the proofs to be created by the verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSchema {
    /// The unique presentation context id
    pub id: String,
    /// The statements associated with this presentation
    pub statements: BTreeMap<String, Statements>,
}

impl PresentationSchema {
    /// Add challenge contribution
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(b"presentation schema id", self.id.as_bytes());
        transcript.append_message(
            b"presentation statement length",
            &Uint::from(self.statements.len()).bytes(),
        );
        for (id, statement) in &self.statements {
            transcript.append_message(b"presentation statement id", id.as_bytes());
            statement.add_challenge_contribution(transcript);
        }
    }
}
