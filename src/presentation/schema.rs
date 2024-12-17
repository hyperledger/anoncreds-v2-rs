use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::random_string;
use crate::{statement::Statements, utils::*};
use indexmap::IndexMap;
use log::debug;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;

/// A description of the proofs to be created by the verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSchema<S: ShortGroupSignatureScheme + Serialize> {
    /// The unique presentation context id
    pub id: String,
    /// The statements associated with this presentation
    #[serde(
        serialize_with = "serialize_indexmap",
        deserialize_with = "deserialize_indexmap",
        bound(serialize = "Statements<S>: Serialize"),
        bound(deserialize = "Statements<S>: Deserialize<'de>")
    )]
    pub statements: IndexMap<String, Statements<S>>,
}

impl<S: ShortGroupSignatureScheme> PresentationSchema<S> {
    /// Create a new presentation schema with random id
    pub fn new(statements: &[Statements<S>]) -> Self {
        let id = random_string(16, rand::thread_rng());
        Self::new_with_id(statements, &id)
    }

    /// Create a new presentation schema with given id
    pub fn new_with_id(statements: &[Statements<S>], pres_schema_id: &str) -> Self {
        let id = pres_schema_id.into();
        let statements = statements.iter().map(|s| (s.id(), (*s).clone())).collect();
        let presentation_schema = Self { id, statements };
        debug!(
            "Presentation Schema: {}",
            serde_json::to_string_pretty(&presentation_schema).unwrap()
        );
        presentation_schema
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
