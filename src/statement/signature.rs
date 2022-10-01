use super::Statement;
use crate::issuer::IssuerPublic;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uint_zigzag::Uint;

/// A PS signature statement
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureStatement {
    /// The labels for the disclosed claims
    pub disclosed: BTreeSet<String>,
    /// The statement id
    pub id: String,
    /// The issuer information
    pub issuer: IssuerPublic,
}

impl Statement for SignatureStatement {
    /// Return this statement unique identifier
    fn id(&self) -> String {
        self.id.clone()
    }

    /// Any statements that this statement references
    fn reference_ids(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"statement type", b"ps signature");
        transcript.append_message(b"statement id", self.id.as_bytes());
        transcript.append_message(
            b"disclosed message length",
            &Uint::from(self.disclosed.len()).to_vec(),
        );
        for (index, d) in self.disclosed.iter().enumerate() {
            transcript.append_message(
                b"disclosed message label index",
                &Uint::from(index).to_vec(),
            );
            transcript.append_message(b"disclosed message label", d.as_bytes());
        }
        self.issuer.add_challenge_contribution(transcript);
    }

    fn get_claim_index(&self, _reference_id: &str) -> usize {
        unimplemented!()
    }
}
