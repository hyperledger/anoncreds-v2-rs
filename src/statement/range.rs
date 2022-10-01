use crate::statement::*;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;

/// A Range proof statement
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeStatement {
    /// The statement id
    pub id: String,
    /// The reference id to the commitment statement
    pub reference_id: String,
    /// The reference id to the signature statement
    pub signature_id: String,
    /// The claim index in the other statement
    pub claim: usize,
    /// The lower bound to test against if set
    pub lower: Option<isize>,
    /// The upper bound to test against if set
    pub upper: Option<isize>,
}

impl Statement for RangeStatement {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn r#type(&self) -> StatementType {
        StatementType::RangeProofBulletproof
    }

    fn reference_ids(&self) -> Vec<String> {
        vec![self.reference_id.clone()]
    }

    fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"statement type", b"range proof");
        transcript.append_message(b"statement id", self.id.as_bytes());
        transcript.append_message(
            b"reference commitment statement id",
            self.reference_id.as_bytes(),
        );
        transcript.append_message(
            b"reference signature statement id",
            self.signature_id.as_bytes(),
        );
        transcript.append_message(b"claim index", &Uint::from(self.claim).to_vec());
        transcript.append_message(b"lower version", &[self.lower.map_or(0u8, |_| 1u8)]);
        if let Some(lower) = self.lower.as_ref() {
            transcript.append_message(b"lower", &Uint::from(*lower).to_vec());
        }
        transcript.append_message(b"upper version", &[self.upper.map_or(0u8, |_| 1u8)]);
        if let Some(upper) = self.upper.as_ref() {
            transcript.append_message(b"upper", &Uint::from(*upper).to_vec());
        }
    }

    fn get_claim_index(&self, _reference_id: &str) -> usize {
        self.claim
    }
}
