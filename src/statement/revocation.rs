use crate::statement::Statement;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;
use crate::knox::accumulator::vb20;

/// Accumulator set membership statement for revocation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationStatement {
    /// The statement id
    pub id: String,
    /// The other statement id
    pub reference_id: String,
    /// The accumulator value
    pub accumulator: vb20::Accumulator,
    /// The accumulator verification key
    pub verification_key: vb20::PublicKey,
    /// The claim index in the other statement
    pub claim: usize,
}

impl Statement for RevocationStatement {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn reference_ids(&self) -> Vec<String> {
        vec![self.reference_id.clone()]
    }

    fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"statement type", b"vb20 set membership revocation");
        transcript.append_message(b"statement id", self.id.as_bytes());
        transcript.append_message(b"reference statement id", self.reference_id.as_bytes());
        transcript.append_message(b"claim index", &Uint::from(self.claim).to_vec());
        transcript.append_message(
            b"verification key",
            self.verification_key.to_bytes().as_ref(),
        );
        transcript.append_message(b"accumulator", self.accumulator.to_bytes().as_ref());
    }

    fn get_claim_index(&self, _reference_id: &str) -> usize {
        self.claim
    }
}
