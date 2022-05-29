use serde::{Deserialize, Serialize};

/// A description of the proofs to be created by the verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSchema {
    /// The unique presentation context id
    pub id: [u8; 16],
}
