mod bundle;
mod membership;
mod offer;
mod schema;

pub use bundle::*;
pub use membership::*;
pub use offer::*;
pub use schema::*;

use super::claim::*;
use serde::{Deserialize, Serialize};
use crate::knox::{accumulator::vb20::MembershipWitness, ps::Signature};

/// A credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Credential {
    /// The signed claims
    pub claims: Vec<ClaimData>,
    /// The signature
    pub signature: Signature,
    /// The revocation handle
    pub revocation_handle: MembershipCredential,
    /// The claim that is used for revocation
    pub revocation_index: usize,
}
