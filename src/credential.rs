mod bundle;
mod membership;
mod offer;
mod schema;

pub use bundle::*;
pub use membership::*;
pub use offer::*;
pub use schema::*;

use super::claim::*;
use crate::knox::accumulator::vb20::MembershipWitness;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use serde::{Deserialize, Serialize};

/// A credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Credential<S: ShortGroupSignatureScheme> {
    /// The signed claims
    pub claims: Vec<ClaimData>,
    /// The signature
    pub signature: S::Signature,
    /// The revocation handle
    pub revocation_handle: MembershipCredential,
    /// The claim that is used for revocation
    pub revocation_index: usize,
}
