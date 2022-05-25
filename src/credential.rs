mod schema;

pub use schema::*;

use super::claim::*;
use crate::issuer::IssuerPublic;
use serde::{Deserialize, Serialize};
use yeti::knox::accumulator::vb20;
use yeti::knox::ps;

/// A credential and the issuer's information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialBundle {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublic,
    /// The signed credential
    pub credential: Credential,
}

/// A credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Credential {
    /// The signed claims
    pub claims: Vec<ClaimData>,
    /// The signature
    pub signature: ps::Signature,
    /// The revocation handle
    pub revocation_handle: vb20::MembershipWitness,
    /// The claim that is used for revocation
    pub revocation_index: usize,
}

/// A credential offer from the issuer to the holder
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOffer {
    /// The claims to be signed
    pub claims: Vec<ClaimData>,
    /// The issuer's id
    pub issuer: IssuerPublic,
    /// The credential offer id
    pub offer_id: [u8; 16],
}
