use crate::claim::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A credential schema
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialSchema {
    /// The unique identifier for this schema
    pub id: String,
    /// Friendly label
    pub label: String,
    /// A longer description
    pub description: String,
    /// The list of claims allowed to be blindly signed
    pub blind_claims: Vec<String>,
    /// The claim labels to indices
    pub claim_indices: BTreeMap<String, usize>,
    /// The claims that can be signed
    pub claims: Vec<ClaimSchema>,
}

/// A claim schema
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimSchema {
    /// The claim type
    pub claim_type: ClaimType,
    /// The claim label
    pub label: String,
}
