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
    /// Can the claim be represented as printable characters
    pub print_friendly: bool,
    /// The claim data validators
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validators: Vec<ClaimValidator>,
}

impl ClaimSchema {
    /// [`Some(true)`] if the claim is the right type and meets the validator requirements
    /// [`Some(false)`] if the claim is the right type but doesn't meet the requirements
    /// [`None`] if the claim is the incorrect type
    pub fn is_valid(&self, claim: &ClaimData) -> Option<bool> {
        let mut result = true;
        for v in &self.validators {
            match v.is_valid(claim) {
                Some(b) => result &= b,
                None => return None,
            }
        }
        Some(result)
    }
}
