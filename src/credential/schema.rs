use yeti::yeti_core::*;
use crate::claim::*;

/// A credential schema
#[derive(Clone, Debug)]
pub struct CredentialSchema {
    /// The unique identifier for this schema
    pub id: [u8; 16],
    /// The index of claims allowed to be blindly signed
    pub blind_claims: Vec<usize>,
    /// The claim types allowed for this schema
    pub claims: Vec<ClaimType>
}
