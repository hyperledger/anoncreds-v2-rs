use crate::{claim::ClaimData, issuer::IssuerPublic};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

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

impl CredentialOffer {
    /// Create a new offer
    pub fn new(claims: &[ClaimData], issuer: IssuerPublic) -> Self {
        let mut offer_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut offer_id);
        Self {
            claims: claims.to_vec(),
            issuer,
            offer_id,
        }
    }
}
