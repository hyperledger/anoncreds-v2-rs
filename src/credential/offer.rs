use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::{claim::ClaimData, issuer::IssuerPublic};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

/// A credential offer from the issuer to the holder
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOffer<S: ShortGroupSignatureScheme> {
    /// The claims to be signed
    pub claims: Vec<ClaimData>,
    /// The issuer's id
    #[serde(bound(
        serialize = "IssuerPublic<S>: Serialize",
        deserialize = "IssuerPublic<S>: Deserialize<'de>"
    ))]
    pub issuer: IssuerPublic<S>,
    /// The credential offer id
    pub offer_id: [u8; 16],
}

impl<S: ShortGroupSignatureScheme> CredentialOffer<S> {
    /// Create a new offer
    pub fn new(claims: &[ClaimData], issuer: IssuerPublic<S>) -> Self {
        let mut offer_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut offer_id);
        Self {
            claims: claims.to_vec(),
            issuer,
            offer_id,
        }
    }
}
