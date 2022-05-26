use crate::{credential::Credential, issuer::IssuerPublic};
use serde::{Deserialize, Serialize};

/// A credential and the issuer's information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialBundle {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublic,
    /// The signed credential
    pub credential: Credential,
}
