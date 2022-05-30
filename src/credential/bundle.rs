use crate::{credential::*, issuer::*};
use serde::{Deserialize, Serialize};

/// A credential and the issuer's information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialBundle {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublic,
    /// The signed credential
    pub credential: Credential,
}

impl From<&CredentialBundle> for CredentialBundleText {
    fn from(cb: &CredentialBundle) -> Self {
        Self {
            issuer: IssuerPublicText::from(&cb.issuer),
            credential: CredentialText::from(&cb.credential),
        }
    }
}

/// A credential and the issuer's information in text friendly form
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialBundleText {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublicText,
    /// The signed credential
    pub credential: CredentialText,
}

impl TryFrom<&CredentialBundleText> for CredentialBundle {
    type Error = Error;

    fn try_from(value: &CredentialBundleText) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: IssuerPublic::try_from(&value.issuer)?,
            credential: Credential::try_from(&value.credential)?,
        })
    }
}
