use crate::{credential::*, issuer::*};
use serde::{Deserialize, Serialize};
use yeti::knox::accumulator::vb20::Accumulator;

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

impl CredentialBundle {
    /// Update the bundles revocation handle
    pub fn update_revocation_handle(
        &mut self,
        revocation_handle: MembershipWitness,
        revocation_registry: Accumulator,
    ) {
        self.credential.revocation_handle = revocation_handle;
        self.issuer.revocation_registry = revocation_registry;
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
