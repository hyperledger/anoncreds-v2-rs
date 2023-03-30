use crate::knox::accumulator::vb20::Accumulator;
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
