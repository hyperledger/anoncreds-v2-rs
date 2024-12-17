use crate::knox::accumulator::vb20::Accumulator;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::{credential::*, issuer::*};
use serde::{Deserialize, Serialize};

/// A credential and the issuer's information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialBundle<S: ShortGroupSignatureScheme> {
    /// The issuer information that gave this credential
    #[serde(bound(
        serialize = "IssuerPublic<S>: Serialize",
        deserialize = "IssuerPublic<S>: Deserialize<'de>"
    ))]
    pub issuer: IssuerPublic<S>,
    /// The signed credential
    #[serde(bound(
        serialize = "Credential<S>: Serialize",
        deserialize = "Credential<S>: Deserialize<'de>"
    ))]
    pub credential: Credential<S>,
}

impl<S: ShortGroupSignatureScheme> CredentialBundle<S> {
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
