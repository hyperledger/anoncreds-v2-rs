use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::*;
use serde::{Deserialize, Serialize};

/// The types of credentials to pass in
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PresentationCredential<S: ShortGroupSignatureScheme> {
    /// A signature credential
    #[serde(bound(
        serialize = "Credential<S>: Serialize",
        deserialize = "Credential<S>: Deserialize<'de>"
    ))]
    Signature(Box<Credential<S>>),
    /// A membership check credential
    Membership(Box<MembershipCredential>),
}

impl<S: ShortGroupSignatureScheme> From<Credential<S>> for PresentationCredential<S> {
    fn from(value: Credential<S>) -> Self {
        Self::Signature(Box::new(value))
    }
}

impl<S: ShortGroupSignatureScheme> From<MembershipCredential> for PresentationCredential<S> {
    fn from(value: MembershipCredential) -> Self {
        Self::Membership(Box::new(value))
    }
}
