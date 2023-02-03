use crate::prelude::*;
use serde::{Deserialize, Serialize};

/// The types of credentials to pass in
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PresentationCredential {
    /// A signature credential
    Signature(Box<Credential>),
    /// A membership check credential
    Membership(Box<MembershipCredential>),
}

impl From<Credential> for PresentationCredential {
    fn from(value: Credential) -> Self {
        Self::Signature(Box::new(value))
    }
}

impl From<MembershipCredential> for PresentationCredential {
    fn from(value: MembershipCredential) -> Self {
        Self::Membership(Box::new(value))
    }
}
