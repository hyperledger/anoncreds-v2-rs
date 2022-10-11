use super::*;
use crate::issuer::IssuerPublic;

use serde::{Deserialize, Serialize};

/// A blind credential bundle returned by the issuer from a blind signing operation
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredentialBundle {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublic,
    /// The blind credential
    pub credential: BlindCredential,
}
