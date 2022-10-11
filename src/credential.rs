mod bundle;
mod offer;
mod schema;

pub use bundle::*;
pub use offer::*;
pub use schema::*;

use super::claim::*;
use super::error::Error;
use super::CredxResult;
use crate::utils::g1_from_hex_str;
use serde::{Deserialize, Serialize};
use yeti::knox::{accumulator::vb20::MembershipWitness, ps::Signature};

/// A credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Credential {
    /// The signed claims
    pub claims: Vec<ClaimData>,
    /// The signature
    pub signature: Signature,
    /// The revocation handle
    pub revocation_handle: MembershipWitness,
    /// The claim that is used for revocation
    pub revocation_index: usize,
}

impl From<&Credential> for CredentialText {
    fn from(credential: &Credential) -> Self {
        Self {
            claims: credential.claims.iter().map(|c| c.to_text()).collect(),
            signature: hex::encode(&credential.signature.to_bytes()),
            revocation_handle: hex::encode(&credential.revocation_handle.to_bytes()),
            revocation_index: credential.revocation_index,
        }
    }
}

impl From<Credential> for CredentialText {
    fn from(credential: Credential) -> Self {
        Self::from(&credential)
    }
}

/// A credential in a text friendly format
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialText {
    /// The signed claims
    pub claims: Vec<String>,
    /// The signature
    pub signature: String,
    /// The revocation handle
    pub revocation_handle: String,
    /// The claim that is used for revocation
    pub revocation_index: usize,
}

impl TryFrom<&CredentialText> for Credential {
    type Error = Error;

    fn try_from(credential: &CredentialText) -> CredxResult<Self> {
        let mut claims = Vec::new();
        for s in &credential.claims {
            claims.push(ClaimData::from_text(s)?);
        }

        let sig_bytes = hex::decode(&credential.signature).map_err(|_| {
            Error::InvalidClaimData("unable to decode credential signature from hex string")
        })?;
        let sig_buf = <[u8; 128]>::try_from(sig_bytes.as_slice())
            .map_err(|_| Error::InvalidClaimData("unable to read credential signature bytes"))?;
        let sig = Signature::from_bytes(&sig_buf);
        if sig.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidClaimData(
                "unable to deserialize credential signature",
            ));
        }
        Ok(Self {
            claims,
            signature: sig.unwrap(),
            revocation_handle: MembershipWitness(g1_from_hex_str(
                &credential.revocation_handle,
                Error::InvalidClaimData("unable to deserialize revocation handle"),
            )?),
            revocation_index: credential.revocation_index,
        })
    }
}

impl TryFrom<CredentialText> for Credential {
    type Error = Error;

    fn try_from(value: CredentialText) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}
