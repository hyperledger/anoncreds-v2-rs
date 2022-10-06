mod bundle;
mod offer;
mod schema;

pub use bundle::*;
pub use offer::*;
pub use schema::*;

use super::claim::*;
use super::error::Error;
use super::CredxResult;
use crate::utils::{g1_from_hex_str, scalar_from_hex_str};
use serde::{Deserialize, Serialize};
use yeti::knox::{accumulator::vb20::MembershipWitness, ps::Signature};

/// Hashed utf8 string
pub const HASHED_UTF8: &str = "ut8:";
/// Hashed binary string
pub const HASHED_HEX: &str = "hex:";
/// Scalar
pub const SCALAR: &str = "scl:";
/// Number
pub const NUMBER: &str = "num:";
/// Revocation id
pub const REVOCATION: &str = "rev:";
/// Enumeration
pub const ENUMERATION: &str = "enm:";

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
        let mut claims = Vec::new();
        for c in &credential.claims {
            let mut s = String::new();
            match c {
                ClaimData::Hashed(HashedClaim {
                    value,
                    print_friendly,
                }) => {
                    if *print_friendly {
                        s.push_str(HASHED_UTF8);
                        s.push_str(&String::from_utf8(value.clone()).unwrap());
                    } else {
                        s.push_str(HASHED_HEX);
                        s.push_str(&hex::encode(value));
                    }
                }
                ClaimData::Number(NumberClaim { value }) => {
                    s.push_str(NUMBER);
                    s.push_str(&value.to_string());
                }
                ClaimData::Scalar(ScalarClaim { value }) => {
                    s.push_str(SCALAR);
                    s.push_str(&hex::encode(&value.to_bytes()));
                }
                ClaimData::Revocation(RevocationClaim { value }) => {
                    s.push_str(REVOCATION);
                    s.push_str(value);
                }
                ClaimData::Enumeration(e) => {
                    s.push_str(ENUMERATION);
                    let data = serde_bare::to_vec(&e).unwrap();
                    s.push_str(&hex::encode(data.as_slice()))
                }
            }
            claims.push(s);
        }
        Self {
            claims,
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
            match &s[0..4] {
                HASHED_HEX => {
                    let value = hex::decode(&s[4..]).map_err(|_| Error::InvalidClaimData)?;
                    claims.push(ClaimData::Hashed(HashedClaim {
                        value,
                        print_friendly: false,
                    }));
                }
                HASHED_UTF8 => {
                    let value = s[4..].to_string();
                    claims.push(ClaimData::Hashed(HashedClaim {
                        value: value.into_bytes(),
                        print_friendly: true,
                    }));
                }
                NUMBER => {
                    let value = s[4..]
                        .parse::<isize>()
                        .map_err(|_| Error::InvalidClaimData)?;
                    claims.push(ClaimData::Number(NumberClaim { value }));
                }
                SCALAR => {
                    let value = scalar_from_hex_str(&s[4..], Error::InvalidClaimData)?;
                    claims.push(ClaimData::Scalar(ScalarClaim { value }));
                }
                REVOCATION => {
                    let value = s[4..].to_string();
                    claims.push(ClaimData::Revocation(RevocationClaim { value }));
                }
                ENUMERATION => {
                    let value = hex::decode(&s[4..]).map_err(|_| Error::InvalidClaimData)?;
                    let e = serde_bare::from_slice::<EnumerationClaim>(value.as_slice())
                        .map_err(|_| Error::InvalidClaimData)?;
                    claims.push(ClaimData::Enumeration(e));
                }
                _ => {
                    return Err(Error::InvalidClaimData);
                }
            }
        }

        let sig_bytes = hex::decode(&credential.signature).map_err(|_| Error::InvalidClaimData)?;
        let sig_buf =
            <[u8; 128]>::try_from(sig_bytes.as_slice()).map_err(|_| Error::InvalidClaimData)?;
        let sig = Signature::from_bytes(&sig_buf);
        if sig.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidClaimData);
        }
        Ok(Self {
            claims,
            signature: sig.unwrap(),
            revocation_handle: MembershipWitness(g1_from_hex_str(
                &credential.revocation_handle,
                Error::InvalidClaimData,
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
