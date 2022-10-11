use super::*;
use crate::{error::Error, utils::scalar_from_hex_str, CredxResult};
use serde::{Deserialize, Serialize};

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

/// The type of claim data that can be signed
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, Hash)]
pub enum ClaimData {
    /// Data is hashed before signing
    Hashed(HashedClaim),
    /// Data is a number
    Number(NumberClaim),
    /// Data is a scalar
    Scalar(ScalarClaim),
    /// Data is a fixed string
    Revocation(RevocationClaim),
    /// Data is from a list of unique values
    Enumeration(EnumerationClaim),
}

impl From<HashedClaim> for ClaimData {
    fn from(c: HashedClaim) -> Self {
        Self::Hashed(c)
    }
}

impl From<NumberClaim> for ClaimData {
    fn from(c: NumberClaim) -> Self {
        Self::Number(c)
    }
}

impl From<ScalarClaim> for ClaimData {
    fn from(c: ScalarClaim) -> Self {
        Self::Scalar(c)
    }
}

impl From<RevocationClaim> for ClaimData {
    fn from(c: RevocationClaim) -> Self {
        Self::Revocation(c)
    }
}

impl From<EnumerationClaim> for ClaimData {
    fn from(c: EnumerationClaim) -> Self {
        Self::Enumeration(c)
    }
}

impl ClaimData {
    /// Get the scalar to be signed
    pub fn to_scalar(&self) -> Scalar {
        match self {
            Self::Hashed(h) => h.to_scalar(),
            Self::Number(n) => n.to_scalar(),
            Self::Scalar(s) => s.to_scalar(),
            Self::Revocation(r) => r.to_scalar(),
            Self::Enumeration(e) => e.to_scalar(),
        }
    }

    /// Convert this claim to a byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Hashed(h) => h.value.clone(),
            Self::Number(n) => n.value.to_le_bytes().to_vec(),
            Self::Scalar(s) => s.value.to_bytes().to_vec(),
            Self::Revocation(r) => r.value.as_bytes().to_vec(),
            Self::Enumeration(e) => vec![e.value],
        }
    }

    /// Convert the byte sequence to a claim
    pub fn from_bytes(claim_type: ClaimType, data: &[u8]) -> CredxResult<Self> {
        match claim_type {
            ClaimType::Hashed => Ok(Self::Hashed(HashedClaim {
                value: data.to_vec(),
                print_friendly: false,
            })),
            ClaimType::Number => {
                let n = match data.len() {
                    1 => NumberClaim::from(data[0]),
                    2 => {
                        let i = u16::from_le_bytes(<[u8; 2]>::try_from(data).unwrap());
                        NumberClaim::from(i)
                    }
                    4 => {
                        let i = u32::from_le_bytes(<[u8; 4]>::try_from(data).unwrap());
                        NumberClaim::from(i)
                    }
                    8 => {
                        let i = u64::from_le_bytes(<[u8; 8]>::try_from(data).unwrap());
                        NumberClaim::from(i)
                    }
                    _ => {
                        return Err(Error::InvalidClaimData(
                            "number claim size must be 1, 2, 4, 8, found unknown",
                        ))
                    }
                };
                Ok(Self::Number(n))
            }
            ClaimType::Scalar => {
                let s = Scalar::from_bytes(&<[u8; 32]>::try_from(data).unwrap());
                if s.is_none().unwrap_u8() == 1 {
                    return Err(Error::InvalidClaimData(
                        "scalar claim could not be deserialized",
                    ));
                }
                Ok(Self::Scalar(ScalarClaim { value: s.unwrap() }))
            }
            ClaimType::Revocation => {
                if data.len() != 16 {
                    return Err(Error::InvalidClaimData(
                        "revocation claim could not be deserialized",
                    ));
                }
                let s = String::from_utf8(data.to_vec()).map_err(|_| {
                    Error::InvalidClaimData("cannot convert revocation claim to UTF8")
                })?;
                Ok(Self::Revocation(RevocationClaim { value: s }))
            }
            _ => Err(Error::InvalidClaimData("unknown claim type")),
        }
    }

    /// [`true`] if the claim is the right type
    /// [`false`] if the claim is the incorrect type
    pub fn is_type(&self, claim_type: ClaimType) -> bool {
        match (self, claim_type) {
            (Self::Hashed(_), ClaimType::Hashed)
            | (Self::Number(_), ClaimType::Number)
            | (Self::Scalar(_), ClaimType::Scalar)
            | (Self::Revocation(_), ClaimType::Revocation)
            | (Self::Enumeration(_), ClaimType::Enumeration) => true,
            (_, _) => false,
        }
    }

    /// Convert to a text friendly format
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        match self {
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
        s
    }

    /// Convert text to [`ClaimData`]
    pub fn from_text(s: &str) -> CredxResult<Self> {
        match &s[0..4] {
            HASHED_HEX => {
                let value = hex::decode(&s[4..]).map_err(|_| {
                    Error::InvalidClaimData("unable to decode hashed claim hex string")
                })?;
                Ok(ClaimData::Hashed(HashedClaim {
                    value,
                    print_friendly: false,
                }))
            }
            HASHED_UTF8 => {
                let value = s[4..].to_string();
                Ok(ClaimData::Hashed(HashedClaim {
                    value: value.into_bytes(),
                    print_friendly: true,
                }))
            }
            NUMBER => {
                let value = s[4..]
                    .parse::<isize>()
                    .map_err(|_| Error::InvalidClaimData("unable to deserialize number claim"))?;
                Ok(ClaimData::Number(NumberClaim { value }))
            }
            SCALAR => {
                let value = scalar_from_hex_str(
                    &s[4..],
                    Error::InvalidClaimData("unable to deserialize scalar claim"),
                )?;
                Ok(ClaimData::Scalar(ScalarClaim { value }))
            }
            REVOCATION => {
                let value = s[4..].to_string();
                Ok(ClaimData::Revocation(RevocationClaim { value }))
            }
            ENUMERATION => {
                let value = hex::decode(&s[4..]).map_err(|_| {
                    Error::InvalidClaimData("unable to decode enumeration claim hex string")
                })?;
                let e =
                    serde_bare::from_slice::<EnumerationClaim>(value.as_slice()).map_err(|_| {
                        Error::InvalidClaimData("unable to deserialize enumeration claim")
                    })?;
                Ok(ClaimData::Enumeration(e))
            }
            _ => Err(Error::InvalidClaimData("unknown claim type")),
        }
    }
}
