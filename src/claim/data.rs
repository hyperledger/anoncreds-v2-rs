use super::*;
use crate::{error::Error, CredxResult};
use serde::{Deserialize, Serialize};

/// The type of claim data that can be signed
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ClaimData {
    /// Data is hashed before signing
    Hashed(HashedClaim),
    /// Data is a number
    Number(NumberClaim),
    /// Data is a scalar
    Scalar(ScalarClaim),
    /// Data is a fixed string
    Revocation(RevocationClaim),
}

impl ClaimData {
    /// Get the scalar to be signed
    pub fn to_scalar(&self) -> Scalar {
        match self {
            Self::Hashed(h) => h.to_scalar(),
            Self::Number(n) => n.to_scalar(),
            Self::Scalar(s) => s.to_scalar(),
            Self::Revocation(r) => r.to_scalar(),
        }
    }

    /// Convert this claim to a byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Hashed(h) => h.value.clone(),
            Self::Number(n) => n.value.to_le_bytes().to_vec(),
            Self::Scalar(s) => s.value.to_bytes().to_vec(),
            Self::Revocation(r) => r.value.as_bytes().to_vec(),
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
                    _ => return Err(Error::InvalidClaimData),
                };
                Ok(Self::Number(n))
            }
            ClaimType::Scalar => {
                let s = Scalar::from_bytes(&<[u8; 32]>::try_from(data).unwrap());
                if s.is_none().unwrap_u8() == 1 {
                    return Err(Error::InvalidClaimData);
                }
                Ok(Self::Scalar(ScalarClaim { value: s.unwrap() }))
            }
            ClaimType::Revocation => {
                if data.len() != 16 {
                    return Err(Error::InvalidClaimData);
                }
                let s = String::from_utf8(data.to_vec()).map_err(|_| Error::InvalidClaimData)?;
                Ok(Self::Revocation(RevocationClaim { value: s }))
            }
            _ => Err(Error::InvalidClaimData),
        }
    }

    /// [`true`] if the claim is the right type
    /// [`false`] if the claim is the incorrect type
    pub fn is_type(&self, claim_type: ClaimType) -> bool {
        match (self, claim_type) {
            (Self::Hashed(_), ClaimType::Hashed)
            | (Self::Number(_), ClaimType::Number)
            | (Self::Scalar(_), ClaimType::Scalar)
            | (Self::Revocation(_), ClaimType::Revocation) => true,
            (_, _) => false,
        }
    }
}
