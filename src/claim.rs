mod validator;

use crate::error::Error;
use crate::CredxResult;
use core::fmt::{self, Debug, Display, Formatter};
use serde::{Deserialize, Serialize};
use yeti::knox::accumulator::vb20;
use yeti::knox::{bls12_381_plus::Scalar, Knox};

/// The claim type
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum ClaimType {
    /// The case where its none of the others
    Unknown = 0,
    /// Hashed claims
    Hashed = 1,
    /// Numeric claims
    Number = 2,
    /// Scalar based claims
    Scalar = 3,
    /// Revocation based claims
    Revocation = 4,
}

/// The type of claim data that can be signed
#[derive(Clone, Debug, Deserialize, Serialize)]
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
}

/// Represents claims
pub trait Claim {
    /// The inner type
    type Value;

    /// Get the claim type
    fn get_type(&self) -> ClaimType;
    /// Convert this claim to a scalar
    fn to_scalar(&self) -> Scalar;
    /// Get the claim data value
    fn get_value(&self) -> Self::Value;
}

/// Claims that are hashed to a scalar
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HashedClaim {
    /// The value to be hashed
    pub value: Vec<u8>,
}

impl Display for HashedClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "HashedClaim {{ [")?;
        let mut sep = "";
        for b in &self.value {
            write!(f, "{}{}", sep, b)?;
            sep = ", ";
        }
        write!(f, "] }}")
    }
}

impl<'a> From<&'a [u8]> for HashedClaim {
    fn from(value: &'a [u8]) -> Self {
        Self {
            value: value.to_vec(),
        }
    }
}

impl AsRef<[u8]> for HashedClaim {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl Claim for HashedClaim {
    type Value = Vec<u8>;

    fn get_type(&self) -> ClaimType {
        ClaimType::Hashed
    }

    fn to_scalar(&self) -> Scalar {
        let mut buffer = [0u8; 64];
        Knox::xof_digest::<yeti::sha3::Shake256>(&self.value, &mut buffer);
        Scalar::from_bytes_wide(&buffer)
    }

    fn get_value(&self) -> Self::Value {
        self.value.clone()
    }
}

/// A claim that is a 64-bit signed number
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct NumberClaim {
    /// The claim value
    pub value: isize,
}

impl Display for NumberClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "NumberClaim {{ {} }}", self.value)
    }
}

macro_rules! impl_from {
    ($name:ident, $($ty:ty),*) => {
        $(
            impl From<$ty> for $name {
                fn from(value: $ty) -> Self {
                    Self::from(value as isize)
                }
            }
        )*
    };
}

impl From<isize> for NumberClaim {
    fn from(value: isize) -> Self {
        Self { value }
    }
}

impl_from!(NumberClaim, i64, i32, i16, i8, usize, u64, u32, u16, u8);

impl Claim for NumberClaim {
    type Value = isize;

    fn get_type(&self) -> ClaimType {
        ClaimType::Number
    }

    fn to_scalar(&self) -> Scalar {
        Scalar::from(self.value as u64)
    }

    fn get_value(&self) -> Self::Value {
        self.value
    }
}

/// A claim that is already a scalar
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct ScalarClaim {
    /// The scalar value
    pub value: Scalar,
}

impl Display for ScalarClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ScalarClaim {{ {} }}", self.value)
    }
}

impl From<Scalar> for ScalarClaim {
    fn from(value: Scalar) -> Self {
        Self { value }
    }
}

impl Claim for ScalarClaim {
    type Value = Scalar;

    fn get_type(&self) -> ClaimType {
        ClaimType::Scalar
    }

    fn to_scalar(&self) -> Scalar {
        self.value
    }

    fn get_value(&self) -> Self::Value {
        self.value
    }
}

/// A claim used for revocation
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationClaim {
    /// The revocation id
    pub value: String,
}

impl Display for RevocationClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RevocationClaim {{ {} }}", self.value)
    }
}

impl From<String> for RevocationClaim {
    fn from(s: String) -> Self {
        Self { value: s }
    }
}

impl Claim for RevocationClaim {
    type Value = String;

    fn get_type(&self) -> ClaimType {
        ClaimType::Revocation
    }

    fn to_scalar(&self) -> Scalar {
        vb20::Element::hash(self.value.as_bytes()).0
    }

    fn get_value(&self) -> Self::Value {
        self.value.clone()
    }
}
