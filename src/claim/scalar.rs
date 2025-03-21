use super::{Claim, ClaimType};
use crate::error::Error;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};

/// A claim that is already a scalar
#[derive(Copy, Clone, Debug, Eq, Deserialize, Serialize)]
pub struct ScalarClaim {
    /// The scalar value
    pub value: Scalar,
}

impl PartialEq for ScalarClaim {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Hash for ScalarClaim {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.to_be_bytes().hash(state)
    }
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

impl ScalarClaim {
    pub fn encode_str(value: &str) -> CredxResult<Self> {
        if value.len() > 30 {
            return Err(Error::InvalidClaimData(
                "scalar claim can only store 30 bytes or less and cannot be empty",
            ));
        }
        let mut bytes = [0u8; 32];
        if !value.is_empty() {
            bytes[1] = value.len() as u8;
            bytes[32 - value.len()..].copy_from_slice(value.as_bytes());
        }
        let s = Option::<Scalar>::from(Scalar::from_be_bytes(&bytes))
            .ok_or(Error::InvalidClaimData("scalar claim is not valid UTF-8"))?;
        Ok(Self::from(s))
    }

    pub fn decode_to_str(&self) -> CredxResult<String> {
        let data = self.value.to_be_bytes();
        let len = data[1] as usize;
        String::from_utf8(data[32 - len..].to_vec())
            .map_err(|_| Error::InvalidClaimData("scalar claim is not valid UTF-8"))
    }

    pub fn encode_bytes(value: &[u8]) -> CredxResult<Self> {
        if value.len() > 30 {
            return Err(Error::InvalidClaimData(
                "scalar claim can only store 30 bytes or less",
            ));
        }
        let mut bytes = [0u8; 32];
        if !value.is_empty() {
            bytes[1] = value.len() as u8;
            bytes[32 - value.len()..].copy_from_slice(value);
        }
        let s = Option::<Scalar>::from(Scalar::from_be_bytes(&bytes))
            .ok_or(Error::InvalidClaimData("scalar claim is not byte data"))?;
        Ok(Self::from(s))
    }

    pub fn decode_to_bytes(&self) -> CredxResult<Vec<u8>> {
        let data = self.value.to_be_bytes();
        let len = data[1] as usize;
        Ok(data[32 - len..].to_vec())
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
