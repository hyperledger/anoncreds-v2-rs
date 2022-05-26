use super::{Claim, ClaimType};
use core::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use yeti::{
    knox::{bls12_381_plus::Scalar, Knox},
    sha3::Shake256,
};

/// Claims that are hashed to a scalar
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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
        Knox::xof_digest::<Shake256>(&self.value, &mut buffer);
        Scalar::from_bytes_wide(&buffer)
    }

    fn get_value(&self) -> Self::Value {
        self.value.clone()
    }
}
