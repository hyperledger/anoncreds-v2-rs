use super::{Claim, ClaimType};
use core::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use yeti::knox::bls12_381_plus::Scalar;

/// A claim that is already a scalar
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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
