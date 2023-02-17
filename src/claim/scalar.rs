use super::{Claim, ClaimType};
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};
use signature_bls::bls12_381_plus::Scalar;

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
        self.value.to_bytes().hash(state)
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
