use super::{Claim, ClaimType};
use crate::knox::accumulator::vb20::Element;
use blsful::inner_types::Scalar;
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};

/// A claim used for revocation
#[derive(Clone, Debug, Eq, Deserialize, Serialize)]
pub struct RevocationClaim {
    /// The revocation id
    pub value: String,
}

impl PartialEq for RevocationClaim {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Hash for RevocationClaim {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
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

impl From<&String> for RevocationClaim {
    fn from(s: &String) -> Self {
        Self { value: s.clone() }
    }
}

impl From<&str> for RevocationClaim {
    fn from(s: &str) -> Self {
        Self {
            value: s.to_string(),
        }
    }
}

impl Claim for RevocationClaim {
    type Value = String;

    fn get_type(&self) -> ClaimType {
        ClaimType::Revocation
    }

    fn to_scalar(&self) -> Scalar {
        Element::hash(self.value.as_bytes()).0
    }

    fn get_value(&self) -> Self::Value {
        self.value.clone()
    }
}
