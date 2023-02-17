use crate::prelude::*;
use serde::{Deserialize, Serialize};
use crate::knox::accumulator::vb20;

/// A membership signing key
pub type MembershipSigningKey = vb20::SecretKey;

/// A membership verification key
pub type MembershipVerificationKey = vb20::PublicKey;

/// A membership registry
pub type MembershipRegistry = vb20::Accumulator;

/// A membership credential
pub type MembershipCredential = vb20::MembershipWitness;

/// A membership claim in the registry
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MembershipClaim(pub vb20::Element);

impl From<ClaimData> for MembershipClaim {
    fn from(value: ClaimData) -> Self {
        Self::from(&value)
    }
}

impl From<&ClaimData> for MembershipClaim {
    fn from(value: &ClaimData) -> Self {
        Self(vb20::Element(value.to_scalar()))
    }
}

impl From<NumberClaim> for MembershipClaim {
    fn from(value: NumberClaim) -> Self {
        Self::from(&value)
    }
}

impl From<&NumberClaim> for MembershipClaim {
    fn from(value: &NumberClaim) -> Self {
        Self(vb20::Element(value.to_scalar()))
    }
}

impl From<HashedClaim> for MembershipClaim {
    fn from(value: HashedClaim) -> Self {
        Self::from(&value)
    }
}

impl From<&HashedClaim> for MembershipClaim {
    fn from(value: &HashedClaim) -> Self {
        Self(vb20::Element(value.to_scalar()))
    }
}

impl From<ScalarClaim> for MembershipClaim {
    fn from(value: ScalarClaim) -> Self {
        Self::from(&value)
    }
}

impl From<&ScalarClaim> for MembershipClaim {
    fn from(value: &ScalarClaim) -> Self {
        Self(vb20::Element(value.to_scalar()))
    }
}
