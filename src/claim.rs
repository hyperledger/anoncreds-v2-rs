mod data;
mod enumeration;
mod hashed;
mod number;
mod revocation;
mod scalar;
mod r#type;
mod validator;

pub use data::*;
pub use enumeration::*;
pub use hashed::*;
pub use number::*;
pub use r#type::*;
pub use revocation::*;
pub use scalar::*;
pub use validator::*;

use blsful::bls12_381_plus::Scalar;

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
