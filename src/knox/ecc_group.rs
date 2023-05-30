use core::{fmt, ops};
use sha3::digest::Digest;

use blsful::inner_types::Scalar;
use zeroize::Zeroize;

/// Adds `from_bytes_wide` for Generic Scalars
pub trait ScalarOps {
    /// The scalar value to be returned
    type Scalar: Copy
        + Default
        + From<u64>
        + From<Self::Scalar>
        + ops::Neg<Output = Self::Scalar>
        + ops::Add<Output = Self::Scalar>
        + ops::Sub<Output = Self::Scalar>
        + ops::Mul<Output = Self::Scalar>
        + Zeroize
        + fmt::Debug;

    /// Convert 64 bytes into a scalar element
    fn from_bytes_wide(input: &[u8; 64]) -> Self::Scalar;

    /// Perform a cryptographic hashing operation to produce a scalar element
    fn from_hash(input: &[u8]) -> Self::Scalar {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sha2::Sha512::digest(input));
        Self::from_bytes_wide(&bytes)
    }
}

impl ScalarOps for Scalar {
    type Scalar = Scalar;

    fn from_bytes_wide(input: &[u8; 64]) -> Self::Scalar {
        Scalar::from_bytes_wide(input)
    }
}

/// Adds necessary methods for frost signing
pub trait ElementOps: ScalarOps {
    /// The inner element to operate on
    type Element: Copy
        + ops::Add<Output = Self::Element>
        + ops::Sub<Output = Self::Element>
        + ops::Neg<Output = Self::Element>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Element>
        + fmt::Debug;

    /// Return if this Element is negative or odd
    fn is_negative(&self) -> bool;

    /// Return the bytes use for computing signatures
    fn to_sig_bytes(&self) -> [u8; 32];
}
