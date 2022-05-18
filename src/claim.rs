use core::fmt::{self, Debug, Display, Formatter};
use yeti::knox::{bls12_381_plus::Scalar, Knox};

/// Represents claims
pub trait Claim {
    /// Convert this claim to a scalar
    fn to_scalar(&self) -> Scalar;
}

/// Claims that are hashed to a scalar
pub struct HashedClaim<'a> {
    /// The value to be hashed
    pub value: &'a [u8],
}

impl<'a> Clone for HashedClaim<'a> {
    fn clone(&self) -> Self {
        Self { value: self.value }
    }
}

impl<'a> Display for HashedClaim<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "HashedClaim {{ [")?;
        let mut sep = "";
        for b in self.value {
            write!(f, "{}{}", sep, b)?;
            sep = ", ";
        }
        write!(f, "] }}")
    }
}

impl<'a> Debug for HashedClaim<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "HashedClaim {{ {} }}", hex::encode(self.value))
    }
}

impl<'a> From<&'a [u8]> for HashedClaim<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self { value }
    }
}

impl<'a> AsRef<[u8]> for HashedClaim<'a> {
    fn as_ref(&self) -> &[u8] {
        self.value
    }
}

impl<'a> Claim for HashedClaim<'a> {
    fn to_scalar(&self) -> Scalar {
        let mut buffer = [0u8; 64];
        Knox::xof_digest::<yeti::sha3::Shake256>(self.value, &mut buffer);
        Scalar::from_bytes_wide(&buffer)
    }
}

/// A claim that is a 64-bit signed number
#[derive(Copy, Clone, Debug)]
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
    fn to_scalar(&self) -> Scalar {
        Scalar::from(self.value as u64)
    }
}

/// A claim that is already a scalar
#[derive(Copy, Clone, Debug)]
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
