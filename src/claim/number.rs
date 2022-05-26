use super::{Claim, ClaimType};
use core::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use yeti::knox::bls12_381_plus::Scalar;

/// A claim that is a 64-bit signed number
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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
