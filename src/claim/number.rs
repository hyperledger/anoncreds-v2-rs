use super::{Claim, ClaimType};
use crate::utils::get_num_scalar;
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};
use signature_bls::bls12_381_plus::Scalar;

/// A claim that is a 64-bit signed number
#[derive(Copy, Clone, Eq, Debug, Deserialize, Serialize)]
pub struct NumberClaim {
    /// The claim value
    pub value: isize,
}

impl PartialEq for NumberClaim {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Hash for NumberClaim {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
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
        get_num_scalar(self.value)
    }

    fn get_value(&self) -> Self::Value {
        self.value
    }
}
