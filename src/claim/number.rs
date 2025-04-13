use super::{Claim, ClaimType};
use crate::utils::zero_center;
use crate::{error::Error, utils::get_num_scalar};
use blsful::inner_types::Scalar;
use chrono::Datelike;
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};

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

impl From<Scalar> for NumberClaim {
    fn from(value: Scalar) -> Self {
        let limb = <[u8; 8]>::try_from(&value.to_le_bytes()[..8])
            .expect("Scalar is 32 bytes, so 8 bytes should exist");
        Self::from(zero_center(u64::from_le_bytes(limb) as isize))
    }
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

impl NumberClaim {
    /// RFC3339 dates are in the format of `YYYY-MM-DD` and are treated
    /// as a number claim with the value of `YYYYMMDD`.
    pub fn parse_rfc3339_date<S: AsRef<str>>(date: S) -> Result<Self, Error> {
        // Use chrono to check whether the date is valid.
        // Invalid dates include days greater than 31, months greater than 12, etc.
        // and checks whether the month even supports the number of days specified
        // like February 30th is never valid.
        let dt = chrono::NaiveDate::parse_from_str(date.as_ref(), "%Y-%m-%d")
            .map_err(|_| Error::InvalidClaimData("Invalid RFC3339 date"))?;
        // There's no need to zero center unless we're dealing with a dates BC
        let mut value = dt.year().to_string();
        if dt.month() < 10 {
            value.push('0');
        }
        value.push_str(&dt.month().to_string());
        if dt.day() < 10 {
            value.push('0');
        }
        value.push_str(&dt.day().to_string());
        Ok(Self::from(value.parse::<isize>().map_err(|_| {
            Error::InvalidClaimData("Invalid RFC3339 date")
        })?))
    }

    /// RFC3339 DateTimes are in the format of `YYYY-MM-DDTHH:MM:SSZ` and are treated
    /// as a number claim representing the number of seconds since the Unix epoch.
    pub fn parse_rfc3339_datetime<S: AsRef<str>>(datetime: S) -> Result<Self, Error> {
        let dt = chrono::DateTime::parse_from_rfc3339(datetime.as_ref())
            .map_err(|_| Error::InvalidClaimData("Invalid RFC3339 datetime"))?;
        // There's no need to zero center unless we're dealing with a dates BC
        Ok(Self::from(dt.timestamp() as isize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_date() {
        let claim = NumberClaim::parse_rfc3339_date("2021-01-01").unwrap();
        assert_eq!(claim.value, 20210101);

        let claim = NumberClaim::parse_rfc3339_date("1982-12-31").unwrap();
        assert_eq!(claim.value, 19821231);
    }

    #[test]
    fn test_rfc3339_datetime() {
        let claim = NumberClaim::parse_rfc3339_datetime("2021-01-01T00:00:00Z").unwrap();
        assert_eq!(claim.value, 1609459200);
    }
}
