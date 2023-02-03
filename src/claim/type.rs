use serde::{
    de::{Error as DError, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::{Display, Error as FmtError, Formatter};
use std::str::FromStr;

/// The claim type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClaimType {
    /// The case where its none of the others
    Unknown = 0,
    /// Hashed claims
    Hashed = 1,
    /// Numeric claims
    Number = 2,
    /// Scalar based claims
    Scalar = 3,
    /// Revocation based claims
    Revocation = 4,
    /// Enumeration based claims
    Enumeration = 5,
}

impl FromStr for ClaimType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "enumeration" => Ok(Self::Enumeration),
            "hashed" => Ok(Self::Hashed),
            "number" => Ok(Self::Number),
            "scalar" => Ok(Self::Scalar),
            "revocation" => Ok(Self::Revocation),
            _ => Err("invalid type".to_string()),
        }
    }
}

impl Display for ClaimType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumeration => write!(f, "Enumeration"),
            Self::Hashed => write!(f, "Hashed"),
            Self::Number => write!(f, "Number"),
            Self::Revocation => write!(f, "Revocation"),
            Self::Scalar => write!(f, "Scalar"),
            _ => Err(FmtError),
        }
    }
}

impl From<u8> for ClaimType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Hashed,
            2 => Self::Number,
            3 => Self::Scalar,
            4 => Self::Revocation,
            5 => Self::Enumeration,
            _ => Self::Unknown,
        }
    }
}

impl Serialize for ClaimType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let s = self.to_string();
            serializer.serialize_str(&s)
        } else {
            let u = *self as u8;
            serializer.serialize_u8(u)
        }
    }
}

impl<'de> Deserialize<'de> for ClaimType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClaimTypeVisitor;

        impl<'de> Visitor<'de> for ClaimTypeVisitor {
            type Value = ClaimType;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                write!(formatter, "a string or byte")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: DError,
            {
                Ok(ClaimType::from(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DError,
            {
                ClaimType::from_str(v)
                    .map_err(|_e| DError::invalid_type(Unexpected::Other(v), &self))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(ClaimTypeVisitor)
        } else {
            deserializer.deserialize_u8(ClaimTypeVisitor)
        }
    }
}
