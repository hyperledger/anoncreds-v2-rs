use crate::claim::ClaimData;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// The claim validator types
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u8)]
pub enum ClaimValidatorType {
    /// The catch all type
    Unknown = 0,
    /// The length type
    Length = 1,
    /// The range type
    Range = 2,
    /// The regular expression type
    Regex = 3,
    /// The any one list type
    Anyone = 4,
}

/// The validations that can be made to ClaimData
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ClaimValidator {
    /// The Hashed claim data length must be between `min` and `max`
    /// `min` default is 0
    /// `max` default is [`u64::MAX`]
    Length {
        /// The minimum length
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// The maximum length
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
    },
    /// The Number claim data length must be between `min` and `max`
    /// `min` default is [`i64::MIN`]
    /// `max` default is [`i64::MAX`]
    Range {
        /// The minimum inclusive value
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<isize>,
        /// The maximum inclusive value
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<isize>,
    },
    /// The Hashed claim data must match this regular expression pattern
    #[serde(with = "serde_regex")]
    Regex(Regex),
    /// The claim data must be one of these
    AnyOne(Vec<ClaimData>),
}

impl ClaimValidator {
    /// [`Some(true)`] if the claim is the right type and meets the validator requirements
    /// [`Some(false)`] if the claim is the right type but doesn't meet the requirements
    /// [`None`] if the claim is the incorrect type
    pub fn is_valid(&self, claim: &ClaimData) -> Option<bool> {
        match self {
            Self::Length { min, max } => match claim {
                ClaimData::Hashed(h) => {
                    let min = min.unwrap_or(0);
                    let max = max.unwrap_or(u64::MAX as usize);
                    let len = h.value.len();
                    Some(min <= len && len <= max)
                }
                _ => None,
            },
            Self::Range { min, max } => match claim {
                ClaimData::Number(n) => {
                    let min = min.unwrap_or(i64::MIN as isize);
                    let max = max.unwrap_or(i64::MAX as isize);
                    Some(min <= n.value && n.value <= max)
                }
                _ => None,
            },
            Self::Regex(rx) => match claim {
                ClaimData::Hashed(h) => match String::from_utf8(h.value.clone()) {
                    Err(_) => None,
                    Ok(s) => Some(rx.is_match(&s)),
                },
                _ => None,
            },
            Self::AnyOne(claims) => Some(claims.iter().any(|c| c == claim)),
        }
    }
}
