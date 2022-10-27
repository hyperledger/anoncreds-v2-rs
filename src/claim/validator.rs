use crate::claim::ClaimData;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;
use crate::CredxResult;
use crate::error::Error;

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
    AnyOne = 4,
}

impl From<u8> for ClaimValidatorType {
    fn from(d: u8) -> Self {
        match d {
            1 => Self::Length,
            2 => Self::Range,
            3 => Self::Regex,
            4 => Self::AnyOne,
            _ => Self::Unknown
        }
    }
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

    /// Add the public data to the transcript
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        match self {
            Self::Length { min, max } => {
                transcript
                    .append_message(b"claim validator type", &[ClaimValidatorType::Length as u8]);
                transcript.append_message(
                    b"claim validator length - min",
                    &min.map_or_else(Vec::new, |i| Uint::from(i).to_vec()),
                );
                transcript.append_message(
                    b"claim validator length - max",
                    &max.map_or_else(Vec::new, |i| Uint::from(i).to_vec()),
                );
            }
            Self::Range { min, max } => {
                transcript
                    .append_message(b"claim validator type", &[ClaimValidatorType::Range as u8]);
                transcript.append_message(
                    b"claim validator range - min",
                    &min.map_or_else(Vec::new, |i| Uint::from(i).to_vec()),
                );
                transcript.append_message(
                    b"claim validator range - max",
                    &max.map_or_else(Vec::new, |i| Uint::from(i).to_vec()),
                );
            }
            Self::Regex(rx) => {
                transcript
                    .append_message(b"claim validator type", &[ClaimValidatorType::Regex as u8]);
                transcript.append_message(b"claim validator regex", rx.to_string().as_bytes());
            }
            Self::AnyOne(set) => {
                transcript
                    .append_message(b"claim validator type", &[ClaimValidatorType::AnyOne as u8]);
                transcript.append_message(
                    b"claim validator anyone length",
                    &Uint::from(set.len()).to_vec(),
                );
                for (index, c) in set.iter().enumerate() {
                    transcript.append_message(
                        b"claim validator anyone claim index",
                        &Uint::from(index).to_vec(),
                    );
                    transcript
                        .append_message(b"claim validator anyone claim raw data", &c.to_bytes());
                    transcript.append_message(
                        b"claim validator anyone claim mapped data",
                        &c.to_scalar().to_bytes(),
                    );
                }
            }
        }
    }

    /// Convert a regex into a validator
    pub fn regex_from_string(regex: &str) -> CredxResult<Self> {
        let rx = Regex::new(regex).map_err(|_| Error::General("invalid regex"))?;
        Ok(Self::Regex(rx))
    }
}
