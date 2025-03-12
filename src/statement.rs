mod commitment;
mod equality;
mod membership;
mod range;
mod revocation;
mod signature;
mod verifiable_encryption;
mod verifiable_encryption_decryption;

pub use commitment::*;
pub use equality::*;
pub use membership::*;
pub use range::*;
pub use revocation::*;
pub use signature::*;
pub use verifiable_encryption::*;
pub use verifiable_encryption_decryption::*;

use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use blsful::inner_types::G1Projective;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// Statement methods
pub trait Statement {
    /// Return this statement unique identifier
    fn id(&self) -> String;
    /// Any statements that this statement references
    fn reference_ids(&self) -> Vec<String>;
    /// Add the public statement data to the transcript
    fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript);
    /// Get the claim index to which this statement refers
    fn get_claim_index(&self, reference_id: &str) -> usize;
}

/// The various statement types
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Statements<S: ShortGroupSignatureScheme> {
    /// Signature statements
    #[serde(bound(
        serialize = "SignatureStatement<S>: Serialize",
        deserialize = "SignatureStatement<S>: Deserialize<'de>"
    ))]
    Signature(Box<SignatureStatement<S>>),
    /// Equality statements
    Equality(Box<EqualityStatement>),
    /// Revocation statements
    Revocation(Box<RevocationStatement>),
    /// Commitment statements
    Commitment(Box<CommitmentStatement<G1Projective>>),
    /// Verifiable Encryption statements
    VerifiableEncryption(Box<VerifiableEncryptionStatement<G1Projective>>),
    /// Range statements
    Range(Box<RangeStatement>),
    /// Membership statements
    Membership(Box<MembershipStatement>),
    VerifiableEncryptionDecryption(Box<VerifiableEncryptionDecryptionStatement<G1Projective>>),
}

impl<S: ShortGroupSignatureScheme> From<SignatureStatement<S>> for Statements<S> {
    fn from(s: SignatureStatement<S>) -> Self {
        Self::Signature(Box::new(s))
    }
}

impl<S: ShortGroupSignatureScheme> From<EqualityStatement> for Statements<S> {
    fn from(e: EqualityStatement) -> Self {
        Self::Equality(Box::new(e))
    }
}

impl<S: ShortGroupSignatureScheme> From<RevocationStatement> for Statements<S> {
    fn from(a: RevocationStatement) -> Self {
        Self::Revocation(Box::new(a))
    }
}

impl<S: ShortGroupSignatureScheme> From<CommitmentStatement<G1Projective>> for Statements<S> {
    fn from(c: CommitmentStatement<G1Projective>) -> Self {
        Self::Commitment(Box::new(c))
    }
}

impl<S: ShortGroupSignatureScheme> From<VerifiableEncryptionStatement<G1Projective>>
    for Statements<S>
{
    fn from(c: VerifiableEncryptionStatement<G1Projective>) -> Self {
        Self::VerifiableEncryption(Box::new(c))
    }
}

impl<S: ShortGroupSignatureScheme> From<RangeStatement> for Statements<S> {
    fn from(c: RangeStatement) -> Self {
        Self::Range(Box::new(c))
    }
}

impl<S: ShortGroupSignatureScheme> From<MembershipStatement> for Statements<S> {
    fn from(m: MembershipStatement) -> Self {
        Self::Membership(Box::new(m))
    }
}

impl<S: ShortGroupSignatureScheme> From<VerifiableEncryptionDecryptionStatement<G1Projective>>
    for Statements<S>
{
    fn from(m: VerifiableEncryptionDecryptionStatement<G1Projective>) -> Self {
        Self::VerifiableEncryptionDecryption(Box::new(m))
    }
}

impl<S: ShortGroupSignatureScheme> Statements<S> {
    /// Return the statement id
    pub fn id(&self) -> String {
        match self {
            Self::Signature(s) => s.id(),
            Self::Equality(e) => e.id(),
            Self::Revocation(a) => a.id(),
            Self::Commitment(c) => c.id(),
            Self::VerifiableEncryption(v) => v.id(),
            Self::Range(r) => r.id(),
            Self::Membership(m) => m.id(),
            Self::VerifiableEncryptionDecryption(v) => v.id(),
        }
    }

    /// Return any references to other statements
    pub fn reference_ids(&self) -> Vec<String> {
        match self {
            Self::Signature(s) => s.reference_ids(),
            Self::Equality(e) => e.reference_ids(),
            Self::Revocation(a) => a.reference_ids(),
            Self::Commitment(c) => c.reference_ids(),
            Self::VerifiableEncryption(v) => v.reference_ids(),
            Self::Range(r) => r.reference_ids(),
            Self::Membership(m) => m.reference_ids(),
            Self::VerifiableEncryptionDecryption(v) => v.reference_ids(),
        }
    }

    /// Add the data to the challenge hash
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        match self {
            Self::Signature(s) => s.add_challenge_contribution(transcript),
            Self::Equality(e) => e.add_challenge_contribution(transcript),
            Self::Revocation(a) => a.add_challenge_contribution(transcript),
            Self::Commitment(c) => c.add_challenge_contribution(transcript),
            Self::VerifiableEncryption(v) => v.add_challenge_contribution(transcript),
            Self::Range(r) => r.add_challenge_contribution(transcript),
            Self::Membership(m) => m.add_challenge_contribution(transcript),
            Self::VerifiableEncryptionDecryption(v) => v.add_challenge_contribution(transcript),
        }
    }

    /// Return the index associated with the claim label
    pub fn get_claim_index(&self, reference_id: &str) -> usize {
        match self {
            Self::Signature(s) => s.get_claim_index(reference_id),
            Self::Equality(e) => e.get_claim_index(reference_id),
            Self::Revocation(a) => a.get_claim_index(reference_id),
            Self::Commitment(c) => c.get_claim_index(reference_id),
            Self::VerifiableEncryption(v) => v.get_claim_index(reference_id),
            Self::Range(r) => r.get_claim_index(reference_id),
            Self::Membership(m) => m.get_claim_index(reference_id),
            Self::VerifiableEncryptionDecryption(v) => v.get_claim_index(reference_id),
        }
    }
}

/// Statement types
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum StatementType {
    /// Unknown statements
    Unknown = 0,
    /// Signature statements
    Signature = 1,
    /// Equality statements
    Equality = 2,
    /// Revocation statements
    Revocation = 3,
    /// Commitment statements
    Commitment = 4,
    /// VerifiableEncryption statements
    VerifiableEncryption = 5,
    /// Range statements
    Range = 6,
    /// Membership statements
    Membership = 7,
}

impl std::fmt::Display for StatementType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Signature => write!(f, "Signature"),
            Self::Equality => write!(f, "Equality"),
            Self::Revocation => write!(f, "Revocation"),
            Self::Commitment => write!(f, "Commitment"),
            Self::VerifiableEncryption => write!(f, "VerifiableEncryption"),
            Self::Range => write!(f, "Range"),
            Self::Membership => write!(f, "Membership"),
        }
    }
}

impl std::str::FromStr for StatementType {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "signature" => Self::Signature,
            "equality" => Self::Equality,
            "revocation" => Self::Revocation,
            "commitment" => Self::Commitment,
            "verifiableencryption" => Self::VerifiableEncryption,
            "range" => Self::Range,
            "membership" => Self::Membership,
            _ => Self::Unknown,
        })
    }
}

impl From<u8> for StatementType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Signature,
            2 => Self::Equality,
            3 => Self::Revocation,
            4 => Self::Commitment,
            5 => Self::VerifiableEncryption,
            6 => Self::Range,
            7 => Self::Membership,
            _ => Self::Unknown,
        }
    }
}

impl Serialize for StatementType {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            self.to_string().serialize(s)
        } else {
            (*self as u8).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for StatementType {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeVisitor;

        impl Visitor<'_> for TypeVisitor {
            type Value = StatementType;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                write!(formatter, "a string or byte")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                v.parse()
                    .map_err(|_e| Error::invalid_value(serde::de::Unexpected::Str(v), &self))
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.into())
            }
        }

        if d.is_human_readable() {
            d.deserialize_str(TypeVisitor)
        } else {
            d.deserialize_u8(TypeVisitor)
        }
    }
}
