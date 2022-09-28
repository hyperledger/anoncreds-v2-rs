use serde::{Deserialize, Serialize};

/// The possible statement types
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u8)]
pub enum StatementType {
    /// The catch call statement type
    Unknown = 0,
    /// BBS+ signatures
    BBS = 1,
    /// PS signatures
    PS = 2,
    /// Claim equality
    Equality = 3,
    /// Commitment
    Commitment = 4,
    /// Set inclusion
    VbSetInclusion = 5,
    /// Verifiable Encryption
    ElGamalVerifiableEncryption = 6,
    /// Range proofs with Bulletproofs
    RangeProofBulletproof = 7,
}
