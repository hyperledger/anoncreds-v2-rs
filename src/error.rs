/// Errors created by this library
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Bad Credential Schema
    InvalidCredentialSchema,
    /// Bad Blinding Indices
    InvalidBlindingIndices,
    /// Invalid revocation registry elements
    InvalidRevocationRegistryRevokeOperation,
    /// Attempted to update a handle for a value that's already revoked or not included
    InvalidRevocationHandleUpdate,
    /// Invalid signing operation
    InvalidSigningOperation,
    /// Invalid claim data
    InvalidClaimData(&'static str),
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid data for creating a signature proof
    InvalidSignatureProofData,
    /// Invalid data for creating a presentation
    InvalidPresentationData,
    /// Invalid bulletproof range
    InvalidBulletproofRange,
    /// Invalid binary or text data
    DeserializationError,
    /// A generic error message
    General(&'static str),
}
