/// Errors created by this library
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Bad Credential Schema
    InvalidCredentialSchema,
    /// Bad Blinding Indices
    InvalidBlindingIndices,
    /// Invalid revocation registry elements
    InvalidRevocationRegistryRevokeOperation,
    /// Invalid signing operation
    InvalidSigningOperation,
    /// Invalid claim data
    InvalidClaimData,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid data for creating a signature proof
    InvalidSignatureProofData,
    /// Invalid data for creating a presentation
    InvalidPresentationData,
}
