// -----------------------------------------------------------------------------
pub use crate::vcp::Error;
pub use crate::vcp::crypto_interface::CryptoInterface;
pub use crate::vcp::r#impl::general::proof::{create_proof, verify_proof};
pub use crate::vcp::non_primitives::*;
pub use crate::vcp::primitives::*;
pub use crate::vcp::types::*;
// -----------------------------------------------------------------------------

/// For now, we expose all functionality in one API.
/// In future, more focused APIs could be constructed,
/// e.g., specific to individual roles and/or scenarios.
/// For example
///   pub struct IssuerRevocationManagerApi {
///     pub create_signer_data: CreateSignerData,
///     pub sign: Sign,
///   }
/// provides the functionality needed by an Issuer
/// who also serves as the Revocation Manager for all Accumulators.

#[derive(Clone)]
pub struct PlatformApi {
    pub create_signer_data: CreateSignerData,
    pub sign: Sign,
    pub create_blind_signing_info: CreateBlindSigningInfo,
    pub sign_with_blinded_attributes: SignWithBlindedAttributes,
    pub unblind_blinded_signature: UnblindBlindedSignature,
    // Range proof setup
    pub create_range_proof_proving_key: CreateRangeProofProvingKey,
    // This function should return the largest value for which the underlying ZKP
    // can create a range proof.  This enables participants to use and test range
    // proofs without knowing the underlying ZKP library's maximum supported
    // value.  In particular, it can be used by:
    // - Issuers, in case they want to use a "maximum" value for an attribute
    //   that may be subject to range proofs;
    // - Verifiers, in case they want to express a "greater than" range proof
    //   requirement
    // - Tests, to ensure that the maximum supported value is reported accurately
    pub get_range_proof_max_value: GetRangeProofMaxValue,
    // Authority setup
    pub create_authority_data: CreateAuthorityData,
    // Accumulator setup
    pub create_accumulator_data: CreateAccumulatorData,
    pub create_membership_proving_key: CreateMembershipProvingKey,
    // Acccumulator functions
    pub create_accumulator_element: CreateAccumulatorElement,
    pub accumulator_add_remove: AccumulatorAddRemove,
    // Auxiliary data functions
    pub update_accumulator_witness: UpdateAccumulatorWitness,
    // Proofs
    pub create_proof: CreateProof,
    pub verify_proof: VerifyProof,
    pub verify_decryption: VerifyDecryption,
}
