// ----------------------------------------------------------------------------
pub use crate::vcp::primitives::*;
// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct CryptoInterface {
    // Signing
    pub create_signer_data: SpecificCreateSignerData,
    pub sign: SpecificSign,
    pub create_blind_signing_info: SpecificCreateBlindSigningInfo,
    pub sign_with_blinded_attributes: SpecificSignWithBlindedAttributes,
    pub unblind_blinded_signature: SpecificUnblindBlindedSignature,
    // Range proof setup
    pub create_range_proof_proving_key: CreateRangeProofProvingKey,
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
    pub specific_prover: SpecificProver,
    pub specific_verifier: SpecificVerifier,
    pub specific_verify_decryption: SpecificVerifyDecryption,
}
