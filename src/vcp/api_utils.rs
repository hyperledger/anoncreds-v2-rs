// ---------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::api::PlatformApi;
use crate::vcp::crypto_interface::CryptoInterface;
use crate::vcp::r#impl::common::general::proof::*;
use crate::vcp::non_primitives::*;
use crate::vcp::primitives::*;
// ---------------------------------------------------------------------------
use std::collections::HashMap;
use std::rc::Rc;
// ---------------------------------------------------------------------------

pub fn implement_platform_api_using(
    CryptoInterface {
        create_signer_data: csd,
        sign,
        create_range_proof_proving_key: crpk,
        create_authority_data: cauthd,
        create_accumulator_data: caccd,
        create_membership_proving_key: cmpk,
        create_accumulator_element: cae,
        accumulator_add_remove: aar,
        update_accumulator_witness: ucad,
        specific_prover: sp,
        specific_verifier: sv,
        specific_verify_decryption: svd,
    }: CryptoInterface,
) -> PlatformApi {
    PlatformApi {
        create_signer_data: csd,
        sign,
        create_range_proof_proving_key: crpk,
        create_authority_data: cauthd,
        create_accumulator_data: caccd.clone(),
        create_membership_proving_key: cmpk,
        create_accumulator_element: cae.clone(),
        accumulator_add_remove: aar.clone(),
        update_accumulator_witness: ucad.clone(),
        create_proof: create_proof(sp),
        verify_proof: verify_proof(sv.clone()),
        verify_decryption: verify_decryption(sv,svd),
    }
}
