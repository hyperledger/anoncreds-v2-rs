// ---------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::api::PlatformApi;
use crate::vcp::crypto_interface::CryptoInterface;
use crate::vcp::r#impl::general::proof::*;
use crate::vcp::r#impl::general::signer::*;
use crate::vcp::non_primitives::*;
use crate::vcp::primitives::*;
// ---------------------------------------------------------------------------
use std::collections::HashMap;
use std::rc::Rc;
// ---------------------------------------------------------------------------

pub fn implement_platform_api_using(
    CryptoInterface {
        create_signer_data: csd,
        sign: ss,
        create_blind_signing_info: cbsi,
        sign_with_blinded_attributes: swba,
        unblind_blinded_signature: ubs,
        create_range_proof_proving_key: crpk,
        get_range_proof_max_value: grpmv,
        create_authority_data: cauthd,
        create_accumulator_data: caccd,
        create_membership_proving_key: cmpk,
        create_accumulator_element: cae,
        accumulator_add_remove: aar,
        get_accumulator_witness: gaw,
        update_accumulator_witness: ucad,
        specific_prover: sp,
        specific_verifier: sv,
        specific_verify_decryption: svd,
    }: &CryptoInterface,
) -> PlatformApi {
    PlatformApi {
        create_signer_data: create_signer_data(csd.clone()),
        sign: sign(ss.clone()),
        create_blind_signing_info: create_blind_signing_info(cbsi.clone()),
        sign_with_blinded_attributes: sign_with_blinded_attributes(swba.clone()),
        unblind_blinded_signature: unblind_blinded_signature(ubs.clone()),
        create_range_proof_proving_key: crpk.clone(),
        get_range_proof_max_value: grpmv.clone(),
        create_authority_data: cauthd.clone(),
        create_accumulator_data: caccd.clone(),
        create_membership_proving_key: cmpk.clone(),
        create_accumulator_element: cae.clone(),
        accumulator_add_remove: aar.clone(),
        get_accumulator_witness: gaw.clone(),
        update_accumulator_witness: ucad.clone(),
        create_proof: create_proof(sp.clone()),
        verify_proof: verify_proof(sv.clone()),
        verify_decryption: verify_decryption(sv.clone(),svd.clone()),
    }
}
