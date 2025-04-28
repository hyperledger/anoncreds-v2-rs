// ------------------------------------------------------------------------------
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::dnc::accumulators::*;
use crate::vcp::zkp_backends::dnc::authority::*;
use crate::vcp::zkp_backends::dnc::proof::*;
use crate::vcp::zkp_backends::dnc::range_proof::*;
use crate::vcp::zkp_backends::dnc::signer::*;
// ------------------------------------------------------------------------------
use lazy_static::lazy_static;
// ------------------------------------------------------------------------------

lazy_static! {
    pub static ref CRYPTO_INTERFACE_DNC: CryptoInterface = CryptoInterface {
        create_signer_data             : specific_create_signer_data(),
        sign                           : sign(),
        create_blind_signing_info      : specific_create_blind_signing_info(),
        sign_with_blinded_attributes   : specific_sign_with_blinded_attributes(),
        unblind_blinded_signature      : specific_unblind_blinded_signature(),
        create_range_proof_proving_key : create_range_proof_proving_key(),
        get_range_proof_max_value      : get_range_proof_max_value(),
        create_authority_data          : create_authority_data(),
        create_accumulator_data        : create_accumulator_data(),
        create_membership_proving_key  : create_membership_proving_key(),
        create_accumulator_element     : create_accumulator_element(),
        accumulator_add_remove         : accumulator_add_remove(),
        update_accumulator_witness     : update_accumulator_witness(),
        specific_prover                : specific_prover_dnc(),
        specific_verifier              : specific_verifier_dnc(),
        specific_verify_decryption     : specific_verify_decryption_dnc(),
    };
}

