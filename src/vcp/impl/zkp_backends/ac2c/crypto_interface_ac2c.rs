// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::zkp_backends::ac2c::accumulators::*;
use crate::vcp::r#impl::zkp_backends::ac2c::authority::*;
use crate::vcp::r#impl::zkp_backends::ac2c::proof::*;
use crate::vcp::r#impl::zkp_backends::ac2c::range_proof::*;
use crate::vcp::r#impl::zkp_backends::ac2c::signer::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use lazy_static::lazy_static;
// ------------------------------------------------------------------------------

lazy_static! {
    pub static ref CRYPTO_INTERFACE_AC2C: CryptoInterface = CryptoInterface {
        create_signer_data             : create_signer_data(),
        sign                           : sign(),
        create_range_proof_proving_key : create_range_proof_proving_key(),
        create_authority_data          : create_authority_data(),
        create_accumulator_data        : create_accumulator_data(),
        create_membership_proving_key  : create_membership_proving_key(),
        create_accumulator_element     : create_accumulator_element(),
        accumulator_add_remove         : accumulator_add_remove(),
        update_accumulator_witness     : update_accumulator_witness(),
        specific_prover                : specific_prover_ac2c(),
        specific_verifier              : specific_verifier_ac2c(),
        specific_verify_decryption     : specific_verify_decryption_ac2c(),
    };
}

