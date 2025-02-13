// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::zkp_backends::ac2c::accumulators::*;
use crate::vcp::r#impl::zkp_backends::ac2c::authority::*;
use crate::vcp::r#impl::zkp_backends::ac2c::proof::*;
use crate::vcp::r#impl::zkp_backends::ac2c::range_proof::*;
use crate::vcp::r#impl::zkp_backends::ac2c::signer::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use crate::knox::ps::PsScheme;
use crate::knox::bbs::BbsScheme;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
// ------------------------------------------------------------------------------
use lazy_static::lazy_static;
// ------------------------------------------------------------------------------

macro_rules! define_crypto_interface_with {
    ($schmid: ident, $scheme: ident) => {
        paste::item! {
            lazy_static! {
                pub static ref [< CRYPTO_INTERFACE_AC2C_ $schmid >]: CryptoInterface = CryptoInterface {
                    create_signer_data             : create_signer_data::<$scheme>(),
                    sign                           : sign::<$scheme>(),
                    create_range_proof_proving_key : create_range_proof_proving_key(),
                    get_range_proof_max_value      : get_range_proof_max_value(),
                    create_authority_data          : create_authority_data::<$scheme>(),
                    create_accumulator_data        : create_accumulator_data(),
                    create_membership_proving_key  : create_membership_proving_key(),
                    create_accumulator_element     : create_accumulator_element(),
                    accumulator_add_remove         : accumulator_add_remove(),
                    update_accumulator_witness     : update_accumulator_witness(),
                    specific_prover                : specific_prover_ac2c::<$scheme>(),
                    specific_verifier              : specific_verifier_ac2c::<$scheme>(),
                    specific_verify_decryption     : specific_verify_decryption_ac2c(),
                };
            }
        }
    }
}

define_crypto_interface_with!(PS, PsScheme);
define_crypto_interface_with!(Bbs, BbsScheme);

