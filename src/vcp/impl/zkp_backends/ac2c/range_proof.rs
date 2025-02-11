// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::ac2c::to_from_api::range_proof_to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::inner_types::*;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn create_range_proof_proving_key() -> CreateRangeProofProvingKey {
    Arc::new(|_rng_seed| {
        let message_generator = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        let blinder_generator = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        to_api(&RangeProofCommitmentSetup { message_generator, blinder_generator })
    })
}

pub fn get_range_proof_max_value() -> GetRangeProofMaxValue {
    Arc::new(|| { 2_u64.pow(63) - 1})
}
