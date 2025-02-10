// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::dnc::reversible_encoding::text_to_field_element;
use crate::vcp::r#impl::zkp_backends::dnc::types::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn generate_fr_from_val_and_ct(
    ct_dv : (&ClaimType, &DataValue)
) -> VCPResult<Fr>
{
    match ct_dv
    {
        (ClaimType::CTText             , DataValue::DVText(t)) => Ok(field_elems_from_seeds(t)?),
        (ClaimType::CTEncryptableText  , DataValue::DVText(t)) => Ok(text_to_field_element(t.to_string())?),
        (ClaimType::CTInt              , DataValue::DVInt(i))  => Ok(Fr::from(*i)),
        (ClaimType::CTAccumulatorMember, DataValue::DVText(t)) => Ok(field_elems_from_seeds(t)?),
        _x => Err(Error::General(format!("generate_fr_from_val_and_ct, UNEXPECTED combination: {:?} {:?}",
                                         ct_dv.0, ct_dv.1)))
    }
}

pub fn generate_frs_from_vals_and_ct(
    vals    : &[DataValue],
    sdcts   : &[ClaimType],
    err_msg : &str,
) -> VCPResult<Vec<Fr>>
{
    if (vals.len() != sdcts.len()) {
        Err(Error::General(format!(
            "{err_msg}, number of values and claim types unequal: {:?} {:?}", sdcts, vals)))
    } else {
        sdcts.iter().zip(vals.iter())
            .map(generate_fr_from_val_and_ct)
            .collect::<VCPResult<Vec<_>>>()
    }
}

fn field_elems_from_seeds(t : &String) -> VCPResult<Fr> {
    let hasher = <DefaultFieldHasher<Blake2b512> as HashToField<Fr>>::new(b"STRING-TO-FR");
    let seed   = t.as_bytes();
    match hasher.hash_to_field(seed, 1).pop() {
        None    => Err(Error::General("DNC field_elems_from_seeds".to_string())),
        Some(x) => Ok(x)
    }
}

