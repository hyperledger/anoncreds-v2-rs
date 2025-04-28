use crate::str_vec_from;
use crate::vcp::{Error, VCPResult};
use crate::vcp::api::ClaimType::*;
use crate::vcp::api::DataValue::*;
use crate::vcp::r#impl::general::signer::ProofMode::*;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::non_primitives::*;
use crate::vcp::interfaces::primitives::*;
use crate::vcp::interfaces::types::*;
// ----------------------------------------------------------------------------
use std::rc::Rc;
use std::sync::Arc;
// ----------------------------------------------------------------------------

pub fn create_signer_data (
    spec_create_signer_data : SpecificCreateSignerData
) -> CreateSignerData {
    Arc::new(
        move |rng_seed, schema, blind_attr_idxs, proof_mode| {
            // Keep indices sorted to facilitate comparison when checking correct indices provided
            let mut blind_attr_idxs: Vec<_> = blind_attr_idxs.to_vec();
            blind_attr_idxs.sort();
            if proof_mode != TestBackend {
                check_attr_idxs_for_schema("create_signer_data", schema, &blind_attr_idxs)?;
            }
            let (spsd,ssd) = spec_create_signer_data(rng_seed, schema, &blind_attr_idxs)?;
            Ok(SignerData {
                signer_public_data: Box::new(SignerPublicData {
                    signer_public_setup_data: spsd,
                    signer_public_schema: schema.to_vec(),
                    signer_blinded_attr_idxs: blind_attr_idxs.to_vec()}),
                signer_secret_data: ssd})
        }
    )
}

pub fn create_blind_signing_info (
    spec_create_blind_signing_info : SpecificCreateBlindSigningInfo
) -> CreateBlindSigningInfo {
    Arc::new(
        move |rng_seed, SignerPublicData {signer_public_setup_data,
                                          signer_public_schema,
                                          signer_blinded_attr_idxs: b_idxs },
        blinded_attrs, proof_mode| {
            if proof_mode != TestBackend {
                let mut given_idxs =
                    blinded_attrs
                    .iter()
                    .map(|CredAttrIndexAndDataValue { index, value : _}| *index)
                    .collect::<Vec<_>>();
                given_idxs.sort();
                if given_idxs != *b_idxs {
                    return Err(Error::General(ic_semi(&str_vec_from!(
                        "createBlindSigningInfo",
                        "blinded attributes expected for indices",
                        format!("{:?}", b_idxs),
                        "but received for",
                        format!("{:?}", given_idxs)))))
                }
            }
            spec_create_blind_signing_info(
                rng_seed,
                signer_public_setup_data,
                signer_public_schema,
                blinded_attrs)
        }

    )}

pub fn sign (
    spec_sign : SpecificSign
) -> Sign {
    Arc::new(
        move |rng_seed, vals, sd@(SignerData {signer_public_data, .. }), prf_mode| {
            if prf_mode != TestBackend {
                let pairs = vals
                    .iter()
                    .enumerate()
                    .map(|(index,value)|
                         CredAttrIndexAndDataValue::new(
                             index as CredAttrIndex, value.clone()))
                    .collect::<Vec<_>>();
                check_attr_idxs_and_vals_for_schema(
                    "sign",
                    &signer_public_data.signer_public_schema,
                    pairs.as_slice())?;
            }
            spec_sign(rng_seed, vals, sd)
        }
    )
}


pub fn sign_with_blinded_attributes (
    spec_sign_wba : SpecificSignWithBlindedAttributes
) -> SignWithBlindedAttributes {
    Arc::new(
        move |rng_seed, non_blinded_attrs, bifs, sd, proof_mode| {
            let SignerData {signer_public_data, signer_secret_data } = sd;
            let SignerPublicData {
                signer_public_setup_data,
                signer_public_schema,
                signer_blinded_attr_idxs} = *(*signer_public_data).clone();
            if proof_mode != TestBackend {
                let mut schema_idxs: Vec<CredAttrIndex> =
                    (0..signer_public_schema.len()).map(|x| x as CredAttrIndex).collect();
                let unblinded_idxs: Vec<_> =
                    non_blinded_attrs
                    .iter()
                    .map(|CredAttrIndexAndDataValue { index, value : _ }| *index)
                    .collect();
                let mut all_idxs = unblinded_idxs;
                all_idxs.extend(signer_blinded_attr_idxs.clone());
                all_idxs.sort();
                if all_idxs != schema_idxs {
                    let mut needed_idxs = schema_idxs;
                    needed_idxs.retain(|x| !signer_blinded_attr_idxs.contains(x));
                    return Err(Error::General(ic_semi(&str_vec_from!(
                        "sign_with_blinded_attributes",
                        "expected one value for each unblinded attribute index",
                        format!("{needed_idxs:?}"),
                        "but given",
                        format!("{non_blinded_attrs:?}")))))
                }
            }
            spec_sign_wba(rng_seed,
                          signer_public_schema.as_slice(),
                          non_blinded_attrs,
                          bifs,
                          &signer_public_setup_data,
                          signer_secret_data )
        })
}

pub fn unblind_blinded_signature (
    spec_unblind_blinded_signature : SpecificUnblindBlindedSignature
) -> UnblindBlindedSignature {
    Arc::new(
        move |schema, unblinded_attrs, blinded_sig, blinder, proof_mode| {
            if proof_mode != TestBackend {
                check_attr_idxs_and_vals_for_schema(
                    "unblind_blinded_signature", schema, unblinded_attrs)?;
            }
            spec_unblind_blinded_signature(
                schema,
                unblinded_attrs,
                blinded_sig,
                blinder)
        })
}

fn check_attr_idxs_for_schema (
    s      : &str,
    schema : &[ClaimType],
    idxs   : &[CredAttrIndex]
) -> VCPResult<()> {
    let bad_idxs = idxs
        .iter()
        .filter(|i| **i >= schema.len() as u64)
        .collect::<Vec<_>>();
    if !bad_idxs.is_empty() {
        return Err(Error::General(ic_semi(&str_vec_from!(
            s,
            "attribute index(es) out of range for schema",
            format!("{schema:?}"),
            format!("{bad_idxs:?}")))))
    }
    let mut idxs_1 = idxs.to_vec();
    idxs_1.dedup();
    if idxs_1 != idxs {
        return Err(Error::General(ic_semi(&str_vec_from!(
            s,
            "duplicate attribute index(es)",
            format!("{idxs:?}")))))
    }
    Ok(())
}

fn check_attr_idxs_and_vals_for_schema (
    s      : &str,
    schema : &[ClaimType],
    pairs  : &[CredAttrIndexAndDataValue]
) -> VCPResult<()> {
    let given_idxs = pairs
        .iter()
        .map(|CredAttrIndexAndDataValue { index, value : _ }| *index)
        .collect::<Vec<_>>();
    check_attr_idxs_for_schema(s, schema, given_idxs.as_slice())?;
    for CredAttrIndexAndDataValue { index, value } in pairs {
        let ct = lookup_throw_if_out_of_bounds(
            schema, *index as usize, Error::General,
            &str_vec_from!(
                "check_attr_idxs_and_vals_for_schema",
                "IMPOSSIBLE"))?;
        match (ct, value) {
            (CTEncryptableText,   DVText(_)) => (),
            (CTText,              DVText(_)) => (),
            (CTInt,               DVInt(_))  => (),
            (CTAccumulatorMember, DVText(_)) => (),
            (ct0,                 val0)      => return Err(Error::General(ic_semi(&str_vec_from!(
                "check_attr_idxs_and_vals_for_schema",
                "invalid value",
                format!("{val0:?}"),
                "for claim type",
                format!("{ct0:?}")))))
        }
    };
    Ok(())
}
