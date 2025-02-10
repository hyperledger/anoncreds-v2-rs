// ---------------------------------------------------------------------------
use credx::str_vec_from;
use credx::vcp::{Error, VCPResult};
use credx::vcp::api;
use credx::vcp::crypto_interface::*;
use credx::vcp::r#impl::common::util::*;
// ---------------------------------------------------------------------------
pub use crate::vcp::test_framework::AccumsForSigner;
// ---------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use maplit::hashmap;
use std::collections::HashMap;
use std::sync::Arc;
// ---------------------------------------------------------------------------

// ----------------------------------------------------------------------------

// The utilities below use functions provided by the platform API to implement
// convenient utilities.  They are used by the testing framework and may be
// useful, directly or indirectly, for anyone implementing code that uses the
// platform API.  For example, the create_accumulators utility is used by
// step_create_accumulators_for_issuer to call the create_accumulator_data
// function provided by the platform API once for each attribute of type
// CTAccumulatorMember in an Issuer's schema.

pub fn create_accumulators(f: CreateAccumulatorData) -> CreateAccumulators {
    Arc::new(move |n, sdcts| {
        create_for_accumulator_fields(sdcts, |i| f(n + i))
            .map(|m| {
                m.iter()
                    .map(|(k, CreateAccumulatorResponse { accumulator_data, accumulator })|
                         (*k, (accumulator_data.clone(), accumulator.clone(), hashmap!())))
                    .collect()
            })
    })
}

pub fn accumulator_indexes(sdcts: &[ClaimType]) -> Vec<u64> {
    sdcts
        .iter()
        .enumerate()
        .filter_map(|(i, ct)| {
            if *ct == ClaimType::CTAccumulatorMember {
                Some(i as u64)
            } else {
                None
            }
        })
        .collect()
}

pub fn create_for_accumulator_fields<A>(
    sdcts: &[ClaimType],
    f: impl Fn(CredAttrIndex) -> Result<A, Error>,
) -> Result<HashMap<CredAttrIndex, A>, Error> {
    let accum_idxs = accumulator_indexes(sdcts);
    Ok(HashMap::from_iter(
        accum_idxs
            .into_iter()
            .map(|i| Ok((i, f(i)?)))
            .collect::<VCPResult<Vec<_>>>()?,
    ))
}

// TODO: this is not currently used.  It was translated from the Haskell prototype
// which uses it in another test framework that is not translated (yet?) to Rust
#[allow(dead_code)]
pub fn accumulator_add_remove_with_map(
    accumulator_add_remove: AccumulatorAddRemove,
) -> AccumulatorAddRemoveWithMap {
    Arc::new(move |accs, a_idx, adds, rms| {
        let mut accs = accs.clone();
        let (acc_data_api, orig_acc, upd_info_and_accums) = accs
            .get(&a_idx)
            .ok_or(Error::General("accumulatorAddRemoveInternal".to_string()))?;
        let sn = upd_info_and_accums.len();
        let acc = get_accumulator_from_map()(&accs, a_idx, sn as u64)?;
        let AccumulatorAddRemoveResponse {
            witness_update_info: paui,
            witnesses_for_new: wits,
            accumulator_data: acc_data,
            accumulator: new_accum,
        } = accumulator_add_remove(acc_data_api, &acc, adds, rms)?;
        accs.insert(
            a_idx,
            (acc_data, orig_acc.clone(), {
                let mut upd_info_and_accums = upd_info_and_accums.clone();
                upd_info_and_accums.insert(sn as u64, (paui.clone(), new_accum.clone()));
                upd_info_and_accums
            }),
        );
        Ok(AccumulatorAddRemoveWithMapResponse {
            public_update_info: paui,
            wits_for_new: wits,
            updated_accum_map: accs.clone(),
            updated_accum_value: new_accum,
        })
    })
}

pub fn get_accumulator_from_map() -> GetAccumulatorFromMap {
    Arc::new(move |acc_hdls, idx, sn| {
        let (_, orig_acc, upd_info_and_accums) =
            acc_hdls.get(&idx).ok_or(Error::General(format!(
                "get_accumulator_from_map; missing; {idx}; should be one of; {:?}",
                acc_hdls.keys().collect::<Vec<_>>()
            )))?;
        if sn == 0 {
            Ok(orig_acc.clone())
        } else {
            upd_info_and_accums
                .get(&(sn - 1))
                .map(|(_, acc)| acc.clone())
                .ok_or(Error::General("get_accumulator_from_map".to_string()))
        }
    })
}

pub fn get_accumulator_public_data_from_map() -> GetAccumulatorPublicDataFromMap {
    Arc::new(|acc_hdls, idx| {
        let (AccumulatorData { accumulator_public_data: pub_data, .. }, _, _) =
             acc_hdls.get(&idx).ok_or(Error::General(format!(
                 "get_accumulator_public_data_from_map; missing index; {idx}; should be one of; {:?}",
                 acc_hdls.keys().collect::<Vec<_>>())))?;
        Ok(pub_data.clone())
    })
}

// This is for convenience only, and does not depend on any primitives
// provided by the underlying cryptography library.  It provides the
// highest AccumulatorBatchSeqNo that is at most the queried SeqNo and for
// which a witness is present.

// Thus, if we already have a witness for the given SeqNo, we get back the
// same value.  Otherwise, we receive a lower SeqNo for which we do have a
// witness, enabling fetching the relevant AccumulatorUpdateInfo(s) needed
// to update a previous witness so that we have a witness for the desired
// SeqNo.
//
// Returns an error in case no such index exists, which indicates that EITHER:
//
// * the desired SeqNo is actually before our AccumulatorElement was added
//   to the accumulator (in which case we obviously will be unable to prove
//   membership); OR
//
// * we have "garbage collected" too many old witnesses, in which case it would
//   be necessary to request the original witness (or one for a later SeqNo)
//   from the revocation manager
//
// We don't do anything to enable the above-mentioned "garbage collection" or
// re-requesting a witness at this stage, but this part of the interface
// is designed to accommodate it in future.  In particular, it does not
// assume that all witnesses are retained forever, nor that witnesses are
// retained for a consecutive set of SeqNos.
//
// TODO: consider making it return the witness if available

pub fn get_witness_sequence_number_for_update(
    m: &AllAccumulatorWitnesses,
    a_idx: CredAttrIndex,
    sn: AccumulatorBatchSeqNo
) -> VCPResult<AccumulatorBatchSeqNo> {
    let wits = lookup_throw_if_absent(&a_idx, m, Error::General,
                                      &str_vec_from!("getWitnessSequenceNumberForUpdate",
                                                     "no witnesses for attribute index"))?;
    match wits.get(&sn) {
        Some(_) => Ok(sn),
        None => match wits
            .range(..sn)
            .map(|(n, _)| n)
            .max() {
                // TODO: This suggests that verb-throw-if-adjective things might be refactored to
                // use a common throw-if-none, which could be used here too.
                None => Err(Error::General(format!(
                    concat!("getWitnessSequenceNumberForUpdate; ",
                            "no witnesses available at or before sequence number {}; ",
                            "for attribute index {}"), sn, a_idx))),
                Some(prev_sn) => Ok(*prev_sn)
            }
        }
}

pub fn update_accumulator_witness_with_map(
    platform_api: &api::PlatformApi,
    wits_api: &mut AllAccumulatorWitnesses,
    a_idx: CredAttrIndex,
    vals: &[DataValue],
    adui_api: &AccumulatorWitnessUpdateInfo,
    sn: AccumulatorBatchSeqNo
) -> VCPResult<()> {
    let prim_upd_wit = platform_api.update_accumulator_witness.clone();
    let create_elt = platform_api.create_accumulator_element.clone();
    let wits =
        lookup_throw_if_absent_mut(&a_idx, wits_api, Error::General,
                                   &str_vec_from!("updateAccumWitnessesAndValues",
                                              "no witnesses for attribute index"))?;
    let wit = lookup_throw_if_absent(&sn, wits, Error::General,
                                     &str_vec_from!("updateAccumWitnessesAndValues",
                                                    "witness not found for sequence number"))?;
    // TODO: lookup_throw_if_out_of_bounds
    let val = vals.get(a_idx as usize).ok_or(Error::General(format!(
        "update_accumulator_witness_with_map; out of range; {a_idx}; {vals:?}"
    )))?;
    let t = get_text_from_value(val)?;
    let elt = create_elt(t)?;
    let wit_ = prim_upd_wit(wit, &elt, adui_api)?;
    wits.insert(sn+1, wit_);
    Ok(())
}

pub type CreateAccumulators = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[ClaimType],
    ) -> VCPResult<AccumsForSigner>
        + Send
        + Sync,
>;

pub type AccumulatorAddRemoveWithMap = Arc<
    dyn Fn(
            &AccumsForSigner,
            CredAttrIndex,
            &HashMap<HolderID, AccumulatorElement>,
            &[AccumulatorElement],
        ) -> VCPResult<AccumulatorAddRemoveWithMapResponse>
        + Send
        + Sync,
>;

pub type GetAccumulatorFromMap = Arc<
    dyn Fn(&AccumsForSigner, CredAttrIndex, AccumulatorBatchSeqNo) -> VCPResult<Accumulator>
        + Send
        + Sync,
>;

pub type GetAccumulatorPublicDataFromMap = Arc<
    dyn Fn(&AccumsForSigner, CredAttrIndex) -> VCPResult<AccumulatorPublicData>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorAddRemoveWithMapResponse {
    pub public_update_info: AccumulatorWitnessUpdateInfo,
    pub wits_for_new: HashMap<HolderID, AccumulatorMembershipWitness>,
    pub updated_accum_map: AccumsForSigner,
    pub updated_accum_value: Accumulator,
}

