// -----------------------------------------------------------------------------
use credx::str_vec_from;
use credx::vcp::{Error, VCPResult};
use credx::vcp::api;
use credx::vcp::r#impl::general::presentation_request_setup::get_proof_instructions;
use credx::vcp::r#impl::json::shared_params::put_shared_one;
use credx::vcp::r#impl::json::util::encode_to_text;
use credx::vcp::r#impl::util::*;
use credx::vcp::interfaces::primitives::ProofInstructionGeneral;
use credx::vcp::interfaces::primitives::types::*;
use credx::vcp::interfaces::types::ClaimType::*;
use credx::vcp::interfaces::types::DataValue::*;
// -----------------------------------------------------------------------------
use crate::vcp::r#impl::general::testing_framework::*;
use crate::vcp::r#impl::general::testing_framework::PerturbDecryptedValue::*;
use crate::vcp::r#impl::general::utility_functions as tuf;
// -----------------------------------------------------------------------------
use maplit::hashmap;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
// -----------------------------------------------------------------------------

pub fn step_create_issuer(
    platform_api: &api::PlatformApi,
    i_lbl: IssuerLabel,
    schema: Vec<api::ClaimType>,
) -> AddTestStep {
    let create_signer_data = platform_api.create_signer_data.clone();
    Arc::new(move |ts| {
        pprintln("step_create_issuer", &format!("{:#?}", &ts));
        let asd0 = &mut ts.all_signer_data;
        let sp0  = &mut ts.sparms;
        // Check that issuer label is new
        if asd0.get(&i_lbl).is_some() {
            return Err(Error::General(ic_semi(&str_vec_from!(
                "step_create_issuer", "Duplicate issuer label", format!("{i_lbl}")))));
        }
        // asd0.len creates SignerData with a different RNG seed so it differs from previous ones
        let sd = (*create_signer_data)(asd0.len() as u64, &schema)?;
        let spd = &sd.signer_public_data;

        // update test state
        sp0.insert(
            i_lbl.clone(),
            api::SharedParamValue::SPVOne(api::DataValue::DVText(encode_to_text(&spd)?)),
        );
        asd0.insert(i_lbl.clone(), sd);
        Ok(())
    })
}

pub fn step_create_accumulators_for_issuer(
    platform_api: &api::PlatformApi,
    i_lbl: IssuerLabel,
) -> AddTestStep {
    let create_accumulators = tuf::create_accumulators(platform_api.create_accumulator_data.clone());
    Arc::new(move |ts| {
        pprintln(
            "step",
            &format!("step_create_accumulators_for_issuer\n{:#?}", &ts),
        );
        let spd = &ts
            .all_signer_data
            .get(&i_lbl)
            .ok_or(Error::General(ic_semi(&str_vec_from!(
                "step_create_accumulators_for_issuer", "no such Issuer"))))?
            .signer_public_data;
        let schema = &spd.signer_public_schema;
        // TODO: ensure different RNG seeds for different revocation managers
        let accs = create_accumulators(0, schema)?;
        if ts.accums.contains_key(spd) {
            return Err(Error::General(ic_semi(&str_vec_from!(
                "step_create_accumulators_for_issuer", "accumulators already exist for",
                format!("{i_lbl}")))));
        };
        // Create map of accumulators, each with empty PublicAccumulatorUpdateInfo
        ts.accums.insert(
            spd.deref().clone(),
            accs
        );
        Ok(())
    })
}

pub fn step_sign_credential(
    platform_api: &api::PlatformApi,
    i_lbl: IssuerLabel,
    h_lbl: HolderLabel,
    vals: Vec<api::DataValue>,
) -> AddTestStep {
    let sign = platform_api.sign.clone();
    Arc::new(move |ts| {
        pprintln("step_sign_credential", &format!("{:#?}", &ts));
        let sards0 = &mut ts.sigs_and_rel_data;
        match sards0.get(&h_lbl) {
            None => {}
            Some(h_sards) => {
                if h_sards.get(&i_lbl).is_some() {
                    return Err(Error::General(ic_semi(&str_vec_from!(
                        "A credential signed by", format!("{i_lbl}"), "already exists"))));
                }
            }
        }
        let h_sards = match sards0.get_mut(&h_lbl) {
            None => {
                sards0.insert(h_lbl.clone(), hashmap!());
                sards0.get_mut(&h_lbl).unwrap()
            }
            Some(h_sards) => h_sards,
        };
        let asd0 = &ts.all_signer_data;
        let preqs0 = &mut ts.preqs;
        // let h_pres0_default = &mut hashmap!();
        if preqs0.get(&h_lbl).is_none() {
            preqs0.insert(h_lbl.clone(), hashmap!());
        }
        let h_pres0 = preqs0.get_mut(&h_lbl).unwrap();
        // Get issuer SignerData
        let sd = asd0.get(&i_lbl).ok_or(Error::General(
            "stepSignCredential; Issuer has not been created".to_string(),
        ))?;
        // sign credential
        let sig = sign(0, &vals, sd)?;
        // This models the Issuer sending the signature to the Holder, which stores it along with
        // empty CredentialAuxiliaryData (e.g., it has not yet received its accumulator witness(es),
        // associating this with the IssuerLabvel, which is the same as the CredentialLabel.
        h_pres0.insert(i_lbl.clone(), new_credential_reqs(i_lbl.clone()));
        h_sards.insert(
            i_lbl.clone(),
            api::SignatureAndRelatedData {
                signature: sig,
                values: vals.clone(),
                accum_wits: hashmap!(),
            },
        );
        Ok(())
    })
}

pub fn step_accumulator_add_remove(
    platform_api: &api::PlatformApi,
    i_lbl: IssuerLabel,
    a_idx: api::CredAttrIndex,
    adds: HashMap<HolderLabel, api::DataValue>,
    removes: Vec<api::DataValue>,
) -> AddTestStep {
    let accumulator_add_remove = platform_api.accumulator_add_remove.clone();
    let create_accumulator_element = platform_api.create_accumulator_element.clone();

    let convert_to_accum_elt = move |dv: &api::DataValue| -> VCPResult<api::AccumulatorElement> {
        get_text_from_value(dv).and_then(|s| create_accumulator_element(s))
    };

    let i_lbl_clone = i_lbl.clone();
    let populate_holder_wits =
        move |sn: api::AccumulatorBatchSeqNo,
              h_wits: &mut HolderAllWitnesses,
              (api::HolderID(h_lbl), mw): (api::HolderID, api::AccumulatorMembershipWitness)|
                                           -> VCPResult<()> {
                  let l1 = h_wits.entry(h_lbl.clone()).or_default();
                  let l2 = l1.entry(i_lbl.clone()).or_default();
                  let l3 = l2.entry(a_idx).or_default();
                  insert_throw_if_present(
                      sn, mw, l3,
                      Error::General, &str_vec_from!(
                          "populate_holder_wits", "witness_already_present",
                          format!("{h_lbl}; {i_lbl}; {a_idx}; sn={sn}")))?;
                  Ok(())
              };

    Arc::new(move |ts| {
        pprintln("step_accumulator_add_remove", &format!("{:#?}", &ts));
        let spd = &ts
            .all_signer_data
            .get(&i_lbl_clone)
            .ok_or(Error::General(
                "step_accumulator_add_remove; no such Issuer".to_string(),
            ))?
            .signer_public_data;
        let accs = ts.accums.get_mut(spd).ok_or(Error::General(
            "step_accumulator_add_remove; accumulators not created for Issuer".to_string(),
        ))?;
        let (acc_data, orig_accum, upd_info_and_accums) = accs.get(&a_idx).ok_or(Error::General(
            "step_accumulator_add_remove; no accumulator found".to_string(),
        ))?;
        // The sequence number is the number of previous updates
        // since the original accumulator was created
        let sn = upd_info_and_accums.len() as u64;
        // If sn == 0, i is not used, so saturating is ok
        let i = sn.saturating_sub(1);
        let acc_val = {
            if sn == 0 { orig_accum }
            else {
                let (_,v) = lookup_throw_if_absent(
                    &i,upd_info_and_accums,Error::General,
                    // This assumes that Revocation Managers never "garbage collect" update
                    // information and accumulators; if that is ever done in future, this
                    // error message should change, and also we'll need to track the
                    // maximum sequence number (as opposed to using M.size above).
                    &str_vec_from!("step_accumulator_add_remove", "INTERNAL ERROR"))?;
                v
            }
        };
        // In reality, the Issuer would use getAccumulatorElement
        // to get the AccumulatorElements to pass to accumulatorAddRemove.
        // Here we compute it as part of the step.
        let adds_with_acc_elts = adds
            .clone()
            .into_iter()
            .map(|(k, dv)| -> VCPResult<_> { Ok((k, convert_to_accum_elt(&dv)?)) })
            .collect::<VCPResult<HashMap<HolderLabel, api::AccumulatorElement>>>()?;
        let rems_with_acc_elts = removes
            .clone()
            .into_iter()
            .map(|dv| convert_to_accum_elt(&dv))
            .collect::<VCPResult<Vec<api::AccumulatorElement>>>()?;
        let api::AccumulatorAddRemoveResponse {
            witness_update_info: awui,
            wits_for_new: wits_for_adds,
            updated_accum_data: updated_acc_data,
            updated_accum_value: updated_acc_val,
        } = accumulator_add_remove(
            acc_data,
            acc_val,
            &adds_with_acc_elts
                .into_iter()
                .map(|(k, v)| (api::HolderID(k), v))
                .collect(),
            &rems_with_acc_elts,
        )?;
        // Store AccumWitnessUpdateInfo in map
        let accs = {
            let mut upd_info_and_accums = upd_info_and_accums.clone();
            upd_info_and_accums.insert(sn, (awui, updated_acc_val));
            let mut accs = accs.clone();
            accs.insert(a_idx, (updated_acc_data, orig_accum.clone(), upd_info_and_accums));
            accs
        };
        ts.accums.insert(spd.as_ref().clone(), accs);
        for (holder_id, mem_wit) in wits_for_adds.iter() {
        // Similarly to above, in reality, new witnesses would be sent to the respective
        // Holders (using the HolderIDs), who would add them to their SigsAndRelatedData,
        // but for expedience we add them directly in the TestState
        // Because we have now done one more update, holders associate their new witness with sn + 1
            let _ = populate_holder_wits(sn + 1, &mut ts.accum_witnesses, (holder_id.clone(), mem_wit.clone()));
        };
        Ok(())
    })
}

pub fn step_receive_initial_accumulator_witness(
    _platform_api: &api::PlatformApi,
    _h_lbl: HolderLabel,
    _i_lbl: IssuerLabel,
    _a_idx: api::CredAttrIndex,
) -> AddTestStep {
    unimplemented!("step_receive_initial_accumulator_witness")
}

pub fn step_reveal(
    _platform_api: &api::PlatformApi,
    h_lbl: HolderLabel,
    i_lbl: String,
    idxs: Vec<api::CredAttrIndex>,
) -> AddTestStep {
    Arc::new(move |ts| {
        pprintln("step_reveal", &format!("{:#?}", &ts));
        let err_msg = format!(
            "step_reveal; no credentials signed for holder; h_lbl={h_lbl}; i_lbl={i_lbl}; ts.preqs={:?}",
            &ts.preqs
        );
        let crs = ts
            .preqs
            .get_mut(&h_lbl)
            .ok_or_else(|| Error::General(err_msg.clone()))?
            .get_mut(&i_lbl)
            .ok_or_else(|| Error::General(err_msg))?;
        // Deliberately no ordering or eliminating dups, so we can test underlying libraries
        let api::Disclosed(ix0) = crs.disclosed.clone();
        crs.disclosed = api::Disclosed([ix0, idxs.clone()].concat());
        Ok(())
    })
}

pub fn step_in_range(
    platform_api: &api::PlatformApi,
    h_lbl: HolderLabel,
    i_lbl: String,
    a_idx: api::CredAttrIndex,
    min_v: u64,
    max_v: u64
) -> AddTestStep {
    let create_range_proof_proving_key = platform_api.create_range_proof_proving_key.clone();
    Arc::new(move |ts| {
        // Including min and max values in labels enables different ranges for the same attribute
        let range_min_val_sp_label =
            ic_semi(&str_vec_from!("rangeMinValueFor", format!("{i_lbl}"), format!("{a_idx}")));
        let range_max_val_sp_label =
            ic_semi(&str_vec_from!("rangeMaxValueFor", format!("{i_lbl}"), format!("{a_idx}")));
        let range_prv_key_sp_label =
            "singleRangeProvingKey".to_string();
        let err_msg = format!(
            "step_in_range; no credentials signed for holder; h_lbl={h_lbl}; i_lbl={i_lbl}"
        );
        let cred_reqs = ts
            .preqs
            .get_mut(&h_lbl)
            .ok_or(Error::General(err_msg.clone()))?
            .get_mut(&i_lbl)
            .ok_or(Error::General(err_msg))?;
        cred_reqs.in_range.0.insert(
            0,
            api::InRangeInfo {
                index: a_idx,
                min_label: range_min_val_sp_label.clone(),
                max_label: range_max_val_sp_label.clone(),
                proving_key_label: range_prv_key_sp_label.clone(),
            },
        );
        // Add RangeProvingKey to SharedParams if not already present
        let sp1 = match &ts
            .sparms
            // We use only one range proving key for testing,
            // so create and add one only if not already present.
            .get(&range_prv_key_sp_label)
        {
            Some(_) => Ok(&mut ts.sparms),
            None => {
                let range_prv_key = create_range_proof_proving_key(0)?;
                ts.sparms.insert(
                    range_prv_key_sp_label.clone(),
                    api::SharedParamValue::SPVOne(api::DataValue::DVText(encode_to_text(
                        &range_prv_key)?)));
                Ok(&mut ts.sparms)
            }
        }?;
        sp1.insert(
            range_min_val_sp_label,
            api::SharedParamValue::SPVOne(api::DataValue::DVInt(min_v)));
        sp1.insert(
            range_max_val_sp_label,
            api::SharedParamValue::SPVOne(api::DataValue::DVInt(max_v)));
        Ok(())
    })
}

pub fn step_in_accum(
    platform_api: &api::PlatformApi,
    h_lbl: HolderLabel,
    i_lbl: IssuerLabel,
    a_idx: api::CredAttrIndex,
    sn: api::AccumulatorBatchSeqNo,
) -> AddTestStep {
    let create_membership_proving_key = platform_api.create_membership_proving_key.clone();
    let get_accumulator_public_data_from_map = tuf::get_accumulator_public_data_from_map().clone();
    let get_accumulator_from_map = tuf::get_accumulator_from_map().clone();
    Arc::new(move |ts| {
        pprintln("step_in_accum", &format!("{:#?}", &ts));
        let membership_proving_key_sp_label = "SingleMembershipProvingKey".to_string();
        let acc_pub_data_sp_key = ic_semi(&str_vec_from!(
            "accPubDataFor", format!("{i_lbl}"), format!("{a_idx}")));
        // HolderID is included in SharedParamLabels to avoid needing per-holder SharedParams
        let acc_val_sp_key = ic_semi(&str_vec_from!(
            "accValueFor", format!("{i_lbl}"), format!("{h_lbl}"), format!("{a_idx}")));
        let acc_sn_sp_key = ic_semi(&str_vec_from!(
            "accumSeqNoFor", format!("{i_lbl}"), format!("{h_lbl}"), format!("{a_idx}")));
        let cred_reqs = ts
            .preqs
            .get_mut(&h_lbl)
            .ok_or(Error::General(ic_semi(&str_vec_from!(
                "step_in_accum", "no credentials signed for holder",
                format!("{h_lbl}")))))?
            .get_mut(&i_lbl)
            .ok_or(Error::General(ic_semi(&str_vec_from!(
                "step_in_accum", "no credentials signed for holder",
                format!("{h_lbl}"), "issuer", format!("{i_lbl}")))))?;
        cred_reqs.in_accum.0.insert(
            0,
            api::InAccumInfo {
                index: a_idx,
                public_data_label: acc_pub_data_sp_key.clone(),
                mem_prv_label: membership_proving_key_sp_label.clone(),
                accumulator_label: acc_val_sp_key.clone(),
                accumulator_seq_no_label: acc_sn_sp_key.clone(),
            },
        );

        // Add MembershipProvingKey if not already present
        let sp1 = match &ts
            .sparms
            // We use only one membership proving key for testing,
            // so create and add one only if not already present.
            .get(&membership_proving_key_sp_label)
        {
            Some(_) => Ok(&mut ts.sparms),
            None => {
                let acc_prv_key = create_membership_proving_key(0)?;
                ts.sparms.insert(
                    membership_proving_key_sp_label,
                    api::SharedParamValue::SPVOne(api::DataValue::DVText(encode_to_text(
                        &acc_prv_key)?)));
                Ok(&mut ts.sparms)
            }
        }?;
        // Get Issuer's SignerPublicData
        let spd = ts
            .all_signer_data
            .get(&i_lbl)
            .ok_or(Error::General("step_in_accum; SignerPublicData".to_string()))?
            .signer_public_data
            .as_ref();
        // Use it to look up Accums
        let accums_for_signer = &ts
            .accums
            .get(spd)
            .ok_or(Error::General("step_in_accum; AccumulatorData".to_string()))?;
        let acc_pub_api = get_accumulator_public_data_from_map(accums_for_signer,a_idx).unwrap();
        // Add accumulator public data and current value
        let acc_val_api = get_accumulator_from_map(accums_for_signer,a_idx,sn).unwrap();
        sp1.insert(
            acc_pub_data_sp_key,
            api::SharedParamValue::SPVOne(api::DataValue::DVText(encode_to_text(&acc_pub_api)?)));
        sp1.insert(
            acc_val_sp_key,
            api::SharedParamValue::SPVOne(api::DataValue::DVText(encode_to_text(&acc_val_api)?)));
        sp1.insert(
            acc_sn_sp_key,
            api::SharedParamValue::SPVOne(api::DataValue::DVInt(sn)));
        Ok(())
    })
}

pub fn step_equality(
    h_lbl: HolderLabel,
    i_lbl: IssuerLabel,
    a_idx: api::CredAttrIndex,
    eqs: Vec<(IssuerLabel, api::CredAttrIndex)>,
) -> AddTestStep {
    Arc::new(move |ts| {
        pprintln("step_equality", &format!("{:#?}", &ts));
        let cred_reqs = ts
            .preqs
            .get_mut(&h_lbl)
            .ok_or(Error::General(ic_semi(&str_vec_from!(
                "step_equality", "missing holder", format!("{h_lbl}")))))?
            .get_mut(&i_lbl)
            .ok_or(Error::General(ic_semi(&str_vec_from!(
                "step_equality", "holder", format!("{h_lbl}"),
                "missing issuer", format!("{i_lbl}")))))?;
        cred_reqs.equal_to.0.append(
            &mut eqs
                .iter()
                .map(|(i_lbl, cai)| api::EqInfo {
                    from_index: a_idx,
                    to_label: i_lbl.clone(),
                    to_index: *cai,
                })
                .collect());
        Ok(())
    })
}

pub fn step_create_and_verify_proof(
    platform_api: &api::PlatformApi,
    h_lbl: HolderLabel,
    test_exp: CreateVerifyExpectation,
) -> AddTestStep {
    use step_create_and_verify_proof_support::*;
    let create_proof = platform_api.create_proof.clone();
    let verify_proof = platform_api.verify_proof.clone();
    Arc::new(move |ts| {
        pprintln("step_create_and_verify_proof", &format!("{:#?}", &ts));
        let proof_reqs = ts.preqs.get(&h_lbl).ok_or(Error::General(format!(
            "step_create_and_verify_proof; no credentials signed for holder; h_lbl={h_lbl}")))?;
        let all_sigs_and_rd = ts
            .sigs_and_rel_data
            .get(&h_lbl)
            .ok_or(Error::General(format!(
                "step_create_and_verify_proof; no credentials signed for holder; h_lbl={h_lbl}")))?;
        let shared_params = &ts.sparms; // TODO: Holder-specific?

        // populate accum witnesses

        // The holder has to get the accumulator witnesses for the InAccum requests
        // and put them into the map in sigsAndRD (which has an empty map for accumulator witnesses).
        // First, find out what's requested.
        let all_wits: HashMap<IssuerLabelAsCredentialLabel,api::AllAccumulatorWitnesses> =
            ts.accum_witnesses.get(&h_lbl).cloned().unwrap_or_default();

        // We don't need to request revealing any attributes for getting ProofInstructions
        // for InAccum requirements.
        // But we do need to provide a map for each CredentialLabel
        // because Proof.getValsToReveal uses mergeMaps and is therefore arguably too inflexible.
        let to_reveal: HashMap<CredentialLabel,HashMap<CredAttrIndex,DataValue>> =
            proof_reqs
            .keys()
            .map(|k| (k.clone(),HashMap::new()))
            .collect();

        let witness_reqs = get_proof_instructions(shared_params, proof_reqs, &to_reveal)?;

        // collect all attributeIndex/sequenceNumber pairs,
        // together for each credential label
        let witness_reqs : Vec<(CredentialLabel,(CredAttrIndex,AccumulatorBatchSeqNo))> = witness_reqs
            .into_iter()
            .filter_map(|x| { match x {
                ProofInstructionGeneral {
                    cred_label       : c_lbl,
                    attr_idx_general : a_idx,
                    discl_general    : ResolvedDisclosure::InAccumResolvedWrapper
                        (InAccumResolved {
                            public_data : _,
                            mem_prv     : _,
                            accumulator : _,
                            seq_num     : sn
                        }),
                    ..
                } => {Some((c_lbl, (a_idx, sn)))},
                _ => None,
            }})
            .collect();

        // for each credential mentioned in proof request
        // get SignatureAndRelatedData (with no accumulator witnesses, so far)
        let mut sigs_and_rd =
            proof_reqs
            .keys()
            .map(|c_lbl| { all_sigs_and_rd
                           .get(c_lbl)
                           .ok_or_else(|| Error::General(ic_semi(&str_vec_from!(
                               "step_create_and_verify_proof",
                               format!("{h_lbl}"),
                               "does not have a signed credential from",
                               format!("{c_lbl}")))))
                           .map(|sard| (c_lbl.clone(), sard.clone()))})
            .collect::<Result<HashMap<CredentialLabel,SignatureAndRelatedData>,Error>>()?;

        // For each witness required, look it up and insert it into the correct SignaturesAndRelatedData
        let res_w = witness_reqs
            .into_iter()
            .map(|(c_lbl,(a_idx,sn))| {
                match sigs_and_rd.get_mut(&c_lbl) {
                    // This is an INTERNAL (testing framework) error because we've already
                    // looked up all signatures for credentials required by proof_reqs, and
                    // witness_reqs are derived from proof_reqs
                    None => panic!("{}", format!(
                        "step_create_and_verify_proof; INTERNAL ERROR: {c_lbl} missing from sigs_and_rd")),
                    Some(sard) => {
                        match all_wits
                            .get(&c_lbl).cloned().unwrap_or_default()
                            .get(&a_idx).cloned().unwrap_or_default()
                            .get(&sn) {
                                None =>
                                // This is a USER error: the holder (h_lbl) does not have the
                                // necessary witness presumably because they have failed to update
                                // their witnesses to ensure that they have one for the specifcied
                                // seqiuence number
                                    Err(Error::General(ic_semi(&str_vec_from!(
                                        "step_create_and_verify_proof",
                                        format!("{h_lbl}"),
                                        "has no witness for",
                                        format!("{c_lbl}"), format!("{a_idx}"), format!("{sn}"))))),
                                Some (wit) => {
                                    Ok(sard.accum_wits.insert(a_idx,wit.clone()))}}}}})
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>,_>>();
        // No `?` here because we want to check if the error (if any) is compatible with the test
        // expectation.  For example, if the test requests a membership witness for a sequence
        // number that the holder doesn't have, and expects failure, we want to see that the proof
        // fails, so the test succeeds.  We would also like to report the error we have captured in
        // case create_proof unexpectedly succeeds (which would be a bug of the underlying crypto
        // library).

        // Complicating matters further, the underlying library may panic and not throw an error, as
        // is the case with AC2C, which currently panics with 'IndexMap: key not found',
        // src/presentation/create.rs:111:26 in the missing witness case.

        // For now, we just print out the following error and let create_proof run; this is not a satisfactory solution
        // for example, this does not print out unless -- --nocapture is used.
        if let Err(e) = res_w {
            println!("step_create_and_verify_proof; create_proof should fail as not all required membership witnesses have been provided: {:?}",e)
        }

        // Uncomment and run with: cargo test vcp::r#impl::general::proof_system::direct::tests::test_001_reveal_metadata_from_two_credentials_equality_for_two_attributes -- --nocapture
        // poor_persons_test_get_value_for(ts);

        let res_p = create_proof(
            proof_reqs,
            shared_params,
            &sigs_and_rd,
            None,
        );
        let wadfv = match res_p {
            Ok(wadfv) => wadfv,
            Err(Error::CredxError(e)) => {
                if [CreateVerifyExpectation::CreateProofFails,
                    CreateVerifyExpectation::CreateOrVerifyFails
                ].contains(&test_exp) {
                    return Ok(());
                } else {
                    return Err(Error::General(format!("step_create_and_verify_proof; create_proof expected to succeed, but failed; {e:?}")));
                }
            },
            // This catches all errors we're not expecting, including panics from the library
            Err(e) => return Err(e)
        };
        let create_warns = &wadfv.warnings;
        let dfv = &wadfv.result;
        let d_reqs = ts.decrypt_requests.get(&h_lbl).cloned().unwrap_or_default();
        let res_v = verify_proof(
            proof_reqs,
            shared_params,
            dfv,
            &d_reqs,
            None,
        );
        let api::WarningsAndDecryptResponses { statement_warnings : verify_warns,
                                               decrypt_responses } = match res_v {
            Err(e) => {
                if [CreateVerifyExpectation::VerifyProofFails,
                    CreateVerifyExpectation::CreateOrVerifyFails,
                ].contains(&test_exp) {
                    return Ok(());
                } else {
                    return Err(Error::General(format!(
                        "step_create_verify_proof; verify_proof expected to succeed, but failed; {e:?}")));
                }
            }
            Ok(wadr) => wadr,
        };

        match test_exp {
            CreateVerifyExpectation::CreateProofFails => {
                Err(Error::General(
                    "step_create_and_verify_proof; create_proof expected to fail, but succeeded"
                        .to_string(),
                ))
            }
            CreateVerifyExpectation::VerifyProofFails => {
                 Err(Error::General(
                    "step_create_and_verify_proof; verify_proof expected to fail, but succeeded"
                        .to_string(),
                ))
            }
            CreateVerifyExpectation::CreateOrVerifyFails => {
                 Err(Error::General(
                    "step_create_and_verify_proof; create_proof or verify_proof expected to fail, but succeeded"
                        .to_string(),
                ))
            },
            CreateVerifyExpectation::BothSucceedNoWarnings => {
                if !create_warns.is_empty() || !verify_warns.is_empty() {
                    return Err(Error::General(
                        format!("step_create_and_verify_proof; expected no warnings, got; {create_warns:?}; {verify_warns:?}")))
                }
                validate_disclosed_values(
                    proof_reqs,
                    &dfv.revealed_idxs_and_vals,
                    &h_lbl,
                    ts)?;
                // Check that decrypted values are correct
                validate_decrypt_responses(
                    &decrypt_responses,
                    &h_lbl,
                    ts)?;
                ts.warnings_and_data_for_verifier = wadfv;
                ts.verification_warnings = verify_warns.to_vec();
                let _ = ts.last_decrypt_responses.insert(h_lbl.to_owned(),decrypt_responses);
                Ok(())
            }
        }
    })
}

mod step_create_and_verify_proof_support {
    use super::*;

    fn validate_values(
        ctxt: &String,
        reqs: &HashMap<CredentialLabel,Vec<CredAttrIndex>>,
        vals: &HashMap<CredentialLabel,HashMap<CredAttrIndex,DataValue>>,
        h_lbl: &HolderLabel,
        ts: &TestState
    ) -> VCPResult<()> {
        // Confirm number of vals same as number of reqs for each credential
        let num_reqs_per_cred = reqs.iter().map(|(c_lbl,l)| (c_lbl.clone(),l.len()))
            .collect::<HashMap<_,_>>();
        let num_vals_per_cred = vals.iter().map(|(c_lbl,m)| (c_lbl.clone(),m.values().len()))
            .collect::<HashMap<_,_>>();
        if num_reqs_per_cred != num_vals_per_cred {
            return Err(Error::General(ic_semi(&str_vec_from!("step_create_and_verify_proof_support",
                                                             "validate_values", ctxt,
                                                             "number of responses per credential",
                                                             format!("{num_reqs_per_cred:?}"),
                                                             "inconsistent with number of response values per credential",
                                                             format!("{num_vals_per_cred:?}")))))
        };

        // Check that all values received are consistent with values signed in credentials
        let sards = lookup_throw_if_absent(h_lbl, &ts.sigs_and_rel_data, Error::General,
                                           &str_vec_from!("step_create_and_verify_proof_support",
                                                          "validate_values",
                                                          "Holder not found"))?;
        for (c_lbl, m1) in vals {
            for (a_idx, val) in m1 {
                let vals_in_cred = lookup_throw_if_absent(c_lbl, sards, Error::General,
                                                          &str_vec_from!("step_create_and_verify_proof_support",
                                                                         "validate_values",
                                                                         "no signature found for credental"))?
                    .values.clone();
                let correct_val = lookup_throw_if_out_of_bounds(&vals_in_cred, *a_idx as usize, Error::General,
                                                                &str_vec_from!("step_create_and_verify_proof_support",
                                                                               "validate_values"))?;
                if val != correct_val {
                    return Err(Error::General(ic_semi(
                        &str_vec_from!("step_create_and_verify_proof_support",
                                       "values don't match",
                                       c_lbl, a_idx, "expected", correct_val, "received", val))))
                }
            }
        };
        Ok(())
    }

    pub fn validate_disclosed_values (
        proof_reqs: &HashMap<CredentialLabel,CredentialReqs>,
        vals: &HashMap<CredentialLabel,HashMap<CredAttrIndex,DataValue>>,
        h_lbl: &HolderLabel,
        ts: &TestState
    ) -> VCPResult<()> {
        validate_values(&"disclosed".to_string(),
                        &proof_reqs
                        .iter()
                        .map(move |(cl,cr)| (cl.clone(),cr.disclosed.0.clone()))
                        .collect::<HashMap<_,_>>(),
                        vals,
                        h_lbl,
                        ts)
    }

    fn ensure_consistent(l:Vec<DecryptResponse>) -> VCPResult<DataValue> {
        let mut all_vals = l
            .iter()
            .map(|DecryptResponse {value,..}| value.clone())
            .collect::<Vec<String>>();
        // Remove duplicates so that, if there is only one value represented in the
        // list, then ther list becomes one item, which we check next to confirm there
        // are no inconsistent values.
        all_vals.dedup();
        if all_vals.len() != 1 {
            return Err(Error::General(
                ic_semi(&str_vec_from!(
                    "inconsistent decrypted values for same attribute",
                    // We cannot indicate which attribute of which credential here
                    format!("{all_vals:?}")))))
        };
        match all_vals.as_slice() {
                [ unique_value ] => Ok(DVText(unique_value.to_string())),
                _ => Err(Error::General(ic_semi(&str_vec_from!("ensure_consistent", "IMPOSSIBLE"))))
        }
    }

    pub fn validate_decrypt_responses (
        d_resps: &HashMap<CredentialLabel,HashMap<CredAttrIndex,HashMap<AuthorityLabel,DecryptResponse>>>,
        h_lbl0: &HolderLabel,
        ts0: &TestState
    ) -> VCPResult<()> {
        let dreqs_for_holder = ts0.decrypt_requests.get(h_lbl0).cloned().unwrap_or_default();
        let vals =
            map_2_lvl_with_err(
                |m| ensure_consistent(m.values()
                                      .cloned()
                                      .collect::<Vec<DecryptResponse>>()),
                d_resps).
            // map the error to show the DecryptResponses, but without the proofs
            map_err(|e| Error::General(format!("{e:?}, {:?}",
                                               map_3_lvl(|DecryptResponse {value,..}| value, d_resps))))?;
        validate_values(&"decrypted".to_string(),
                        &dreqs_for_holder
                        .iter()
                        .map(|(k,m)| (k.clone(),m.keys().copied().collect::<Vec<_>>()))
                        .collect::<Vec<(CredentialLabel,_)>>()
                        .into_iter()
                        .collect::<HashMap<CredentialLabel,Vec<CredAttrIndex>>>(),
                        &vals,
                        h_lbl0,
                        ts0)
    }

}

pub fn step_update_accumulator_witness(
    platform_api: &api::PlatformApi,
    h_lbl: HolderLabel,
    i_lbl: String,
    a_idx: u64,
    sn: u64,
) -> AddTestStep {
    let platform_api = platform_api.clone();
    Arc::new(move |ts| {
        let SignerData{signer_public_data: spd,..} =
            lookup_throw_if_absent(&i_lbl,&ts.all_signer_data,Error::General,
                                   &str_vec_from!("step_update_accumulator_witness",
                                                  r#"issuer does not exist, so there are "
                                                  "no accumulators associated with it"#
                                   ))?;
        let accs_for_signer =
            lookup_throw_if_absent(&**spd,&ts.accums,Error::General,
                                   &str_vec_from!("step_update_accumulator_witness",
                                                  "issuer exists",
                                                  i_lbl,
                                                  "but no accumulators are associated with its public data"
                                   ))?;
        let SignatureAndRelatedData{values: vals,..} =
            lookup_throw_if_absent_2_lvl(&h_lbl, &i_lbl, &ts.sigs_and_rel_data, Error::General,
                                   &str_vec_from!("step_update_accumulator_witness",
                                                  "no signature and related data found"
                                   ))?;
        let aw0 = &mut ts.accum_witnesses;
        let holder_wits =
            lookup_throw_if_absent_mut(&h_lbl, aw0, Error::General,
                                       &str_vec_from!("step_update_accumulator_witness",
                                                      "no existing witnesses available to update",
                                                      "has any credential been signed for this holder?"
                                       ))?;
        let wits_for_cred: &mut AllAccumulatorWitnesses =
            lookup_throw_if_absent_mut(&i_lbl, holder_wits, Error::General,
                                       &str_vec_from!("step_update_accumulator_witness",
                                                      "no existing witnesses available to update",
                                                      "has a credential been signed by this issuer for holder"
                                       ))?;
        let prev_seq_no = tuf::get_witness_sequence_number_for_update(wits_for_cred,a_idx,sn)?;

        let update_once =
            move |platform_api: &api::PlatformApi,
                  accs:         &tuf::AccumsForSigner,
                  vals:         &[api::DataValue],
                  wits_for_cred: &mut AllAccumulatorWitnesses,
                  i: AccumulatorBatchSeqNo | -> VCPResult<()> {
                      let (_,_,update_info) =
                          lookup_throw_if_absent(&a_idx,accs,Error::General,
                                                 &str_vec_from!("stepUpdateAccumulatorWitness"
                                                                ,"no accumulator update information for attribute index"
                                                 ))?;
                      let (awui,_) =
                          lookup_throw_if_absent(&i,update_info,Error::General,
                                                 &str_vec_from!("stepUpdateAccumulatorWitness"
                                                                ,"no accumulator update information for sequence number"
                                                 ))?;
                      tuf::update_accumulator_witness_with_map(platform_api,wits_for_cred,a_idx,vals,awui,i)?;
                      Ok(())
                  };

        //Inclusive range ending in sn-1 to make correspondence to Haskell code on which this is based clearer
        for i in prev_seq_no..=(sn-1) {
            update_once(&platform_api,accs_for_signer,vals,wits_for_cred,i)?;
        };
        Ok(())
    })
}

pub fn step_create_authority(
    platform_api: &api::PlatformApi,
    a_lbl: AuthorityLabel
) -> AddTestStep {
    let create_authority_data = platform_api.create_authority_data.clone();
    Arc::new(move |ts| {
        let aad = &mut ts.all_authority_data;
        // Ensure each new authority is created with a different random seed
        let rng_seed = aad.len();
        let ad = create_authority_data(rng_seed as u64)?;
        insert_throw_if_present(a_lbl.clone(), ad.clone(), aad, Error::General,
                                &str_vec_from!("stepCreateAuthorityData",
                                               "Duplicate authority label"))?;
        match ts.sparms.get(&a_lbl) {
            Some(_) => Err(Error::General(ic_semi(&str_vec_from!(
                "step_create_authority", a_lbl, "already exists in SharedParams")))),
            None    => {
                put_shared_one(a_lbl.clone(), DVText(encode_to_text(&ad.public)?), &mut ts.sparms);
                Ok(())
            }
        }
    })
}

fn ensure_encryptable(
    c_txt: String,
    i_lbl: IssuerLabelAsCredentialLabel,
    a_idx: &api::CredAttrIndex,
    ts: &TestState
) -> VCPResult<()> {
    let SignerData {signer_public_data, ..} =
         lookup_throw_if_absent(&i_lbl,&ts.all_signer_data,Error::General,
                                &str_vec_from!("ensure_encrytable", c_txt,
                                               "signer data not found"))?.to_owned();
    let SignerPublicData {signer_public_schema: cts, ..} = *signer_public_data;
    let ct = lookup_throw_if_out_of_bounds(&cts,*a_idx as usize,Error::General,
                                           &str_vec_from!("ensure_encrytable", c_txt,
                                                          "claim type not found"))?;
    if *ct == CTEncryptableText {
        Ok(())
    } else {
        Err(Error::General(ic_semi(&str_vec_from!(
            "ensure_encrytable", c_txt,
            "attribute index", a_idx, "exprected CTEncryptableText but found", ct))))
    }
}

pub fn step_encrypt_for(
    h_lbl: HolderLabel,
    i_lbl: IssuerLabel,
    a_idx: api::CredAttrIndex,
    a_lbl: AuthorityLabel
) -> AddTestStep {
    Arc::new(move |ts| {
        ensure_encryptable("step_encrypt_for".to_string(),
                           i_lbl.clone(), &a_idx, ts)?;
        let add_encrypted_for =
            |a_idx: api::CredAttrIndex,
             cr: &mut CredentialReqs|{
                cr.encrypted_for.0.push(IndexAndLabel {index: a_idx, label: a_lbl.clone()});
            };

        update_throw_if_absent_2_lvl(&h_lbl, &i_lbl,
                                     |cr: &mut CredentialReqs| add_encrypted_for(a_idx,cr),
                                     &mut ts.preqs, Error::General,
                                     &str_vec_from!("step_encrypt_for",
                                                    "no credentials signed for holder and issuer"))?;

        // TODO: check if we introduced a duplicate encryption request, throw if so

        let _ = &lookup_throw_if_absent(&a_lbl, &ts.all_authority_data, Error::General,
                                        &str_vec_from!("step_encrypt_for", "no such Authority"))?.public;
        Ok(())
    })
}

pub fn step_decrypt(
    h_lbl: HolderLabel,
    i_lbl: IssuerLabelAsCredentialLabel,
    a_idx: api::CredAttrIndex,
    a_lbl: AuthorityLabel
) -> AddTestStep {
    Arc::new(move |ts| {
        ensure_encryptable("step_decrypt".to_string(),
                           i_lbl.clone(), &a_idx, ts)?;
        let AuthorityData {secret, decryption_key, ..} =
            lookup_throw_if_absent(&a_lbl, &ts.all_authority_data, Error::General,
                                   &str_vec_from!("step_decrypt", "authority_not_created"))?;
        let new_decr_req = api::DecryptRequest::new(secret.clone(),decryption_key.clone());
        let dreqs_for_holder = ts.decrypt_requests.entry(h_lbl.clone()).or_default();
        let dreqs_for_issuer = dreqs_for_holder.entry(i_lbl.clone()).or_default();
        let dreqs_for_authority = dreqs_for_issuer.entry(a_idx).or_default();
        match dreqs_for_authority.insert(a_lbl.clone(), new_decr_req) {
            None => Ok(()),
            Some(_) => Err(Error::General(format!(
                "Duplicate decryption request: {h_lbl}/{i_lbl}/{a_idx}/{a_lbl}")))
        }
    })
}

fn perturb_value (dr: DecryptResponse) -> DecryptResponse {
    DecryptResponse { value: dr.value + "_", proof: dr.proof }
}

pub fn verify_decrypt_responses(
    platform_api: &api::PlatformApi,
    proof_reqs: &HashMap<IssuerLabelAsCredentialLabel, api::CredentialReqs>,
    shared_params: &HashMap<api::SharedParamKey, api::SharedParamValue>,
    prf: &Proof,
    perturb: PerturbDecryptedValue,
    d_reqs: &HashMap<IssuerLabelAsCredentialLabel,
                     HashMap<api::CredAttrIndex,
                             HashMap<api::AuthorityLabel,api::DecryptRequest>>>,
    d_resps0: &HashMap<IssuerLabelAsCredentialLabel,
                     HashMap<api::CredAttrIndex,

                             HashMap<api::AuthorityLabel,api::DecryptResponse>>>
) -> VCPResult<()> {
    let platform_api = platform_api.clone();
    let d_resps = match perturb {
        Perturb => &map_3_lvl(perturb_value,d_resps0),
        DontPerturb => d_resps0
    };
    let auth_dks = three_lvl_map_to_vec_of_tuples(d_reqs)
        .iter()
        .map(|(_,_,a_lbl,d_req)| (a_lbl.to_string(),d_req.auth_decryption_key.clone()))
        .collect::<HashMap<AuthorityLabel,AuthorityDecryptionKey>>();
    match (platform_api.verify_decryption)(proof_reqs, shared_params, prf, &auth_dks, d_resps, None) {
        Err(e) => {
            if perturb != Perturb {
                return Err(Error::General(ic_semi(&str_vec_from!(
                    "verify_decrypt_responses",
                    "encryption verification failed with",
                    format!("{e:?}")))))
            };
            Ok(())
        },
        Ok(_warnings) => {
            if perturb != DontPerturb {
                return Err(Error::General(ic_semi(&str_vec_from!(
                    "verifyDecryptResponses",
                    "expected to fail due to perturbed value(s)",
                    "but succeeded"))))
            };
            Ok(())
        }
    }
}

pub fn step_verify_decryption(
    platform_api: &api::PlatformApi,
    h_lbl: HolderLabel
) -> AddTestStep {
    let platform_api = platform_api.clone();
    let h_lbl = h_lbl.clone();
    Arc::new(move |ts| {
        let proof_reqs =
            lookup_throw_if_absent(&h_lbl, &ts.preqs, Error::General,
                                   &str_vec_from!("step_verify_decryption", "no proof requirements found for holder"))?;
        let d_reqs =
            lookup_throw_if_absent(&h_lbl, &ts.decrypt_requests, Error::General,
                                   &str_vec_from!("step_verify_decryption", "no decryption requests found for holder"))?;
        let d_resps =
            lookup_throw_if_absent(&h_lbl, &ts.last_decrypt_responses, Error::General,
                                   &str_vec_from!("step_verify_decryption", "no decryption responses found for holder"))?;
        let prf = &ts.warnings_and_data_for_verifier.result.proof.clone();
        verify_decrypt_responses(&platform_api, proof_reqs, &ts.sparms, prf, Perturb,     d_reqs, d_resps)?;
        verify_decrypt_responses(&platform_api, proof_reqs, &ts.sparms, prf, DontPerturb, d_reqs, d_resps)?;
        Ok(())
    })
}
