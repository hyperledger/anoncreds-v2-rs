// ----------------------------------------------------------------------------
use crate::vcp::{Error, SerdeJsonError, VCPResult};
use crate::vcp::r#impl::json::shared_params::{lookup_one_int, lookup_one_text};
use crate::vcp::r#impl::json::util::decode_from_text;
use crate::vcp::r#impl::util::{disjoint_vec_of_vecs, keys_vec_sorted, merge_maps, sort_by, TryCollectConcat};
use crate::vcp::primitives::types::*;
use crate::vcp::types::*;
// ----------------------------------------------------------------------------
use std::cmp::{min, Ordering};
use std::collections::HashMap;
use std::hash::Hash;
// ----------------------------------------------------------------------------

pub fn presentation_request_setup(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared_params: &HashMap<SharedParamKey, SharedParamValue>,
    vals_to_reveal: &HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
) -> VCPResult<(
    Vec<ProofInstructionGeneral<ResolvedDisclosure>>,
    EqualityReqs,
)> {
    let res_prf_insts = get_proof_instructions(shared_params, pres_reqs, vals_to_reveal)?;
    let eq_reqs = equality_reqs_from_pres_reqs_general(pres_reqs)?;
    Ok((res_prf_insts, eq_reqs))
}

// ----------------------------------------------------------------------------

pub fn get_proof_instructions(
    sparms: &HashMap<SharedParamKey, SharedParamValue>,
    cred_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    vals_to_reveal: &HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
) -> VCPResult<Vec<ProofInstructionGeneral<ResolvedDisclosure>>> {
    let lkups = keys_vec_sorted(cred_reqs)
        .into_iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), RelatedIndex(i as u64)))
        .collect::<HashMap<_, _>>();

    Ok(sort_by(
        merge_maps(cred_reqs.iter().collect(), vals_to_reveal.iter().collect())?
            .into_iter()
            .map(|(label, reqs)| get_proof_instructions_for_cred(sparms, &lkups, label, reqs))
            .try_collect_concat()?,
        compare_prf_instrs,
    ))
}

fn compare_prf_instrs(
    pig1: &ProofInstructionGeneral<ResolvedDisclosure>,
    pig2: &ProofInstructionGeneral<ResolvedDisclosure>,
) -> Ordering {
    match (&pig1.discl_general, &pig2.discl_general) {
        (
            ResolvedDisclosure::CredentialResolvedWrapper(_),
            ResolvedDisclosure::CredentialResolvedWrapper(_),
        ) => pig1.cred_label.cmp(&pig2.cred_label),
        (ResolvedDisclosure::CredentialResolvedWrapper(_), _) => Ordering::Less,
        (_, ResolvedDisclosure::CredentialResolvedWrapper(_)) => Ordering::Greater,
        _ => pig1.cmp(pig2),
    }
}

// ----------------------------------------------------------------------------

pub const POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES: u64 = 0;

fn get_proof_instructions_for_cred(
    sparms: &HashMap<SharedParamKey, SharedParamValue>,
    lkups: &HashMap<CredentialLabel, RelatedIndex>,
    c_lbl: &CredentialLabel,
    (
        CredentialReqs {
            signer_label,
            disclosed: Disclosed(_),
            in_accum: InAccum(in_accum),
            not_in_accum: NotInAccum(not_in_accum),
            in_range: InRange(in_range),
            encrypted_for: EncryptedFor(encrypted_for),
            ..
        },
        vals_to_reveal,
    ): (&CredentialReqs, &HashMap<CredAttrIndex, DataValue>),
) -> VCPResult<Vec<ProofInstructionGeneral<ResolvedDisclosure>>> {
    let cred_pi_idxs = lkups.get(c_lbl).ok_or_else(|| {
        Error::General("get_proof_instructions_for_cred; INTERNAL ERROR".to_string())
    })?;
    let sig_res: ProofInstructionGeneral<ResolvedDisclosure> = {
        let signer_public_data: SignerPublicData = decode_from_text(
            "Unable to decode IssuerPublic from shared parameters",
            lookup_one_text(signer_label, sparms)?)?;
        let schema = &signer_public_data.signer_public_schema;
        let reveal_vals_and_cts = vals_to_reveal
            .iter()
            .map(|(i, v)| -> VCPResult<_> {
                let ct = schema.get(*i as usize).ok_or_else(|| {
                    Error::General(format!(
                        "get_proof_instructions_for_cred; INTERNAL ERROR; {i}; {:?}",
                        &schema
                    ))
                })?;
                Ok((*i, (v.clone(), *ct)))
            })
            .collect::<VCPResult<HashMap<_, _>>>()?;
        Ok(ProofInstructionGeneral {
            cred_label: c_lbl.clone(),
            attr_idx_general: POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES,
            related_pi_idx: *cred_pi_idxs,
            discl_general: ResolvedDisclosure::CredentialResolvedWrapper(CredentialResolved {
                issuer_public: signer_public_data,
                rev_idxs_and_vals: reveal_vals_and_cts,
            }),
        })
    }?;

    let in_accum_res: Vec<ProofInstructionGeneral<ResolvedDisclosure>> = in_accum
        .iter()
        .map(
            |InAccumInfo {
                 index,
                 accumulator_public_data_label,
                 membership_proving_key_label,
                 accumulator_label,
                 accumulator_seq_num_label
             }|
                -> VCPResult<ProofInstructionGeneral<ResolvedDisclosure>> {
                let public_data: AccumulatorPublicData = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(accumulator_public_data_label, sparms)?)?;

                let mem_prv: MembershipProvingKey = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(membership_proving_key_label, sparms)?)?;

                let accumulator: Accumulator = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(accumulator_label, sparms)?)?;

                let seq_num = lookup_one_int(accumulator_seq_num_label, sparms)?;

                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: *index,
                    related_pi_idx: *cred_pi_idxs,
                    discl_general: ResolvedDisclosure::InAccumResolvedWrapper(InAccumResolved {
                        public_data,
                        mem_prv,
                        accumulator,
                        seq_num: *seq_num
                    }),
                })
            },
        )
        .collect::<VCPResult<Vec<_>>>()?;

    let in_range_res: Vec<ProofInstructionGeneral<ResolvedDisclosure>> = in_range
        .iter()
        .map(
            |info| -> VCPResult<ProofInstructionGeneral<ResolvedDisclosure>> {
                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: info.index,
                    related_pi_idx: *cred_pi_idxs,
                    discl_general: ResolvedDisclosure::InRangeResolvedWrapper(InRangeResolved {
                        min_val: *lookup_one_int(&info.min_label, sparms)?,
                        max_val: *lookup_one_int(&info.max_label, sparms)?,
                        proving_key: decode_from_text(
                            "get_proof_instructions_for_cred",
                            lookup_one_text(&info.range_proving_key_label, sparms)?,
                        )?,
                    }),
                })
            },
        )
        .collect::<VCPResult<Vec<_>>>()?;

    let en_f_res = encrypted_for
        .iter()
        .map(
            |IndexAndLabel {
                index: a_idx,
                label: auth_lbl,
            }| {
                let x = EncryptedForResolved {
                    auth_pub_spk  : auth_lbl.to_string(),
                    auth_pub_data : decode_from_text(
                        "get_proof_instructions_for_cred",
                        lookup_one_text(auth_lbl, sparms)?)?
                };
                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: *a_idx,
                    related_pi_idx: *cred_pi_idxs,
                    discl_general: ResolvedDisclosure::EncryptedForResolvedWrapper(x),
                })
            },
        )
        .collect::<VCPResult<Vec<_>>>()?;

    Ok([vec![sig_res], in_accum_res, in_range_res, en_f_res].concat())
}

/// Check that all Equality Reqs reference existing credentials, and attributes
/// are in range, and ClaimTypes and Values match.
fn equality_reqs_from_pres_reqs_general(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
) -> VCPResult<EqualityReqs> {
    let mut all_eq_pairs: EqualityReqs = vec![];
    // Ensure all target credential labels are in map -- maybe unnecessary, will
    // be done by next step anyway
    // TODO: this is difficult to compare to the corresponding Haskell code, which itself
    // is not completely straightforward to understand.  I think we need better tests in both.
    // In particular, I'm concerned that we might be conflating all equivalence classes into one here.
    pres_reqs.iter().for_each(
        |(
            from_label,
            CredentialReqs {
                equal_to: EqualTo(equal_to),
                ..
            },
        )| {
            equal_to.iter().for_each(|equal_info| {
                all_eq_pairs.extend([vec![
                    (from_label.clone(), equal_info.from_index),
                    (equal_info.to_label.clone(), equal_info.to_index),
                ]]);
            });
        },
    );
    all_eq_pairs = disjoint_vec_of_vecs(all_eq_pairs);
    // Ensure all target credential labels are in map -- maybe unnecessary, will be done by next step anyway
    all_eq_pairs.iter().try_for_each(|eq_pairs| {
        eq_pairs.iter().try_for_each(|(x, _)| {
            pres_reqs
                .get(x)
                .ok_or(Error::General("Non-existent credential label".to_string()))?;
            Ok(())
        })
    })?;
    // Ensure that, regardless of the order of `CredentialReqs` in `pres_reqs`,
    // the `EqualityReqs` result is always in the same order.
    // The order of `CredentialReqs` in `pres_reqs` may be different because of external input, such as:
    // - provers and verifiers using equivalent but differently ordered `pres_reqs`
    // - json de/serializers changing the order of items in maps
    // When using AC2C, the prover and verifier must produce the same order of `EqualityReqs`
    // regardless of the order of items in `pres_reqs`.
    // If not, then the Merlin transcript check in verify fails.
    let mut all_eq_pairs_sorted = vec![];
    for mut v in all_eq_pairs.iter_mut() {
        v.sort();
        all_eq_pairs_sorted.push((*v).clone());
    }
    all_eq_pairs_sorted.sort();
    // TODO: check all equality pairs correct according to DataValues
    Ok(all_eq_pairs_sorted)
}

pub fn is_cred_resolved(instr: &ProofInstructionGeneral<ResolvedDisclosure>) -> bool {
    matches!(
        instr,
        ProofInstructionGeneral {
            discl_general: ResolvedDisclosure::CredentialResolvedWrapper(_),
            ..
        }
    )
}
