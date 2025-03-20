use crate::str_vec_from;
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::general::presentation_request_setup::presentation_request_setup;
use crate::vcp::r#impl::json::shared_params::lookup_one_text;
use crate::vcp::r#impl::json::util::decode_from_text;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::non_primitives::*;
use crate::vcp::interfaces::primitives::*;
use crate::vcp::interfaces::primitives::types::WarningsAndProof;
use crate::vcp::interfaces::types::*;
// ----------------------------------------------------------------------------
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;
// ----------------------------------------------------------------------------

pub fn create_proof(spec_prover: SpecificProver) -> CreateProof {
    Arc::new(
        move |pres_reqs, shared_params, sigs_and_rel_data_api, proof_mode, nonce| {
            let all_vals = get_all_vals(pres_reqs, sigs_and_rel_data_api)?;
            let vals_to_reveal = filter_map_2_lvl(|(_,b)| b, |(dv,_)| dv, &all_vals);
            let (res_prf_insts, eq_reqs) =
                presentation_request_setup(pres_reqs, shared_params, &vals_to_reveal, &proof_mode)?;
            let warns_rev = validate_cred_reqs_against_schemas(
                pres_reqs,
                &get_schemas(shared_params, pres_reqs)?,
            )?;
            if (proof_mode != ProofMode::TestBackend) {
                validate_proof_instructions_against_values(&all_vals, &res_prf_insts)?;
                eq_reqs.iter().try_for_each(|x| {validate_one_equality(&all_vals, x)})?;
            }
            let WarningsAndProof {
                warnings: warns_dfv,
                proof: proof_from_sp,
            } = spec_prover(&res_prf_insts, &eq_reqs, sigs_and_rel_data_api, get_nonce(&nonce))?;
            let warnings = [warns_rev, warns_dfv].concat();
            check_warnings("create_proof", &proof_mode, &warnings)?;
            Ok(WarningsAndDataForVerifier {
                warnings,
                data_for_verifier: DataForVerifier {
                    revealed_idxs_and_vals: vals_to_reveal,
                    proof: proof_from_sp
                },
            })
        },
    )
}

pub fn validate_one_equality (
    all_vals: &HashMap<CredentialLabel,HashMap<CredAttrIndex,(DataValue,bool)>>,
    eq_req: &[(CredentialLabel, CredAttrIndex)]
) -> VCPResult<()> {
    match eq_req {
        []  =>  Err(Error::General(ic_semi(&str_vec_from!("validate_one_equality",
                                                          "UNEXPECTED",
                                                          "empty equality list")))),
        [_] =>  Err(Error::General(ic_semi(&str_vec_from!("validate_one_equality",
                                                          "UNEXPECTED",
                                                          "empty equality list")))),
        [(c_lbl_first, a_idx_first),l @ ..] => {
            let (v_first, _) = lookup_throw_if_absent_2_lvl(c_lbl_first, a_idx_first, all_vals, Error::General,
                                                            &str_vec_from!("createProof", "validate_one_equality_1",
                                                                           format!("{all_vals:?}")))?;
            for (ref c_lbl_other, ref a_idx_other) in l.iter() {
                let (v_other, _) = lookup_throw_if_absent_2_lvl(c_lbl_other, a_idx_other, all_vals, Error::General,
                                                                &str_vec_from!("createProof", "validate_one_equality_1",
                                                                           format!("{all_vals:?}")))?;
                if v_first != v_other {
                    return Err(Error::General(ic_semi(&str_vec_from!(
                        "validate_one_equality",
                        "values not equal",
                        c_lbl_first,
                        a_idx_first.to_string(),
                        c_lbl_other,
                        a_idx_other.to_string(),
                        v_first.to_string(),
                        v_other.to_string()))))
                };
            };
            Ok(())
        }
    }
}

pub fn verify_proof(spec_verifier: SpecificVerifier) -> VerifyProof {
    Arc::new(
        move |pres_reqs, shared_params, data_for_verifier, decrypt_reqs, proof_mode, nonce| {
            let (res_prf_instrs, eq_reqs) = presentation_request_setup(
                pres_reqs,
                shared_params,
                &data_for_verifier.revealed_idxs_and_vals,
                &proof_mode,
            )?;
            let warns_rev = validate_cred_reqs_against_schemas(
                pres_reqs,
                &get_schemas(shared_params, pres_reqs)?,
            )?;
            let WarningsAndDecryptResponses {
                warnings: warns_ver,
                decrypt_responses: dcr,
            } = spec_verifier(
                &res_prf_instrs,
                &eq_reqs,
                &data_for_verifier.proof,
                decrypt_reqs,
                get_nonce(&nonce),
            )?;
            let warnings = [warns_rev, warns_ver].concat();
            check_warnings("verify_proof", &proof_mode, &warnings)?;
            Ok(WarningsAndDecryptResponses {
                warnings,
                decrypt_responses: dcr,
            })
        },
    )
}

pub fn verify_decryption(spec_verifier: SpecificVerifier,
                         spec_verify_decryption: SpecificVerifyDecryption
) -> VerifyDecryption {
    Arc::new(
        move |pres_reqs, shared_params, prf, auth_dks, decrypt_responses, proof_mode, nonce| {
            // Verify the original proof, to ensure that information extracted from it for verifying
            // decryption satisfies the presentation/proof requirements

            // No values to reveal
            let mut vals_to_reveal = HashMap::<CredentialLabel, HashMap< CredAttrIndex, DataValue>>::new();
            for key in pres_reqs.keys() {
                vals_to_reveal.insert(key.to_string(), HashMap::new());
            };
            let (res_prf_instrs, eq_reqs) = presentation_request_setup(
                pres_reqs,
                shared_params,
                &vals_to_reveal,
                &proof_mode,
            )?;
            let warns_rev = validate_cred_reqs_against_schemas(
                pres_reqs,
                &get_schemas(shared_params, pres_reqs)?,
            )?;
            let WarningsAndDecryptResponses {
                warnings: warns_ver,
                decrypt_responses: _,
            } = spec_verifier(
                &res_prf_instrs,
                &eq_reqs,
                prf,
                &HashMap::new(),
                get_nonce(&nonce),
            )?;
            let warns_ver_decr = spec_verify_decryption(
                &res_prf_instrs, &eq_reqs, prf, auth_dks, decrypt_responses)?;
            let all_warnings = [warns_rev, warns_ver, warns_ver_decr].concat();
            check_warnings("verify_decryption", &proof_mode, &all_warnings)?;
            Ok(all_warnings)
        })
}
// ----------------------------------------------------------------------------

fn check_warnings(
    s          : &str,
    proof_mode : &ProofMode,
    warnings   : &Vec<Warning>,
) -> VCPResult<()>
{
    if (*proof_mode == ProofMode::Strict && ! warnings.is_empty() ) {
        Err(Error::General(format!(
            "{s}; cannot create proof with warnings in Strict mode; {:?}", warnings)))
    } else {
        Ok(())
    }
}

lazy_static! {
    pub static ref NONCE_DEFAULT : Nonce = "XXXDefaultDeterministicNonce".to_string();
}

fn get_nonce(n : &Option<Nonce>) -> Nonce {
    match n {
        Some(n) => n.to_string(),
        None    => NONCE_DEFAULT.to_string(),
    }
}

fn get_schema(
    shared_params: &HashMap<SharedParamKey, SharedParamValue>,
    cred_reqs: &CredentialReqs,
) -> VCPResult<Vec<ClaimType>> {
    let signer_label = &cred_reqs.signer_label;
    let spsd_as_text = lookup_one_text(signer_label, shared_params)?;
    let spsd: SignerPublicData = decode_from_text("get_schema", spsd_as_text)?;
    Ok(spsd.signer_public_schema)
}

fn get_schemas(
    shared_params: &HashMap<SharedParamKey, SharedParamValue>,
    pres_reqs: &HashMap<SharedParamKey, CredentialReqs>,
) -> VCPResult<HashMap<CredentialLabel, Vec<ClaimType>>> {
    pres_reqs
        .iter()
        .map(|(key, cred_reqs)| Ok((key.clone(), get_schema(shared_params, cred_reqs)?)))
        .collect()
}

fn validate_cred_reqs_against_schemas(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    sdcts: &HashMap<CredentialLabel, Vec<ClaimType>>,
) -> VCPResult<Vec<Warning>> {
    let revs: HashMap<&CredentialLabel, &Disclosed> = pres_reqs
        .iter()
        .map(|(k, cred_reqs)| (k, &cred_reqs.disclosed))
        .collect();
    let revs_merge_sdcts: HashMap<&String, (&Disclosed, &Vec<ClaimType>)> =
        merge_maps(revs, sdcts.iter().collect())?;
    revs_merge_sdcts
        .into_iter()
        .map(warnings_for)
        .try_collect_concat()
}

fn validate_proof_instructions_against_values(
    all_vals      : &HashMap<CredentialLabel, HashMap<CredAttrIndex, (DataValue, bool)>>,
    res_prf_insts : &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<()>
{
    for pi in res_prf_insts {
        if let ProofInstructionGeneral {
            cred_label, attr_idx_general, related_pi_idx,
            discl_general : ResolvedDisclosure::InRangeResolvedWrapper
                (InRangeResolved { min_val, max_val, proving_key }),
        } = pi {
            let v = &lookup_throw_if_absent_2_lvl(
                cred_label,
                attr_idx_general,
                all_vals,
                Error::General,
                &str_vec_from!("validate_proof_instructions_against_values", "missing value"))?.0;
            match v
            {
                DataValue::DVText(t) => {
                    return Err(Error::General(format!(
                        "validate_proof_instructions_against_values;
                         expected DVInt value for range proof, got DVText {t}")));
                }
                DataValue::DVInt(v) => {
                    if v < min_val || v > max_val {
                        return Err(Error::General(format!(
                            "validate_proof_instructions_against_values;
                             {v} out of range [{min_val},{max_val}];
                             for {cred_label}; attribute index {attr_idx_general}")));
                    }
                }
            }
        }
    }
    Ok(())
}

fn warnings_for(
    (cl, (Disclosed(l), ctl)): (&CredentialLabel, (&Disclosed, &Vec<ClaimType>)),
) -> VCPResult<Vec<Warning>> {
    l.iter()
        .map(|i| -> VCPResult<Vec<Warning>> {
            Ok(warnings_by_claim_type(((cl, i), {
                ctl.get(*i as usize).ok_or_else(|| {
                    Error::General(format!(
                        "validate_cred_reqs_against_schemas; warnings for; {cl}"
                    ))
                })
            }?)))
        })
        .try_collect_concat()
}

fn warnings_by_claim_type(
    ((cl, i), ctl): ((&CredentialLabel, &CredAttrIndex), &ClaimType),
) -> Vec<Warning> {
    match ((cl, i), ctl) {
        (_, ClaimType::CTEncryptableText) => vec![Warning::RevealPrivacyWarning(
            cl.clone(),
            *i,
            "encryptable".to_string(),
        )],
        (_, ClaimType::CTAccumulatorMember) => vec![Warning::RevealPrivacyWarning(
            cl.clone(),
            *i,
            "an accumulator member".to_string(),
        )],
        _ => vec![],
    }
}

fn get_vals_for_cred(
    CredentialReqs {
        disclosed: Disclosed(idxs_to_reveal),
        ..
    }: &CredentialReqs,
    SignatureAndRelatedData { values: vals, .. }: &SignatureAndRelatedData,
) -> VCPResult<HashMap<CredAttrIndex, (DataValue, bool)>> {
    {
        let bad_idxs: Vec<&u64> = idxs_to_reveal
            .iter()
            .filter(|i| vals.len() as u64 <= **i)
            .collect();
        if !bad_idxs.is_empty() {
            return Err(Error::General(format!(
                "indexes; {bad_idxs:?}; out of range for; {}; attributes",
                vals.len()
            )));
        }
    }

    let mut result = HashMap::<CredAttrIndex, (DataValue, bool)>::new();
    for i in 0 .. vals.len() {
        let val = vals.get(i).ok_or_else(|| {
            Error::General("get_vals_for_cred; INTERNAL ERROR".to_string()) })?;
        result.insert(i as u64,
                      (val.clone(), idxs_to_reveal.contains( &(i as u64) )));
    }
    Ok(result)
}

#[allow(clippy::type_complexity)]
fn get_all_vals(
    pres_reqs             : &HashMap<CredentialLabel, CredentialReqs>,
    sigs_and_rel_data_api : &HashMap<CredentialLabel, SignatureAndRelatedData>,
) -> VCPResult<HashMap<CredentialLabel, HashMap<CredAttrIndex, (DataValue, bool)>>> {
    merge_maps(
        pres_reqs.iter().collect(),
        sigs_and_rel_data_api.iter().collect(),
    )?
    .into_iter()
    .map(|(cl, (cred_reqs, signature_and_related_data))| {
        Ok((
            cl.clone(),
            get_vals_for_cred(cred_reqs, signature_and_related_data)?,
        ))
    })
    .collect()
}
