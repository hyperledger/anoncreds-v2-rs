use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::general::presentation_request_setup::presentation_request_setup;
use crate::vcp::r#impl::json::shared_params::lookup_one_text;
use crate::vcp::r#impl::json::util::decode_from_text;
use crate::vcp::r#impl::util::{merge_maps, pp, TryCollectConcat};
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
        move |pres_reqs, shared_params, sigs_and_rel_data_api, nonce| {
            let vals_to_reveal = get_vals_to_reveal(pres_reqs, sigs_and_rel_data_api)?;
            let (res_prf_insts, eq_reqs) =
                presentation_request_setup(pres_reqs, shared_params, &vals_to_reveal)?;
            let warns_rev = validate_cred_reqs_against_schemas(
                pres_reqs,
                &get_schemas(shared_params, pres_reqs)?,
            )?;
            let WarningsAndProof {
                warnings: warns_dfv,
                proof: proof_from_sp,
            } = spec_prover(&res_prf_insts, &eq_reqs, sigs_and_rel_data_api, get_nonce(&nonce))?;
            let warnings = [warns_rev, warns_dfv].concat();
            // TODO : enable or delete
            // if !warnings.is_empty() {
            //     return Err(Error::General(format!(
            //         "Cannot proceed when warnings exist: {warnings:#?}"
            //     )))
            // }
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

pub fn verify_proof(spec_verifier: SpecificVerifier) -> VerifyProof {
    Arc::new(
        move |pres_reqs, shared_params, data_for_verifier, decrypt_reqs, nonce| {
            let (res_prf_instrs, eq_reqs) = presentation_request_setup(
                pres_reqs,
                shared_params,
                &data_for_verifier.revealed_idxs_and_vals,
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
            // TODO : enable or delete
            // if !warns_ver.is_empty() {
            //     return Err(Error::General(format!(
            //         "Cannot proceed when warnings exist: {warns_ver:#?}"
            //     )))
            // }
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
        move |pres_reqs, shared_params, prf, auth_dks, decrypt_responses, nonce| {
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
            Ok([warns_rev, warns_ver, warns_ver_decr].concat())
        })
}
// ----------------------------------------------------------------------------

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

fn get_vals_to_reveal_for_cred(
    CredentialReqs {
        disclosed: Disclosed(idxs_to_reveal),
        ..
    }: &CredentialReqs,
    SignatureAndRelatedData { values: vals, .. }: &SignatureAndRelatedData,
) -> VCPResult<HashMap<CredAttrIndex, DataValue>> {
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

    idxs_to_reveal
        .iter()
        .map(|i| {
            Ok((
                *i,
                {
                    vals.get(*i as usize).ok_or_else(|| {
                        Error::General("INTERNAL ERROR; get_vals_to_reveal_for_cred".to_string())
                    })
                }?
                .clone(),
            ))
        })
        .collect()
}

fn get_vals_to_reveal(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    sigs_and_rel_data_api: &HashMap<CredentialLabel, SignatureAndRelatedData>,
) -> VCPResult<HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>> {
    merge_maps(
        pres_reqs.iter().collect(),
        sigs_and_rel_data_api.iter().collect(),
    )?
    .into_iter()
    .map(|(cl, (cred_reqs, signature_and_related_data))| {
        Ok((
            cl.clone(),
            get_vals_to_reveal_for_cred(cred_reqs, signature_and_related_data)?,
        ))
    })
    .collect()
}
