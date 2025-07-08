// ------------------------------------------------------------------------------
use crate::{get_location_and_backtrace_on_panic, str_vec_from};
use crate::vcp::{convert_to_crypto_library_error, Error, VCPResult, UnexpectedError};
use crate::vcp::r#impl::catch_unwind_util::*;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::r#impl::types::WarningsAndResult;
use crate::vcp::r#impl::util::{
    insert_throw_if_present, insert_throw_if_present_3_lvl,
    lookup_throw_if_absent, three_lvl_map_to_vec_of_tuples, Assert};
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::ac2c::presentation_request_setup::*;
use crate::vcp::zkp_backends::ac2c::signer::*;
// ------------------------------------------------------------------------------
use crate::claim::{ClaimData, ScalarClaim};
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{Presentation, PresentationCredential, PresentationProofs, PresentationSchema};
// ------------------------------------------------------------------------------
use indexmap::IndexMap;
use std::collections::HashMap;
use std::panic::RefUnwindSafe;
use std::str;
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn specific_prover_ac2c<S: ShortGroupSignatureScheme>() -> SpecificProver
where <S as ShortGroupSignatureScheme>::PublicKey: RefUnwindSafe,
      <S as ShortGroupSignatureScheme>::Signature: RefUnwindSafe {
    Arc::new(|prf_instrs, eqs, sigs_and_related_data, nonce| {
        let credentials = presentation_credentials_from::<S>(sigs_and_related_data)?;
        // println!("specific_prover_ac2c: credentials: {:?}", credentials);
        let WarningsAndResult {
            warnings: warns,
            result: pres_sch,
        } = presentation_schema_from(prf_instrs, eqs)?;
        // println!("specific_prover_ac2c: pres_sch: {:?}", pres_sch);
        let prf = get_location_and_backtrace_on_panic!(
            Presentation::create(&credentials, &pres_sch, nonce.as_bytes())
                .map_err(|e| convert_to_crypto_library_error("AC2C", "specific_prover_ac2c", e)))?;
        Ok(WarningsAndProof {
            warnings: warns,
            proof: to_api(prf)?,
        })
    })
}

pub fn specific_verifier_ac2c<S: ShortGroupSignatureScheme>() -> SpecificVerifier
where <S as ShortGroupSignatureScheme>::PublicKey: RefUnwindSafe,
      <S as ShortGroupSignatureScheme>::ProofOfSignatureKnowledge: RefUnwindSafe {
    Arc::new(|prf_instrs, eqs, proof_api, decr_reqs, nonce| {
        let WarningsAndResult {
            warnings: warns,
            result: pres_sch,
        } = presentation_schema_from::<S>(prf_instrs, eqs)?;
        let proof_ac2c: Presentation<S> = from_api(proof_api)?;

        verify_disclosed_messages(&proof_ac2c.disclosed_messages, prf_instrs)?;

        // throws if verify fails
        get_location_and_backtrace_on_panic!(
            Presentation::verify(&proof_ac2c, &pres_sch, nonce.as_bytes())
                .map_err(|e| convert_to_crypto_library_error("AC2C", "specific_verifier_ac2c", e)))?;
        let mut decrypt_responses = HashMap::new();

        for (i_lbl, a_idx, a_lbl, DecryptRequest { authority_secret_data, authority_decryption_key }) in
            three_lvl_map_to_vec_of_tuples(decr_reqs)
        {
            let stmt_id = encrypted_for_label_for(i_lbl,a_idx,a_lbl);
            let prf = lookup_throw_if_absent(&stmt_id, &proof_ac2c.proofs, Error::General,
                                             &str_vec_from!("specific_verifier_ac2c",
                                                            "encryption proof not found"))?;
            if let PresentationProofs::VerifiableEncryption(verenc) = prf {
                let dk = from_api(authority_decryption_key)?;
                let decrypted_value_scalar = verenc
                    .decrypt_scalar(&dk)
                    .ok_or(Error::General(format!(
                        "Error decrypting attribute {a_idx} of credential \
                         issued by {i_lbl} for {a_lbl}")))?;

                let decrypted_value = ScalarClaim::from(decrypted_value_scalar)
                         .decode_to_str().map_err(|e| Error::General(format!(
                             "Error {e:?} decoding decrypted scalar {decrypted_value_scalar:?} \
                              for attribute {a_idx} of credential issued by {i_lbl} for {a_lbl}")))?;
                let dr = DecryptResponse {
                    value: decrypted_value,
                    decryption_proof:
                    DecryptionProof("BOGUS-DECRYPTION-VERIFICATION-NOT-YET-SUPPORTED".to_string()),
                };
                insert_throw_if_present_3_lvl(i_lbl, a_idx, a_lbl, dr, &mut decrypt_responses,
                                              Error::General,
                                              &str_vec_from!("specific_verifier_ac2c",
                                                             "duplicate decrypt response"))?;
            } else {
                return Err(Error::General(format!(
                    "Expected VerifiableEncryptionProof for statement {stmt_id}, \
                                                   but found {prf:?}")));
            }
        }
        Ok(WarningsAndDecryptResponses {
            warnings: warns,
            decrypt_responses
        })
    })
}

fn verify_disclosed_messages(
    disclosed_messages_from_proof : &IndexMap<String, IndexMap<String, ClaimData>>,
    prf_instrs : &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<()> {
    let mut new_disclosed_messages : IndexMap<String, IndexMap<String, ClaimData>> = IndexMap::new();
    // Build the disclosed messages from the proof instructions
    // to enable checking they are the same as the ones in the proof (i.e., Presentation)
    for pig in prf_instrs.iter() {
        if let ProofInstructionGeneral {
            cred_label, attr_idx_general,
            discl_general : ResolvedDisclosure::CredentialResolvedWrapper
                (CredentialResolved { rev_idxs_and_vals, .. }),
            ..
        } = pig {
            let disclosed_messages_from_prf_instr = rev_idxs_and_vals;
            for (i, (dv,ct)) in disclosed_messages_from_prf_instr.iter() {
                let stmt_label = stmt_label_for(cred_label);
                let attr_label = attr_label_for_idx(*i);
                let claim_data_from_prf_instr = val_to_claim_data((ct,dv))?;
                let inner_map = new_disclosed_messages.entry(stmt_label.to_string()).or_default();
                inner_map.insert(attr_label.to_string(), claim_data_from_prf_instr.clone());
            }
        }
    }
    let dmfp = remove_empty_inner_maps(disclosed_messages_from_proof);
    if dmfp != new_disclosed_messages {
        return Err(Error::General(format!(
            "verify_disclosed_messages: disclosed_messages_from_proof \
             {dmfp:?} \
             differ from revealed \
             values {new_disclosed_messages:?}")));
    }
    Ok(())
}

fn remove_empty_inner_maps(
    data: &IndexMap<String, IndexMap<String, ClaimData>>,
) -> IndexMap<String, IndexMap<String, ClaimData>> {
    data.into_iter()
        .filter(|(_, inner_map)| !inner_map.is_empty())
        .map(|(k,v)| (k.clone(), v.clone()))
        .collect::<IndexMap<_, _>>()
}
pub fn specific_verify_decryption_ac2c() -> SpecificVerifyDecryption {
    Arc::new(|_prf_instrs, _eqs, _proof_api, _decr_reqs, _auth_dks| {
        Err(Error::General("specific_verify_decryption_ac2c : UNIMPLEMENTED".to_string()))
    })
}
