// ------------------------------------------------------------------------------
use crate::str_vec_from;
use crate::vcp::{convert_to_crypto_library_error, Error, VCPResult};
use crate::vcp::r#impl::types::*;
use crate::vcp::r#impl::general::presentation_request_setup::is_cred_resolved;
use crate::vcp::r#impl::general::presentation_request_setup::POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::dnc::generate_frs::*;
use crate::vcp::zkp_backends::dnc::reversible_encoding::*;
use crate::vcp::zkp_backends::dnc::signer::*;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use ::bbs_plus::prelude::PublicKeyG2;
use ::bbs_plus::prelude::SignatureG1;
use ::bbs_plus::prelude::SignatureParamsG1;
use proof_system::prelude::*;
use proof_system::prelude::accumulator::VBAccumulatorMembership;
use proof_system::prelude::saver::SaverProver;
use proof_system::prelude::saver::SaverVerifier;
use proof_system::statement::bound_check_legogroth16::{
    BoundCheckLegoGroth16Prover   as BoundCheckProverStmt,
    BoundCheckLegoGroth16Verifier as BoundCheckVerifierStmt
};
use proof_system::witness::PoKBBSSignatureG1      as PoKSignatureBBSG1Wit;
use ::saver::keygen::DecryptionKey                  as SaverDecryptionKey;
use vb_accumulator::positive::Accumulator;
use vb_accumulator::prelude::MembershipProvingKey;
use vb_accumulator::prelude::MembershipWitness;
use vb_accumulator::prelude::PositiveAccumulator;
use vb_accumulator::prelude::PublicKey            as VbaPublicKey;
use vb_accumulator::prelude::SetupParams          as VbaSetupParams;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_std::collections::{BTreeMap,BTreeSet};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn specific_prover_dnc() -> SpecificProver {
    Arc::new(|prf_instrs, eqs, sigs_and_related_data, nonce| {
        let (WarningsAndResult { warnings, result: (proof_spec, maybe_witnesses)}, _) =
            proof_spec_from(true, &prf_instrs.to_vec(), eqs, Some(sigs_and_related_data))?;
        let mut rng = StdRng::seed_from_u64(0); // TODO: real seed
        if let Some(witnesses) = maybe_witnesses {
            let (proof, _commitment_randomness) = ProofG1::new::<StdRng, Blake2b512>(
                &mut rng, proof_spec, witnesses, Some(nonce.as_bytes().to_vec()), Default::default(),
            ).map_err(|e| convert_to_crypto_library_error("DNC", "specific_prover_dnc", e))?;
            Ok(WarningsAndProof { warnings, proof : to_api(proof)? })
        } else {
            Err(Error::General("specific_prover_dnc; Prover must provide SignaturesAndRelatedData".to_string()))
        }
    })
}

pub fn specific_verifier_dnc() -> SpecificVerifier {
    Arc::new(|prf_instrs, eqs, proof_api, decr_reqs, nonce| {
        let (WarningsAndResult { warnings, result: (proof_spec, _)}, decr_req_lkups) =
            proof_spec_from(true, &prf_instrs.to_vec(), eqs, None)?;
        let mut rng = StdRng::seed_from_u64(137); // TODO: 137
        let prf : ProofG1 = from_api(proof_api)?;
        let response = WarningsAndDecryptResponses {
            warnings,
            decrypt_responses : get_decryption_responses(&decr_req_lkups, &prf, decr_reqs)?
        };
        prf.verify::<StdRng, Blake2b512>(
            &mut rng, proof_spec, Some(nonce.as_bytes().to_vec()), Default::default()
        ).map_err(|e| Error::General(format!("DNC prf.verify {:?}", e)))?;
        // Note: If 'prf.verify' does not pass, this response is not sent.
        Ok(response)
    })
}

pub fn specific_verify_decryption_dnc() -> SpecificVerifyDecryption {
    Arc::new(|prf_instrs, eqs, proof_api, auth_dks, decr_resps| {
        let (WarningsAndResult { warnings, result: _ }, decr_req_lkups) =
            proof_spec_from(true, &prf_instrs.to_vec(), eqs, None)?;
        let proof : ProofG1 = from_api(proof_api)?;
        map_3_lvl_with_keys_partially_applied_with_error(
            (decr_req_lkups,
             proof,
             auth_dks),
            |(d_lkups, prf, dks), c_lbl, a_idx, auth_label, dr| {
                verify_decryption_response(&d_lkups, &prf, dks, c_lbl, a_idx, auth_label, &dr)
            },
            decr_resps)?;
        Ok(warnings)
    })
}

// ===========================================================================
// IMPLEMENTATION

#[allow(clippy::type_complexity)]
fn get_decryption_responses(
    decr_lkups : &DecryptionLookups,
    prf        : &ProofG1,
    decr_reqs  : &HashMap<CredentialLabel,
                          HashMap<CredAttrIndex,
                                  HashMap<SharedParamKey, DecryptRequest>>>
) -> VCPResult<HashMap<CredentialLabel,
                       HashMap<CredAttrIndex,
                               HashMap<SharedParamKey, DecryptResponse>>>>
{
    map_3_lvl_with_keys_partially_applied_with_error(
        (decr_lkups, prf.clone()),
        |(dl, p), c_lbl, a_idx, auth_label, decr_req| {
            get_decryption_response_for_cred(dl, &p, &c_lbl, &a_idx, &auth_label, &decr_req)
        },
        decr_reqs)
}

#[allow(clippy::type_complexity)]
fn get_decryption_response_for_cred(
    decr_lkups : &DecryptionLookups,
    prf        : &ProofG1,
    c_lbl      : &str,
    a_idx      : &u64,
    auth_label : &SharedParamKey,
    DecryptRequest { authority_secret_data, authority_decryption_key } : &DecryptRequest
) -> VCPResult<DecryptResponse>
{
    let ix = (c_lbl.to_string(), *a_idx, auth_label.to_string());
    let (s_idx,
         AuthorityPublicSetupData {
             chunk_bit_size, snark_proving_key, ..
    }) = lookup_throw_if_absent(&ix, decr_lkups, Error::General,
                                &["get_decryption_response_for_cred".to_string(),
                                  "attribute not encrypted".to_string()])?;
    let (ct,_)         = prf.get_saver_ciphertext_and_proof(*s_idx)
        .map_err(|e| Error::General(format!("DNC get_saver_ciphertext_and_proof {:?}", e)))?;
    let dk : SaverDecryptionKey::<Bls12_381> = from_api(authority_decryption_key)?;
    let sk             = from_api(authority_secret_data)?;
    let (decr_val, nu) = ct.decrypt_given_groth16_vk(&sk, dk, &snark_proving_key.pk.vk, *chunk_bit_size)
        .map_err(|e| Error::General(format!("DNC decrypt_given_groth16_vk {:?}", e)))?;
    Ok(DecryptResponse { value            : field_element_to_string(decr_val)?,
                         decryption_proof : to_api((decr_val, nu))? })
}

fn verify_decryption_response(
    decr_lkups : &DecryptionLookups,
    prf        : &ProofG1,
    auth_dks   : &HashMap<SharedParamKey, AuthorityDecryptionKey>,
    c_lbl      : CredentialLabel,
    a_idx      : CredAttrIndex,
    auth_label : SharedParamKey,
    DecryptResponse { value, decryption_proof } : &DecryptResponse
) -> VCPResult<()>
{
    let ix = (c_lbl.clone(), a_idx, auth_label.clone());
    let (s_idx,
         AuthorityPublicSetupData {
             chunk_bit_size, enc_gens, snark_proving_key, ..
    }) = lookup_throw_if_absent(&ix, decr_lkups, Error::General,
                                &["verify_decryption_response".to_string(),
                                  "attribute not encrypted".to_string()])?;
    let (ct,_)         = prf.get_saver_ciphertext_and_proof(*s_idx)
        .map_err(|e| Error::General(format!("DNC get_saver_ciphertext_and_proof {:?}", e)))?;
    let (decr_val, nu) = from_api(decryption_proof)?;
    let plain_text     = field_element_to_string(decr_val)?;
    if (plain_text.as_bytes() != value.as_bytes()) {
        return Err(Error::General(format!(
            "verifyDecryptResponse; decrypted value; {plain_text}; does not equal original value {value}; {c_lbl}; {a_idx}; {auth_label}")))
    };
    let dk_api = lookup_throw_if_absent(&auth_label, auth_dks, Error::General,
                                        &["verify_decryption_response".to_string(),
                                          "AuthorityDecryptionKey not found".to_string()])?;
    let dk : SaverDecryptionKey::<Bls12_381> = from_api(dk_api)?;
    ct.verify_decryption_given_groth16_vk(
        &decr_val,
        &nu,
        *chunk_bit_size,
        dk,
        &snark_proving_key.pk.vk,
        enc_gens.clone())
        .map_err(|e| Error::General(format!("DNC verify_decryption_given_groth16_vk {:?}", e)))
}

// This should be 0 for normal operation, but can be set to emulate a dishonest prover that lies
// about the value; see usage below for RangeProof case, also in Direct tests, which differ
// depending on how this is set.  TODO: think about how to enable configuring this at runtime;
// probably thread something akin to Loose/Strict through to here.
const RANGE_PROOF_CHEAT_OFFSET : u64 = 0;

#[allow(clippy::type_complexity)]
fn add_statement_and_maybe_witness(
    stmts      : &mut Statements::<Bls12_381>,
    witnesses  : &mut Witnesses::<Bls12_381>,
    sigs_mb    :
      &Option<HashMap<CredentialLabel,
                      (SignatureG1::<Bls12_381>,
                       Vec<DataValue>,
                       HashMap<CredAttrIndex, MembershipWitness::<G1>>)>>,
    decr_lkups : &mut DecryptionLookups,
    pig        : ProofInstructionGeneral<SupportedDisclosure>,
) -> VCPResult<()>
{
    let ProofInstructionGeneral { cred_label, attr_idx_general, related_pi_idx, discl_general } = pig;
    match discl_general
    {
        SupportedDisclosure::PoKofSignature(sig_pars, pk, schema, revealed_idxs_and_frs_for_cred) =>
        {
            if (attr_idx_general != POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES) {
                return Err(Error::General(format!(
                    "add_statement_and_maybe_witness; INTERNAL ERROR; PoK statement attribute index {cred_label}; {attr_idx_general}")));
            }

            let revealed = revealed_idxs_and_frs_for_cred
                .iter()
                .map(|(i,fr)| (*i as usize, *fr))
                .collect();
            if let Some(sigs) = sigs_mb {
                stmts.add(bbs_plus::PoKBBSSignatureG1Prover::new_statement_from_params(*sig_pars, revealed));
                let (sig, vals, _) = lookup_throw_if_absent(
                    &cred_label, sigs, Error::General,
                    &["add_statement_and_maybe_witness".to_string(), "PoKofSig".to_string(),
                      "no signature for credential".to_string()])?;
                let frs = generate_frs_from_vals_and_ct(vals, &schema, "add_statement_and_maybe_witness")?;
                add_pok_witness_new(witnesses, ((sig, frs), revealed_idxs_and_frs_for_cred));
            } else {
                stmts.add(bbs_plus::PoKBBSSignatureG1Verifier::new_statement_from_params(*sig_pars, *pk, revealed));
            }
            Ok(())
        },

        SupportedDisclosure::InAccumProof(acc_pars, acc_pk, mpk, acc_val, _seq_num) =>
        {
            stmts.add(VBAccumulatorMembership::new_statement_from_params(*acc_pars, *acc_pk, *mpk, *acc_val.value()));
            if let Some(sigs) = sigs_mb {
                let (_, vals, acc_wits) = get_sig_vals_wits(sigs, &cred_label)?;
                let fr                  = generate_fr_from_val_and_ct((&ClaimType::CTAccumulatorMember,
                                                                       get_data_value(vals, attr_idx_general)?))?;
                let mem_wit             = get_accum_wit(acc_wits, &attr_idx_general)?;
                // Note: this clone is necessary since the witness will live in two different maps.
                witnesses.add(Membership::new_as_witness(fr, (*mem_wit).clone()));
            }
            Ok(())
        },

        SupportedDisclosure::RangeProof(snark_pk, min, max) =>
        {
            // DNC has changed so that it now interprets intervals for range proof requests as right
            // open, e.g., if min = 10 and max = 20, an attribute value of 20 would previously have
            // passed the test, but now it would fail.  See discussion in this DNC issue:
            // https://github.com/docknetwork/crypto/issues/27
            // For consistency of interpretation at the level of abstract presentation requirements,
            // we add one to the upper bound of the requested range before creating the
            // corresponding DNC statement.
            let max = max.checked_add(1).ok_or(
                Error::General(ic_semi(&str_vec_from!("add_statement_and_maybe_witness",
                                                      "overflow when adjusting range maximum for right-open range"))))?;
            let rng_prf_stmt = match sigs_mb {
                None      => BoundCheckVerifierStmt::new_statement_from_params(min, max, snark_pk.vk)
                    .map_err(|e| Error::General(format!("DNC add_statement_and_maybe_witness RangeProof None {:?}", e)))?,
                (Some(_)) =>   BoundCheckProverStmt::new_statement_from_params(min, max, *snark_pk)
                    .map_err(|e| Error::General(format!("DNC add_statement_and_maybe_witness RangeProof Some {:?}", e)))?,
            };
            stmts.add(rng_prf_stmt);
            if let Some(sigs) = sigs_mb {
                let (_, vals,_acc_wits) = get_sig_vals_wits(sigs, &cred_label)?;
                let val                 = get_data_value(vals, attr_idx_general)?;
                let val_p               = match val {
                    // rangeProofCheatOffset enables emulating cheating Prover; see comment at definition
                    DataValue::DVInt(v) =>
                        DataValue::DVInt(v + RANGE_PROOF_CHEAT_OFFSET),
                    x                   =>
                        return Err(Error::General(format!(
                            "add_statement_and_maybe_witness; RangeProof is only for DVInt; {x}"))),
                };
                if (RANGE_PROOF_CHEAT_OFFSET != 0) {
                    println!("WARNING: Prover is offsetting value for range proof by {RANGE_PROOF_CHEAT_OFFSET}");
                }
                witnesses.add(Witness::BoundCheckLegoGroth16(generate_fr_from_val_and_ct((&ClaimType::CTInt, &val_p))?));
            }
            Ok(())
        },

        SupportedDisclosure::EncryptedForProof(auth_pub_spk, auth_pub_data) =>
        {
            let (AuthorityPublicSetupData { chunk_bit_size, chunked_comm_gens, enc_gens,
                                            encryption_key, snark_proving_key}) = *auth_pub_data.clone();
            let enc_for_stmt = match sigs_mb {
                None      => SaverVerifier::new_statement_from_params(
                    chunk_bit_size, enc_gens, chunked_comm_gens, encryption_key, snark_proving_key.pk.vk)
                    .map_err(|e| Error::General(format!("DNC add_statement_and_maybe_witness EncryptedForProof None {:?}", e)))?,
                (Some(_)) =>   SaverProver::new_statement_from_params(
                    chunk_bit_size, enc_gens, chunked_comm_gens, encryption_key, snark_proving_key)
                    .map_err(|e| Error::General(format!("DNC add_statement_and_maybe_witness EncryptedForProof Some {:?}", e)))?,
            };
            let stmt_idx = stmts.len();
            stmts.add(enc_for_stmt);
            if let Some(sigs) = sigs_mb {
                let (_, vals, _) = get_sig_vals_wits(sigs, &cred_label)?;
                let val          = get_data_value(vals, attr_idx_general)?;
                witnesses.add(Witness::Saver(generate_fr_from_val_and_ct((&ClaimType::CTEncryptableText, val))?));
            }
            let ix = (cred_label, attr_idx_general, auth_pub_spk);
            decr_lkups.insert(ix, (stmt_idx, *auth_pub_data));
            Ok(())
        },
    }
}

fn get_sig_vals_wits<'a>(
    sigs  : &'a HashMap<CredentialLabel,  (ImplSignature, Vec<DataValue>, AccumWitnesses)>,
    c_lbl : &'a CredentialLabel,
) -> VCPResult<&'a (ImplSignature, Vec<DataValue>, AccumWitnesses)>
{
    lookup_throw_if_absent(c_lbl, sigs, Error::General,
                           &["add_statement_and_maybe_witness".to_string(), "getSigValsWits".to_string()])
}

fn get_data_value(
    vals  : &[DataValue],
    a_idx : CredAttrIndex
) -> VCPResult<&DataValue>
{
    lookup_throw_if_out_of_bounds(vals, a_idx as usize, Error::General,
                                  &["add_statement_and_maybe_witness".to_string(),
                                    "getDataValue".to_string(),
                                    "UNEXPECTED".to_string()])
}

fn get_accum_wit<'a>(
    wits  : &'a AccumWitnesses,
    a_idx : &'a CredAttrIndex
) -> VCPResult<&'a MembershipWitness::<G1>>
{
    lookup_throw_if_absent(a_idx, wits, Error::General,
                           &["add_statement_and_maybe_witness".to_string(), "getAccumWit".to_string()])
}

fn convert_vals_to_be_revealed_for_dnc(
    idxs_vals_and_cts : &HashMap<u64, (DataValue, ClaimType)>
) -> VCPResult<Vec<(CredAttrIndex, Fr)>>
{
    let frs = idxs_vals_and_cts
        .iter()
        .map(|(ai, (dv,ct))| generate_fr_from_val_and_ct((ct,dv)))
        .collect::<VCPResult<Vec<_>>>()?;
    let result = idxs_vals_and_cts.iter().zip(frs)
        .map(|((ai, _),fr)| (*ai, fr))
        .collect::<Vec<_>>();
    Ok(result)
}

fn transform_resolved_disclosure(
    prf_instr : &ProofInstructionGeneral<ResolvedDisclosure>,
) -> VCPResult<Validation<ProofInstructionGeneral<SupportedDisclosure>>>
{
    let ProofInstructionGeneral { cred_label, attr_idx_general, related_pi_idx, discl_general } = prf_instr;
    match discl_general {
        ResolvedDisclosure::CredentialResolvedWrapper
            (CredentialResolved { issuer_public, rev_idxs_and_vals }) =>
        {
            let (sig_pars, pk) = from_api(&issuer_public.signer_public_setup_data)?;
            let frs            = convert_vals_to_be_revealed_for_dnc(rev_idxs_and_vals)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::PoKofSignature
                    (Box::new(sig_pars),
                     Box::new(pk),
                     issuer_public.signer_public_schema.to_vec(),
                     frs)}))
        },

        ResolvedDisclosure::InRangeResolvedWrapper
            (InRangeResolved { min_val, max_val, proving_key }) =>
        {
            let prv_key = from_api(proving_key)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::RangeProof
                    (Box::new(prv_key), *min_val, *max_val)}))
        },

        ResolvedDisclosure::InAccumResolvedWrapper
            (InAccumResolved { public_data, mem_prv, accumulator, seq_num }) =>
        {
            let (asp, apk) = from_api(public_data)?;
            #[cfg(not(feature="in_memory_state"))]
            let accumulator = from_api(accumulator)?;
            #[cfg(feature="in_memory_state")]
            let (accumulator, _ims) = from_api(accumulator)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::InAccumProof
                    (Box::new(asp),
                     Box::new(apk),
                     Box::new(from_api(mem_prv)?),
                     accumulator,
                     *seq_num)}))
        },

        ResolvedDisclosure::EncryptedForResolvedWrapper
            (EncryptedForResolved { auth_pub_spk, auth_pub_data }) =>
        {
            let apd = from_api(auth_pub_data)?;
            Ok(success(ProofInstructionGeneral {
                cred_label       : cred_label.clone(),
                attr_idx_general : *attr_idx_general,
                related_pi_idx   : *related_pi_idx,
                discl_general    : SupportedDisclosure::EncryptedForProof
                    (auth_pub_spk.to_string(), Box::new(apd))}))
        },
    }
}

// Here we could apply optimisations,
// (e.g., when a proof is requested for two attributes that are required to be equal)
// but based on resolved params, not only sharedParamKeys.
// HOWEVER, can't this be done at the General level?
fn optimize_supported_disclosures(
    x : Vec<ProofInstructionGeneral<SupportedDisclosure>>
) ->    Vec<ProofInstructionGeneral<SupportedDisclosure>>
{
    x
}

fn get_supported_disclosures(
    prf_mode   : bool,
    prf_instrs : &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<WarningsAndResult<Vec<ProofInstructionGeneral<SupportedDisclosure>>>>
{
    let WarningsAndResult { warnings, result } = transform_instructions(prf_mode, prf_instrs)?;
    Ok (WarningsAndResult { warnings, result : optimize_supported_disclosures(result) })
}

#[allow(clippy::type_complexity)]
fn proof_spec_from(
    prf_mode   : bool,
    prf_instrs : &Vec<ProofInstructionGeneral<ResolvedDisclosure>>,
    eqs        : &EqualityReqs,
    sigs_and_related_data_mb : Option<&HashMap<CredentialLabel, SignatureAndRelatedData>>,
) -> VCPResult<(WarningsAndResult<(ProofSpec::<Bls12_381>, Option<Witnesses<Bls12_381>>)>,
                DecryptionLookups)>
{
    let WarningsAndResult {warnings, result : dnc_instrs_opt} =
        get_supported_disclosures(prf_mode, prf_instrs)?;
    let sards_mb = if let Some(z) = sigs_and_related_data_mb {
        Some(z
             .iter()
             .map(|(k,v)| { from_api(v).map(|x| (k.to_string(),x)) })
             .collect::<Result<HashMap<_,_>,_>>()?)
    } else {
        None
    };
    let (statements, witnesses, decr_lkups) =
        create_statements_and_maybe_witnesses(
            dnc_instrs_opt, &sards_mb)?;
    let meta_statements = create_meta_statements(prf_instrs, eqs)?;
    let ps              = ProofSpec::new(statements, meta_statements, vec![], Some("context".into()));
    Ok((WarningsAndResult { warnings, result : (ps, Some(witnesses)) },
        decr_lkups))
}

#[allow(clippy::type_complexity)]
fn create_statements_and_maybe_witnesses(
    l         : Vec<ProofInstructionGeneral<SupportedDisclosure>>,
    sigs_mb   :
      &Option<(HashMap<CredentialLabel,
                       (SignatureG1::<Bls12_381>,
                        Vec<DataValue>,
                        HashMap<CredAttrIndex, MembershipWitness::<G1>>)>)>
) -> VCPResult<(Statements::<Bls12_381>, Witnesses::<Bls12_381>, DecryptionLookups)>
{
    let mut decr_lkups = HashMap::new();
    let mut statements = Statements::<Bls12_381>::new();
    // TODO: avoid unnecessarily creating Witnesses in the case that sigs_mb is None.
    let mut witnesses  = Witnesses::<Bls12_381>::new();
    for pig in l {
        add_statement_and_maybe_witness(&mut statements, &mut witnesses, sigs_mb, &mut decr_lkups, pig);
    }
    // This makes explicit that witnesses are added if and only if SignatureAndRelatedData are
    // provided (signifying that this is being called by a prover).  This could potentially fail in
    // future if we contemplate constructing proofs that are not tied to signatures, but this would
    // imply a significant change in how proof requirements are expressed, so is not expected any
    // time soon.
    assert_eq!(witnesses.is_empty(), sigs_mb.is_none());
    Ok((statements,witnesses,decr_lkups))
}

fn add_implicit_equality_if_needed(
    meta_statements    : &mut MetaStatements,
    this_pi_idx        : StmtIndex,
    resolved_prf_instr : &ProofInstructionGeneral<ResolvedDisclosure>)
{
    let ProofInstructionGeneral
        { cred_label : _, attr_idx_general, related_pi_idx, discl_general : _ } = resolved_prf_instr;
    if (! is_cred_resolved(resolved_prf_instr)) {
        // This requires the 0th (only) witness of an "other" Statement (e.g., RangeProof or InAccum)
        // to be equal to the "attr_idx_general" attribute of the "related" PoKofSignature statement; in other
        // words, requires that the proof of the property is about the same value in the signed
        // credential
        let mut bts = BTreeSet::new();
        bts.insert( (this_pi_idx, 0) );
        bts.insert( (related_pi_idx.0 as usize, *attr_idx_general as usize) );
        meta_statements.add_witness_equality(EqualWitnesses(bts));
    }
}

fn create_meta_statements(
    prf_instrs : &Vec<ProofInstructionGeneral<ResolvedDisclosure>>,
    eqs        : &EqualityReqs,
) -> VCPResult<MetaStatements>
{
    let mut meta_statements  = MetaStatements::new();
    let equality_constraints = eqs.iter().map(|x| go_eq(prf_instrs, x)).collect::<VCPResult<Vec<_>>>()?;
    for ecs in equality_constraints {
        let bts = ecs.iter().map(|(ecl,ecr)| (*ecl as usize,*ecr as usize)).collect();
        meta_statements.add_witness_equality(EqualWitnesses(bts));
    }
    for (i, pig) in prf_instrs.iter().enumerate() {
        add_implicit_equality_if_needed(&mut meta_statements, i, pig);
    }
    Ok(meta_statements)
}

// Replace the CredentialLabels with the index of their associated PoKofSignature statement
fn go_eq(
    prf_instrs : &Vec<ProofInstructionGeneral<ResolvedDisclosure>>,
    eq_req     : &EqualityReq
) -> VCPResult<Vec<(u64, u64)>> {
    let mut v  = Vec::<(u64,u64)>::new();
    let lu     = lkups(prf_instrs);
    for (c_lbl, b) in eq_req {
        let x = lookup_throw_if_absent(c_lbl, &lu, Error::General,
                                       &["create_meta_statements".to_string()])?;
        v.push( (x.related_pi_idx.0, *b) );
    }
    Ok(v)
}

fn lkups(
    prf_instrs : &Vec<ProofInstructionGeneral<ResolvedDisclosure>>,
) -> HashMap<CredentialLabel, ProofInstructionGeneral<ResolvedDisclosure>>
{
    let mut hm = HashMap::new();
    for pig in prf_instrs {
        if is_cred_resolved(pig) {
            hm.insert(pig.cred_label.clone(), pig.clone());
        };
    }
    hm
}

#[allow(clippy::type_complexity)]
fn add_pok_witness_new(
    wits : &mut Witnesses::<Bls12_381>,
    ((sig, all_frs), revealed_idxs_and_frs) : ((&SignatureG1::<Bls12_381>, Vec<Fr>), Vec<(u64, Fr)>)
)
{
    let revealed_indices        = revealed_idxs_and_frs.iter().map(|(i, _)| *i).collect::<Vec<u64>>();
    let (unrevealed, _revealed) = partition_frs(revealed_indices, all_frs);
    wits.add(PoKSignatureBBSG1Wit::new_as_witness(sig.clone(), unrevealed));
}

#[derive(Debug)]
enum SupportedDisclosure {
    PoKofSignature(Box<SignatureParamsG1<Bls12_381>>,
                   Box<PublicKeyG2<Bls12_381>>,
                   Vec<ClaimType>,
                   Vec<(u64, Fr)>),
    RangeProof(Box<legogroth16::ProvingKey<Bls12_381>>,
               u64,
               u64),
    EncryptedForProof(SharedParamKey,
                      Box<AuthorityPublicSetupData>),
    // So far, only PositiveAccumulator is supported, but in general, InAccum requirements could apply
    // to Universal accumulators, different kinds of accumulators, etc.  In this case, I think we'd
    // have multiple InAccum variants in SupportedDisclosure, but not necessarily multiple InAccum
    // variants in Disclosure.  The difference would be distinguished using accumulator public info,
    // which might be extended to indicate accumulator type.
    InAccumProof(Box<VbaSetupParams::<Bls12_381>>,
                 Box<VbaPublicKey::<Bls12_381>>,
                 Box<MembershipProvingKey::<G1>>,
                 PositiveAccumulator::<G1Affine>,
                 AccumulatorBatchSeqNo),
}

fn transform_instructions(
    prf_mode   : bool,
    prf_instrs : &[ProofInstructionGeneral<ResolvedDisclosure>],
) -> VCPResult<WarningsAndResult<Vec<ProofInstructionGeneral<SupportedDisclosure>>>>
{
    let (warnings0, instrs): (
        Vec<Warning>,
        Vec<ProofInstructionGeneral<SupportedDisclosure>>,
    ) = prf_instrs
        .iter()
        .map(transform_resolved_disclosure)
        .try_partition(|res| {
            res.map(|v| match v {
                Err(warn)     => PartitionItem::Left(warn),
                Ok(prf_instr) => PartitionItem::Right(prf_instr),
            })
        })?;
    Ok(WarningsAndResult { warnings: warnings0, result: instrs, })
}

fn partition_frs(
    revealed_indices : Vec<u64>,
    all_frs          : Vec<Fr>,
) -> (BTreeMap<usize, Fr>, BTreeMap<usize, Fr>)
{
    let mut unrevealed = BTreeMap::new();
    let mut revealed   = BTreeMap::new();
    for (i, fr) in all_frs.iter().enumerate() {
        if revealed_indices.contains(&(i as u64)) {
            revealed.insert  (i, all_frs[i]);
        } else {
            unrevealed.insert(i, all_frs[i]);
        }
    }
    (unrevealed, revealed)
}

