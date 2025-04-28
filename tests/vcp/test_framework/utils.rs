// -----------------------------------------------------------------------------
use credx::str_vec_from;
use credx::vcp::{Error, VCPResult};
use credx::vcp::api;
use credx::vcp::r#impl::util::*;
// -----------------------------------------------------------------------------
use crate::vcp::test_framework::steps::*;
use crate::vcp::test_framework::types::*;
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs::File;
use std::path::*;
// -----------------------------------------------------------------------------

lazy_static! {
    pub static ref INITIAL_TEST_STATE: TestState = TestState {
        sparms: HashMap::new(),
        all_signer_data: HashMap::new(),
        all_blind_signing_info: HashMap::new(),
        sigs_and_rel_data: HashMap::new(),
        accum_witnesses: HashMap::new(),
        accums: HashMap::new(),
        all_authority_data: HashMap::new(),
        decrypt_requests: HashMap::new(),
        preqs: HashMap::new(),
        warnings_and_data_for_verifier: api::WarningsAndDataForVerifier {
            warnings: vec![],
            data_for_verifier: api::DataForVerifier {
                revealed_idxs_and_vals: HashMap::new(),
                proof: api::Proof("NO PROOF CREATED YET".to_string()),
            }
        },
        verification_warnings: vec![],
        last_decrypt_responses: HashMap::new(),
    };
}


#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TestSequenceWithMetadata {
    pub descr: String,
    pub comment: Option<String>,
    pub provenance: Option<String>,
    pub testseq: TestSequence
}

pub fn start_test(platform_api: &api::PlatformApi, t_seq: TestSequence) -> VCPResult<TestState> {
    pprintln(
        "start_test.t_seq",
        &t_seq
            .iter()
            .map(|t| format!(" - {:?}", t))
            .collect::<Vec<_>>()
            .join("\n")
            .to_string(),
    );
    let mut test_state = INITIAL_TEST_STATE.to_owned();
    extend_test(platform_api, t_seq, &mut test_state)?;
    Ok(test_state)
}

pub fn extend_test(
    platform_api: &api::PlatformApi,
    t_seq: TestSequence,
    t_st: &mut TestState,
) -> VCPResult<()> {
    for t_step in t_seq {
        match t_step {
            TestStep::CreateIssuer(i_lbl, schema, blind_attr_idxs, proof_mode) => {
                (*step_create_issuer(platform_api, i_lbl, schema, blind_attr_idxs, proof_mode))(t_st)?
            }
            TestStep::CreateAccumulators(i_lbl) => {
                (*step_create_accumulators_for_issuer(platform_api, i_lbl))(t_st)?
            }
            TestStep::SignCredential(i_lbl, h_lbl, vals, attr_max_off_mb, prf_mode) => {
                (*step_sign_credential(platform_api, i_lbl, h_lbl, vals, attr_max_off_mb, prf_mode))(t_st)?
            }
            TestStep::CreateBlindSigningInfo(h_lbl, i_lbl, vals, proof_mode) => {
                (*step_create_blind_signing_info(platform_api, h_lbl, i_lbl, vals, proof_mode))(t_st)?
            }
            TestStep::SignCredentialWithBlinding(i_lbl, h_lbl, vals, proof_mode) => {
                (*step_sign_credential_with_blinding(platform_api, i_lbl, h_lbl, vals, proof_mode))(t_st)?
            }
            TestStep::AccumulatorAddRemove(i_lbl, a_idx, adds, removes) => {
                (*step_accumulator_add_remove(platform_api, i_lbl, a_idx,
                                              adds, removes))(t_st)?
            }
            TestStep::UpdateAccumulatorWitness(h_lbl, i_lbl, a_idx, seq_no) => {
                (*step_update_accumulator_witness(platform_api, h_lbl, i_lbl, a_idx, seq_no))(t_st)?
            }
            TestStep::Reveal(h_lbl, i_lbl, idxs) => {
                (*step_reveal(platform_api, h_lbl, i_lbl, idxs))(t_st)?
            }
            TestStep::InRange(h_lbl, i_lbl, idx, min_v, max_v, max_off) => {
                (*step_in_range(platform_api, h_lbl, i_lbl, idx, min_v, max_v, max_off))(t_st)?
            }
            TestStep::InAccum(h_lbl, i_lbl, idxs, sn) => {
                (*step_in_accum(platform_api, h_lbl, i_lbl, idxs, sn))(t_st)?
            }
            TestStep::Equality(h_lbl, i_lbl, a_idx, eqs) => {
                (*step_equality(h_lbl, i_lbl, a_idx, eqs))(t_st)?
            }
            TestStep::CreateAndVerifyProof(h_lbl, proof_mode, test_exp) => {
                (*step_create_and_verify_proof(platform_api, h_lbl, proof_mode, test_exp))(t_st)?
            }
            TestStep::CreateAuthority(a_lbl) => {
                (*step_create_authority(platform_api, a_lbl))(t_st)?
            }
            TestStep::EncryptFor(h_lbl, i_lbl, a_idx, a_lbl) => {
                (*step_encrypt_for(h_lbl, i_lbl, a_idx, a_lbl))(t_st)?
            }
            TestStep::Decrypt(h_lbl, i_lbl, a_idx, a_lbl) => {
                (*step_decrypt(h_lbl, i_lbl, a_idx, a_lbl))(t_st)?
            }
            TestStep::VerifyDecryption(h_lbl, proof_mode) => {
                (*step_verify_decryption(platform_api, h_lbl, proof_mode))(t_st)?
            }
        };
    };
    Ok(())
}

pub fn start_test_with_metadata(
    platform_api: &api::PlatformApi,
    TestSequenceWithMetadata { testseq: tseq, ..}:
    TestSequenceWithMetadata
) -> VCPResult<TestState> {
    start_test(platform_api, tseq)
}

pub fn run_test_from_json_file(
    platform_api: &api::PlatformApi,
    filename: String
) -> VCPResult<TestState> {
    let tswmd: TestSequenceWithMetadata = get_test_sequence_and_validate_name(filename)?;
    start_test_with_metadata(platform_api,tswmd)
}

fn get_test_sequence_and_validate_name(filename: String) -> VCPResult<TestSequenceWithMetadata> {
    let json_test_prefix = "json_test_";
    let json_test_suffix = ".json";
    let r#fn = Path::new(&filename)
        .file_name()
        .ok_or(Error::General(format!("No filename found in {filename}")))?
        .to_str()
        .ok_or(Error::General(format!("Can't convert {filename} to String")))?;
    if !r#fn.starts_with(json_test_prefix) {
        return Err(Error::General(ic_semi(&str_vec_from!("getNameAndTestSequence", "expected prefix",
                                                         json_test_prefix, "not found in", r#fn))))
    };
    if !r#fn.ends_with(json_test_suffix) {
        return Err(Error::General(ic_semi(&str_vec_from!("getNameAndTestSequence", "expected suffix",
                                                         json_test_suffix, "not found in", r#fn))))
    };
    let f_in = File::open(filename.clone()).map_err(|e| Error::FileError(e.to_string()))?;
    let tswmd: TestSequenceWithMetadata =
        serde_json::from_reader(f_in).map_err(|e| Error::FileError(e.to_string()))?;
    let fn_base = Path::new(&filename)
        .file_stem()
        .ok_or(Error::General(format!("No file stem found in {filename}")))?
        .to_str()
        .ok_or(Error::General(format!("Can't convert {filename} to String")))?
    .to_string();
    let descr = tswmd.clone().descr;
    if !upper_case_slow(fn_base).ends_with(&upper_case_slow(descr.clone())) {
        return Err(Error::General(format!(
            "ERROR: test description ({descr}) does not match filename ({filename})")));
    };
    Ok(tswmd)
}

#[macro_export]
macro_rules! make_test {
    ($id: ident, $res_ts: expr) => {
        #[test]
        pub fn $id() {
            $crate::vcp::r#impl::test_framework::test_framework_core::run_test($res_ts)
        }
    }
}

pub fn run_test(platform_api: &api::PlatformApi, t_seq: TestSequence) {
    start_test(platform_api, t_seq).unwrap(); // Errors thrown from PresentationSetupRequestSetup end up here
}

pub fn upper_case_slow (s: String) -> String {
        s.replace("slow","SLOW")
}
