// -----------------------------------------------------------------------------
use credx::vcp::r#impl::util::*;
use credx::vcp::{api, Error, VCPResult};
// -----------------------------------------------------------------------------
use crate::vcp::r#impl::general::testing_framework::{steps::*, types::*};
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs::File;

// -----------------------------------------------------------------------------

lazy_static! {
    pub static ref INITIAL_TEST_STATE: TestState = TestState {
        sparms: HashMap::new(),
        all_signer_data: HashMap::new(),
        sigs_and_rel_data: HashMap::new(),
        accum_witnesses: HashMap::new(),
        accums: HashMap::new(),
        all_authority_data: HashMap::new(),
        decrypt_requests: HashMap::new(),
        preqs: HashMap::new(),
        warnings_and_data_for_verifier: api::WarningsAndDataForVerifier {
            warnings: vec![],
            result: api::DataForVerifier {
                revealed_idxs_and_vals: HashMap::new(),
                proof: api::Proof("NO PROOF CREATED YET".to_string()),
            }
        },
        verification_warnings: vec![],
        last_decrypt_responses: HashMap::new(),
    };
}


#[derive(Debug, serde::Deserialize, serde::Serialize)]
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
                TestStep::CreateIssuer(i_lbl, schema) => {
                    (*step_create_issuer(platform_api, i_lbl, schema))(t_st)?
                }
                TestStep::CreateAccumulators(i_lbl) => {
                    (*step_create_accumulators_for_issuer(platform_api, i_lbl))(t_st)?
                }
                TestStep::SignCredential(i_lbl, h_lbl, vals) => {
                    (*step_sign_credential(platform_api, i_lbl, h_lbl, vals))(t_st)?
                }
                TestStep::AccumulatorAddRemove(i_lbl, a_idx, adds, removes) => {
                    (*step_accumulator_add_remove(platform_api, i_lbl, a_idx,
                                                  adds, removes))(t_st)?
                }
                TestStep::ReceiveInitialAccumulatorWitness(h_lbl, i_lbl, a_idx) => {
                    (*step_receive_initial_accumulator_witness(platform_api, h_lbl, i_lbl, a_idx))(t_st)?
                }
                TestStep::Reveal(h_lbl, i_lbl, idxs) => {
                    (*step_reveal(platform_api, h_lbl, i_lbl, idxs))(t_st)?
                }
                TestStep::InRange(h_lbl, i_lbl, idx, min_v, max_v) => {
                    (*step_in_range(platform_api, h_lbl, i_lbl, idx, min_v, max_v))(t_st)?
                }
                TestStep::InAccum(h_lbl, i_lbl, idxs, sn) => {
                    (*step_in_accum(platform_api, h_lbl, i_lbl, idxs, sn))(t_st)?
                }
                TestStep::Equality(h_lbl, i_lbl, a_idx, eqs) => {
                    (*step_equality(h_lbl, i_lbl, a_idx, eqs))(t_st)?
                }
                TestStep::CreateAndVerifyProof(h_lbl, test_exp) => {
                    (*step_create_and_verify_proof(platform_api, h_lbl, test_exp))(t_st)?
                }
                TestStep::UpdateAccumulatorWitness(h_lbl, i_lbl, a_idx, seq_no) => {
                    (*step_update_accumulator_witness(platform_api, h_lbl, i_lbl, a_idx, seq_no))(t_st)?
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
                TestStep::VerifyDecryption(h_lbl) => {
                    (*step_verify_decryption(platform_api, h_lbl))(t_st)?
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
    let f_in = File::open(filename).map_err(|e| Error::FileError(e.to_string()))?;
    let tswmd: TestSequenceWithMetadata =
        serde_json::from_reader(f_in).map_err(|e| Error::FileError(e.to_string()))?;
    start_test_with_metadata(platform_api,tswmd)
}

pub fn run_json_test_ac2c(file_path: &str) {
    if let Err(e) = run_test_from_json_file(
        &credx::vcp::api_utils::implement_platform_api_using(
            credx::vcp::r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C.to_owned()),
        file_path.to_string(),
    ) {
        panic!("run_json_test_ac2c failed with {:?}", e)
    }
}

#[macro_export]
macro_rules! make_test {
    ($id: ident, $res_ts: expr) => {
        #[test]
        pub fn $id() {
            $crate::vcp::r#impl::general::testing_framework::run_test($res_ts)
        }
    }
}

pub fn run_test(platform_api: &api::PlatformApi, t_seq: TestSequence) {
    start_test(platform_api, t_seq).unwrap();
}

