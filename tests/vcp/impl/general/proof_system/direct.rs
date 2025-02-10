// ----------------------------------------------------------------------------
use credx::vcp::api;
// ----------------------------------------------------------------------------
use crate::vcp::r#impl::general::{proof_system::test_data as td, testing_framework as tf};
// ----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
// ----------------------------------------------------------------------------

#[macro_export]
macro_rules! per_crypto_library_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod spec {
            // -----------------------------------------------------------------------------
            use $crate::vcp::r#impl::general::proof_system::test_data as td;
            use $crate::vcp::r#impl::general::proof_system::utils::*;
            use $crate::vcp::r#impl::general::proof_system::direct::*;
            // -----------------------------------------------------------------------------
            use credx::vcp::r#impl::util::*;
            use credx::vcp::types::*;
            use credx::vcp::*;
            // -----------------------------------------------------------------------------
            use lazy_static::*;
            use maplit::*;
            use std::collections::*;
            // -----------------------------------------------------------------------------

            $crate::pok_and_reveal_metadata_spec! { $platform_api }
            $crate::sign_create_verify_spec! { $platform_api, $lib_spec }
            // decrReqUnitSpec
            // accumAddRemoveSpec
            $crate::look_at_warnings_spec! { $platform_api, $lib_spec }
        }
    };
}

pub fn sign_d_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
    tf::TestStep::SignCredential(td::D_ISSUER_LABEL.to_owned(), h_lbl, td::D_VALS.to_owned())
}

pub fn sign_s_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
    tf::TestStep::SignCredential(td::S_ISSUER_LABEL.to_owned(), h_lbl, td::S_VALS.to_owned())
}

lazy_static! {
    pub static ref CREATE_D_ISSUER: tf::TestStep =
        tf::TestStep::CreateIssuer(td::D_ISSUER_LABEL.to_owned(), td::D_CTS_WITH_VE.to_vec());
    pub static ref CREATE_S_ISSUER: tf::TestStep =
        tf::TestStep::CreateIssuer(td::S_ISSUER_LABEL.to_owned(), td::S_CTS.to_vec());
    pub static ref CREATE_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::CreateAuthority(td::POLICE_AUTHORITY_LABEL.to_owned());
    pub static ref ENCRYPT_FOR_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::EncryptFor(td::HOLDER_1.to_owned(),
                                 td::D_ISSUER_LABEL.to_owned(),
                                 td::D_SSN_IDX,
                                 td::POLICE_AUTHORITY_LABEL.to_owned());
    pub static ref DECRYPT_FOR_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::Decrypt(td::HOLDER_1.to_owned(),
                              td::D_ISSUER_LABEL.to_owned(),
                              td::D_SSN_IDX,
                              td::POLICE_AUTHORITY_LABEL.to_owned());
}

mod tests {
    use crate::vcp::r#impl::general::testing_framework::run_json_test_ac2c;

    //  Note: the directory path must be given statically, as it is read directly
    //    at compile-time and not evaluated (so, don't try to define a const for
    //    "./tests/data/JSON/TestSequences" somewhere).
    generate_tests_from_json::map_test_over_dir! { run_json_test_ac2c,
                                                   "./tests/data/JSON/TestSequences/LicenseSubscription",
                                                   "./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json"
    }
}

lazy_static! {
    pub static ref CREATE_ISSUERS: Vec<tf::TestStep> =
        vec![CREATE_D_ISSUER.to_owned(), CREATE_S_ISSUER.to_owned()];
    pub static ref CREATE_ACCUMS: Vec<tf::TestStep> = vec![
        tf::TestStep::CreateAccumulators(td::D_ISSUER_LABEL.to_owned()),
        tf::TestStep::CreateAccumulators(td::S_ISSUER_LABEL.to_owned())
    ];
    pub static ref SIGN_CREDS: Vec<tf::TestStep> = vec![
        sign_d_cred("Holder1".to_string()),
        sign_s_cred("Holder1".to_string()),
    ];
    pub static ref REVEAL_METADATA: Vec<tf::TestStep> = vec![
        tf::TestStep::Reveal(
            "Holder1".to_string(),
            td::D_ISSUER_LABEL.to_owned(),
            vec![td::D_META_IDX]
        ),
        tf::TestStep::Reveal(
            "Holder1".to_string(),
            td::S_ISSUER_LABEL.to_owned(),
            vec![td::S_META_IDX]
        )
    ];
    pub static ref COMMON_SETUP: Vec<tf::TestStep> = [
        CREATE_ISSUERS.to_owned(),
        CREATE_ACCUMS.to_owned(),
        SIGN_CREDS.to_owned(),
        REVEAL_METADATA.to_owned()
    ]
    .concat();
    pub static ref PROOF_SUCCEEDS: Vec<tf::TestStep> = vec![tf::TestStep::CreateAndVerifyProof(
        "Holder1".to_string(),
        tf::CreateVerifyExpectation::BothSucceedNoWarnings
    )];
    pub static ref PROOF_FAILS: Vec<tf::TestStep> = vec![tf::TestStep::CreateAndVerifyProof(
        "Holder1".to_string(),
        tf::CreateVerifyExpectation::CreateOrVerifyFails
    )];
    pub static ref POK_AND_REVEAL_METADATA: Vec<tf::TestStep> =
        [COMMON_SETUP.to_owned(), PROOF_SUCCEEDS.to_owned()].concat();
    pub static ref ADD_TO_ACCUMS: Vec<tf::TestStep> = vec![
        tf::TestStep::AccumulatorAddRemove(
            td::D_ISSUER_LABEL.to_owned(),
            td::D_ACCUM_IDX,
            hashmap!(td::HOLDER_1.to_owned() => td::D_VALS[td::D_ACCUM_IDX as usize].to_owned()),
            vec![]
        ),
        tf::TestStep::AccumulatorAddRemove(
            td::S_ISSUER_LABEL.to_owned(),
            td::S_ACCUM_IDX,
            hashmap!(td::HOLDER_1.to_owned() => td::D_VALS[td::S_ACCUM_IDX as usize].to_owned()),
            vec![]
        )
    ];
}

// This is here to satisfy type requirements but will need to be updated for real tests
pub const SOME_SEQUENCE_NUMBER: api::AccumulatorBatchSeqNo = 99;

lazy_static! {
    pub static ref IN_ACCUM_REQS: Vec<tf::TestStep> = vec![
        tf::TestStep::InAccum(
            "Holder1".to_string(),
            td::D_ISSUER_LABEL.to_owned(),
            td::D_ACCUM_IDX,
            SOME_SEQUENCE_NUMBER
        ),
        tf::TestStep::InAccum(
            "Holder1".to_owned(),
            td::S_ISSUER_LABEL.to_owned(),
            td::S_ACCUM_IDX,
            SOME_SEQUENCE_NUMBER
        )
    ];
    pub static ref SIGN_SECOND_DL: Vec<tf::TestStep> = vec![tf::TestStep::SignCredential(
        td::D_ISSUER_LABEL.to_owned(),
        "Holder2".to_owned(),
        td::D_VALS2.to_owned()
    )];
    pub static ref ADD_TO_ACCUM2: Vec<tf::TestStep> = vec![tf::TestStep::AccumulatorAddRemove(
        td::D_ISSUER_LABEL.to_owned(),
        td::D_ACCUM_IDX,
        hashmap!("Holder2".to_string() => td::D_VALS2[td::D_ACCUM_IDX as usize].to_owned()),
        vec![]
    )];
}

#[macro_export]
macro_rules! pok_and_reveal_metadata_spec {
    ($platform_api: expr) => {
        #[test]
        fn pok_and_reveal_metadata() {
            use $crate::vcp::r#impl::general::testing_framework::start_test;
            start_test($platform_api, POK_AND_REVEAL_METADATA.to_owned())
                .unwrap();
        }
    };
}

#[macro_export]
macro_rules! sign_create_verify_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod sign_create_verify {
            use super::*;

            $crate::pok_spec! { $platform_api, $lib_spec }
            $crate::revealed_spec! { $platform_api, $lib_spec }
            $crate::equalities_spec! { $platform_api, $lib_spec }
            $crate::range_spec! { $platform_api, $lib_spec }
            $crate::warnings_spec! { $platform_api, $lib_spec }
        }
    };
}

#[macro_export]
macro_rules! pok_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        #[test]
        fn pok_no_reveal() {
            let (_, _, d_sig_cd, s_sig_cd, shared) =
                do_create_signers_shared_and_sigs($platform_api);
            let proof_reqs: HashMap<CredentialLabel, CredentialReqs> = td::proof_reqs_with(
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect(
                $platform_api,
                $lib_spec,
                &proof_reqs,
                &shared,
                &d_sig_cd,
                &s_sig_cd,
                &hashmap!(),
            );
        }
    };
}

#[macro_export]
macro_rules! revealed_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod revealed_index_checks {
            use super::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs($platform_api);
                // Since destructuring is not allowed on LHS of a `static ref`
                // definition, must destructure `SHARED_AND_SIGS` as new
                // `static ref`s.
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            $crate::test_in_range! { $platform_api, $lib_spec, 0, revealed_0 }
            $crate::test_in_range! { $platform_api, $lib_spec, 3, revealed_3 }

            $crate::test_out_of_range! { $platform_api, $lib_spec, 5  , index_out_of_bounds_5   }
            $crate::test_out_of_range! { $platform_api, $lib_spec, 200, index_out_of_bounds_200 }
        }
    };
}

#[macro_export]
macro_rules! test_in_range {
    ($platform_api: expr, $lib_spec: expr, $i: expr, $name: ident) => {
        #[test]
        fn $name() {
            let proof_reqs = td::proof_reqs_with(
                (vec![$i], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect(
                $platform_api,
                $lib_spec,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                &hashmap!(),
            );
        }
    };
}

#[macro_export]
macro_rules! test_out_of_range {
    ($platform_api: expr, $lib_spec: expr, $i: expr, $name: ident) => {
        #[test]
        fn $name() {
            let proof_reqs = td::proof_reqs_with(
                (vec![$i], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect_create_proof_to_throw(
                $platform_api,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                |err| {
                    let err_str = format!("{err:?}");
                    let err_infix = format!("General(\"indexes; [{}]; out of range for; 5; attributes\")", $i);
                    assert!(
                        err_str.contains(&err_infix),
                        "expected error infix \"{err_infix}\" but the actual error is \"{err_str}\""
                    );
                    true
                },
            );
        }
    };
}

#[macro_export]
macro_rules! equalities_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        #[test]
        fn one_equality() {
            let (_, _, d_sig_cd, s_sig_cd, shared) =
                do_create_signers_shared_and_sigs($platform_api);
            let proof_reqs = td::proof_reqs_with(
                (vec![3], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (
                    vec![credx::vcp::types::EqInfo {
                        from_index: 2,
                        to_label: td::S_CRED_LABEL.to_string(),
                        to_index: 3,
                    }],
                    vec![credx::vcp::types::EqInfo {
                        from_index: 3,
                        to_label: td::D_CRED_LABEL.to_string(),
                        to_index: 2,
                    }],
                ),
                (vec![], vec![]),
            );
            expect(
                $platform_api,
                $lib_spec,
                &proof_reqs,
                &shared,
                &d_sig_cd,
                &s_sig_cd,
                &hashmap!(),
            );
        }

        // TODO: tests for when equalities _shouldn't_ hold
    };
}

#[macro_export]
macro_rules! range_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod range_proofs {
            use super::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs_with_additional_setup(add_rng_prv_key, $platform_api);
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            lazy_static! {
                static ref PROOF_REQS: HashMap<CredentialLabel, CredentialReqs> =
                    td::proof_reqs_with(
                        (vec![3], vec![0]),
                        (vec![], vec![]),
                        (
                            vec![InRangeInfo {
                                index: td::D_DOB_IDX.to_owned(),
                                min_label: MIN_BDDAYS_LBL.to_owned(),
                                max_label: MAX_BDDAYS_LBL.to_owned(),
                                proving_key_label: RPK_LBL.to_owned(),
                            }],
                            vec![InRangeInfo {
                                index: td::S_VALID_DAYS_IDX.to_owned(),
                                min_label: MIN_VALID_DAYS_LBL.to_owned(),
                                max_label: MAX_VALID_DAYS_LBL.to_owned(),
                                proving_key_label: RPK_LBL.to_owned(),
                            }],
                        ),
                        (vec![], vec![]),
                        (vec![], vec![]),
                    );
            }

            #[test]
            // TODO: use the slow_slow_test macro defined in utils
            #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            fn slowslow_in_range() {
                it_with($lib_spec, "RANGE_PROOF_IN_RANGE_GENERIC", || {
                    let shared = add_rng_params(SHARED.to_owned());
                    expect(
                        $platform_api,
                        $lib_spec,
                        &PROOF_REQS,
                        &shared,
                        &D_SIG_CD,
                        &S_SIG_CD,
                        &hashmap!(),
                    )
                });
            }

            #[test]
            // TODO: use the slow_slow_test macro defined in utils
            #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            fn slowslow_out_of_range_generic() {
                it_with($lib_spec, "RANGE_PROOF_OUT_OF_RANGE_GENERIC", || {
                    // Override minValiddays param *after* setting normal
                    // params, to ensure the range excludes the value in the
                    // credential.
                    let shared = add_rng_params_with_altered_range_to_exclude_signed_value(
                        SHARED.to_owned(),
                    );
                    expect_flow_to_be_unsuccessful(
                        $platform_api,
                        $lib_spec,
                        &PROOF_REQS,
                        &shared,
                        &D_SIG_CD,
                        &S_SIG_CD,
                        &hashmap!(),
                    );
                });
            }

            // This is not really generic since we currently expect a
            // DNC-specific exception.
            #[test]
            // TODO: use the slow_slow_test macro defined in utils
            #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            fn slowslow_out_of_range_honest_prover_should_refuse_to_create_proof() {
                it_with(
                    $lib_spec,
                    "RANGE_PROOF_OUT_OF_RANGE_SPECIFIC_EXCEPTIONS",
                    || {
                        let shared = add_rng_params_with_altered_range_to_exclude_signed_value(
                            SHARED.to_owned(),
                        );
                        expect_create_proof_to_throw(
                            $platform_api,
                            &PROOF_REQS,
                            &shared,
                            &D_SIG_CD,
                            &S_SIG_CD,
                            |err| {
                                let err_str = format!("{err:?}");
                                let err_infix = "proof_G1_new ProofG1::new: LegoGroth16Error(SynthesisError(Unsatisfiable))".to_string();
                                assert!(
                                    err_str.contains(&err_infix),
                                    "expected error infix \"{err_infix}\" but the actual error is \"{err_str}\""
                                );
                                true
                            },
                        );
                    },
                )
            }

            lazy_static! {
                static ref RPK_LBL: SharedParamKey = "rangeProvingKey".to_string();
                static ref MIN_BDDAYS_LBL: CredentialLabel = "minBDdays".to_string();
                static ref MAX_BDDAYS_LBL: CredentialLabel = "maxBDdays".to_string();
                static ref MIN_VALID_DAYS_LBL: CredentialLabel = "minValiddays".to_string();
                static ref MAX_VALID_DAYS_LBL: CredentialLabel = "maxValiddays".to_string();

                static ref S_VALID_DAYS_VAL: u64 = match td::S_VALS[td::S_VALID_DAYS_IDX as usize] {
                    DataValue::DVInt(v) => v,
                    _ => panic!("td::S_VALS[td::S_VALID_DAYS_IDX as usize] was not a DataValue::DVInt")
                };
            }

            fn add_rng_prv_key(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> VCPResult<HashMap<SharedParamKey, SharedParamValue>> {
                let rpk = ($platform_api.create_range_proof_proving_key)(0)?;
                // println!("add_rng_prv_key: rpk: {:?}", rpk);
                let s = serde_json::to_string(&rpk).unwrap();
                // println!("add_rng_prv_key: encoded: {:?}", s);
                shared.insert(
                    RPK_LBL.to_string(),
                    SharedParamValue::SPVOne(DataValue::DVText(s)),
                );
                Ok(shared)
            }

            fn add_rng_params(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> HashMap<SharedParamKey, SharedParamValue> {
                shared.insert(
                    MIN_BDDAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(37696)),
                );
                shared.insert(
                    MAX_BDDAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(999999999999)),
                );
                shared.insert(
                    MIN_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(0)),
                );
                shared.insert(
                    MAX_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(50000)),
                );
                shared
            }

            fn add_rng_params_with_altered_range_to_exclude_signed_value(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> HashMap<SharedParamKey, SharedParamValue> {
                shared = add_rng_params(shared);
                shared.insert(
                    MIN_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(S_VALID_DAYS_VAL.to_owned() + 1)),
                );
                shared
            }
        }
    };
}

#[macro_export]
macro_rules! warnings_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod warnings_spec {
            use super::*;

            $crate::reveal_privacy_warnings_spec! { $platform_api, $lib_spec }
        }
    };
}

#[macro_export]
macro_rules! reveal_privacy_warnings_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        // TODO: currently this Spec only expects warnings from general, but we
        // should also have a way of expecting library-specific warnings, which
        // would be used in a libary-specific test where we know what
        // library-specific warnings to expect.
        mod reveal_privacy_warnings {
            use super::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs($platform_api);
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            fn all_indices<T>(cts: Vec<T>) -> Vec<u64> {
                (0..cts.len() as u64).collect()
            }

            fn minus_vec<T: PartialEq>(v1: Vec<T>, v2: &[T]) -> Vec<T> {
                v1.into_iter().filter(|x| !v2.contains(x)).collect()
            }

            // this comes from `beforeAll(doCreateSignersSharedAndSigs platformAPI)`
            lazy_static! {
                pub static ref D_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::D_ACCUM_IDX];
                pub static ref S_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::S_ACCUM_IDX];

                pub static ref D_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                    minus_vec(D_CTS_ALL_INDICES.to_vec(), &D_CTS_WARNABLE_INDICES);
                pub static ref S_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                    minus_vec(S_CTS_ALL_INDICES.to_vec(), &S_CTS_WARNABLE_INDICES);

                pub static ref D_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                    td::D_CRED_LABEL.to_string(),
                    td::D_ACCUM_IDX,
                    "an accumulator member".to_string()
                )];
                pub static ref S_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                    td::S_CRED_LABEL.to_string(),
                    td::S_ACCUM_IDX,
                    "an accumulator member".to_string()
                )];

                pub static ref D_CTS_ALL_INDICES: Vec<u64> = all_indices(td::D_CTS.to_vec());
                pub static ref S_CTS_ALL_INDICES: Vec<u64> = all_indices(td::S_CTS.to_vec());
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTS_WARNABLE_INDICES,
                D_CTS_WARNABLE_INDICES.to_vec(),
                vec![],
                D_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTX_ALL_INDICES,
                D_CTS_ALL_INDICES.to_vec(),
                vec![],
                D_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTX_NON_WARNABLE_INDICES,
                D_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![],
                vec![]
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_S_CTS_WARNABLE_INDICES,
                vec![],
                S_CTS_WARNABLE_INDICES.to_vec(),
                S_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_S_CTX_ALL_INDICES,
                vec![],
                S_CTS_ALL_INDICES.to_vec(),
                S_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_S_CTX_NON_WARNABLE_INDICES,
                vec![],
                S_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![]
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTS_WARNABLE_INDICES_and_S_CTS_WARNABLE_INDICES,
                D_CTS_WARNABLE_INDICES.to_vec(),
                S_CTS_WARNABLE_INDICES.to_vec(),
                [D_ACCUM_WARNINGS.to_vec(), S_ACCUM_WARNINGS.to_vec()].concat()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTS_ALL_INDICES_and_S_CTS_ALL_INDICES,
                D_CTS_ALL_INDICES.to_vec(),
                S_CTS_ALL_INDICES.to_vec(),
                [D_ACCUM_WARNINGS.to_vec(), S_ACCUM_WARNINGS.to_vec()].concat()
            }

            $crate::expect_privacy_warnings!{
                $platform_api, $lib_spec, _revealed_D_CTS_NON_WARNABLE_INDICES_and_S_CTS_NON_WARNABLE_INDICES,
                D_CTS_NON_WARNABLE_INDICES.to_vec(),
                S_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![]
            }
        }
    };
}

#[macro_export]
macro_rules! expect_privacy_warnings {
    ($platform_api: expr, $lib_spec: expr, $suffix: ident, $d_revealed: expr, $s_revealed: expr, $ws: expr) => {
        #[test]
        #[allow(non_snake_case)]
        fn $suffix() {
            let proof_reqs = td::proof_reqs_with(
                ($d_revealed, $s_revealed),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            // println!(
            //     "expect_privacy_warnings: ws: {:?}",
            //     $ws as Vec<credx::vcp::types::Warning>
            // );
            expect_with_warnings(
                |ws2| {
                    pp("expect_privacy_warnings from createProof", ws2);
                    assert!($ws.iter().all(|w| ws2.contains(w)))
                },
                |ws2| {
                    pp("expect_privacy_warnings from verifyProof", ws2);
                    assert!($ws.iter().all(|w| ws2.contains(w)))
                },
                $platform_api,
                $lib_spec,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                &hashmap!(),
            )
        }
    };
}

#[macro_export]
macro_rules! look_at_warnings_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        fn all_indices<T>(cts: Vec<T>) -> Vec<u64> {
            (0..cts.len() as u64).collect()
        }

        fn minus_vec<T: PartialEq>(v1: Vec<T>, v2: &[T]) -> Vec<T> {
            v1.into_iter().filter(|x| !v2.contains(x)).collect()
        }

        // this comes from `beforeAll(doCreateSignersSharedAndSigs platformAPI)`
        lazy_static! {
            pub static ref D_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::D_ACCUM_IDX];
            pub static ref S_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::S_ACCUM_IDX];
            pub static ref D_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                minus_vec(D_CTS_ALL_INDICES.to_vec(), &D_CTS_WARNABLE_INDICES);
            pub static ref S_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                minus_vec(S_CTS_ALL_INDICES.to_vec(), &S_CTS_WARNABLE_INDICES);
            pub static ref D_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                td::D_CRED_LABEL.to_string(),
                td::D_ACCUM_IDX,
                "an accumulator member".to_string()
            )];
            pub static ref S_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                td::S_CRED_LABEL.to_string(),
                td::S_ACCUM_IDX,
                "an accumulator member".to_string()
            )];
            pub static ref D_CTS_ALL_INDICES: Vec<u64> = all_indices(td::D_CTS.to_vec());
            pub static ref S_CTS_ALL_INDICES: Vec<u64> = all_indices(td::S_CTS.to_vec());
        }

        #[test]
        fn look_at_warnings_spec() {
            print!(
                "D_CTS_WARNABLE_INDICES\n{:?}",
                D_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "S_CTS_WARNABLE_INDICES\n{:?}",
                S_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "D_CTS_NON_WARNABLE_INDICES\n{:?}",
                D_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "S_CTS_NON_WARNABLE_INDICES\n{:?}",
                S_CTS_WARNABLE_INDICES.to_owned()
            );
            print!("D_ACCUM_WARNINGS\n{:?}", D_ACCUM_WARNINGS.to_owned());
            print!("S_ACCUM_WARNINGS\n{:?}", S_ACCUM_WARNINGS.to_owned());
        }
    }
}
