#![allow(unused_imports)]
// ------------------------------------------------------------------------------
use credx::vcp::*;
use credx::vcp::VCPResult;
use credx::vcp::r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C;
use crate::vcp::r#impl::general::{proof_system::test_data as td, testing_framework as tf};
// ------------------------------------------------------------------------------

crate::testing_framework_spec! {}

#[macro_export]
macro_rules! testing_framework_spec {
    () => {
        mod testing_framework {
            // -----------------------------------------------------------------
            use $crate::vcp::r#impl::general::testing_framework as tf;
            use $crate::vcp::r#impl::general::testing_framework_spec::*;
            use $crate::vcp::r#impl::general::proof_system::test_data as td;
            use $crate::vcp::r#impl::general::proof_system::direct::*;
            use $crate::vcp::r#impl::general::utility_functions::*;
            // -----------------------------------------------------------------
            // use credx::vcp::*;
            use credx::vcp::r#impl::util::*;
            use credx::vcp::{
                api_utils::implement_platform_api_using, r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C,
                types::*,
            };
            // -----------------------------------------------------------------
            use std::collections::HashMap;
            use std::collections::BTreeMap;
            use std::collections::BTreeSet;
            use maplit::{hashmap, btreemap, btreeset};
            use lazy_static::lazy_static;
            use std::hash::Hash;
            // -----------------------------------------------------------------

            fn sign_d_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
                tf::TestStep::SignCredential(td::D_ISSUER_LABEL.to_owned(), h_lbl, td::D_VALS.to_vec())
            }

            fn sign_s_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
                tf::TestStep::SignCredential(td::S_ISSUER_LABEL.to_owned(), h_lbl, td::S_VALS.to_vec())
            }

            $crate::test_framework_test_spec!{ AC2C, &implement_platform_api_using(CRYPTO_INTERFACE_AC2C.to_owned()), hashmap!() }
        }
    };
}

#[macro_export]
macro_rules! test_framework_test_spec {
    ($id: ident, $platform_api: expr, $lib_spec: expr) => {
        $crate::initial_test_via_new_framework_spec! { $platform_api, $lib_spec }
        $crate::pok_and_reveal_metadata_test_detailed_cond_spec! { $platform_api, $lib_spec }
        $crate::pok_and_reveal_metadata_test_spec! { $platform_api}
        $crate::pok_and_reveal_metadata_and_eqs_spec! { $platform_api}
        // temp'ly skip accum stuff until this actually impl'ed
        // $crate::accum_spec! { $platform_api}
    };
}

#[macro_export]
macro_rules! pok_and_reveal_metadata_test_spec {
    ($platform_api: expr) => {
        mod pok_and_reveal_metadata_test {
            use super::*;

            #[test]
            fn pok_and_reveal_metadata_test() {
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![tf::TestStep::CreateAndVerifyProof(
                            td::HOLDER_1.to_owned(),
                            tf::CreateVerifyExpectation::BothSucceedNoWarnings,
                        )],
                    ]
                    .concat(),
                )
            }

            #[should_panic]
            #[test]
            fn pok_and_reveal_metadata_test_expected_to_fail_1() {
                // Expects CreateProof to fail, but there is no reason for it to
                // fail, so this test should_panic
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![tf::TestStep::CreateAndVerifyProof(
                            td::HOLDER_1.to_owned(),
                            tf::CreateVerifyExpectation::CreateProofFails,
                        )],
                    ]
                    .concat(),
                )
            }

            #[should_panic]
            #[test]
            fn pok_and_reveal_metadata_test_expected_to_fail_2() {
                // Expects VerifyProof to fail, but there is no reason for it to
                // fail, so this test should_panic
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![tf::TestStep::CreateAndVerifyProof(
                            td::HOLDER_1.to_owned(),
                            tf::CreateVerifyExpectation::VerifyProofFails,
                        )],
                    ]
                    .concat(),
                )
            }

            #[should_panic]
            #[test]
            fn pok_and_reveal_metadata_test_expected_to_fail_3() {
                // Expects CreateProof OR VerifyProof to fail, but there is no reason for EITHER to
                // fail, so this test should_panic
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![tf::TestStep::CreateAndVerifyProof(
                            td::HOLDER_1.to_owned(),
                            tf::CreateVerifyExpectation::CreateOrVerifyFails,
                        )],
                    ]
                    .concat(),
                )
            }
        }
    };
}

#[macro_export]
macro_rules! pok_and_reveal_metadata_and_eqs_spec {
    ($platform_api: expr) => {
        mod pok_and_reveal_metadata_and_eqs {
            use super::*;

            #[test]
            fn pok_and_reveal_metadata_and_eqs() {
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![
                            tf::TestStep::Equality(
                                td::HOLDER_1.to_owned(),
                                td::D_ISSUER_LABEL.to_owned(),
                                td::D_SSN_IDX,
                                vec![(td::S_ISSUER_LABEL.to_owned(), td::S_SSN_IDX.to_owned())],
                            ),
                            tf::TestStep::CreateAndVerifyProof(
                                td::HOLDER_1.to_owned(),
                                tf::CreateVerifyExpectation::BothSucceedNoWarnings,
                            ),
                        ],
                    ]
                    .concat(),
                )
            }

            #[should_panic]
            #[test]
            fn pok_and_reveal_metadata_and_eqs_expected_to_fail_1() {
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![
                            tf::TestStep::Equality(
                                td::HOLDER_1.to_owned(),
                                td::D_ISSUER_LABEL.to_owned(),
                                td::D_ACCUM_IDX,
                                vec![(td::S_ISSUER_LABEL.to_owned(), td::S_SSN_IDX.to_owned())],
                            ),
                            tf::TestStep::CreateAndVerifyProof(
                                td::HOLDER_1.to_owned(),
                                tf::CreateVerifyExpectation::BothSucceedNoWarnings,
                            ),
                        ],
                    ]
                    .concat(),
                )
            }

            #[test]
            fn pok_and_reveal_metadata_and_eqs_equalities_not_equal() {
                tf::run_test(
                    $platform_api,
                    [
                        COMMON_SETUP.to_owned(),
                        vec![
                            tf::TestStep::Equality(
                                td::HOLDER_1.to_owned(),
                                td::D_ISSUER_LABEL.to_owned(),
                                td::D_ACCUM_IDX,
                                vec![(td::S_ISSUER_LABEL.to_owned(), td::S_SSN_IDX.to_owned())],
                            ),
                            tf::TestStep::CreateAndVerifyProof(
                                td::HOLDER_1.to_owned(),
                                tf::CreateVerifyExpectation::CreateOrVerifyFails,
                            ),
                        ],
                    ]
                    .concat(),
                )
            }
        }
    };
}

#[macro_export]
macro_rules! pok_and_reveal_metadata_test_detailed_cond_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod pok_and_reveal_metadata_test_detailed_cond {
            use super::*;

            lazy_static! {
                static ref TS: tf::TestState =
                    tf::start_test($platform_api, POK_AND_REVEAL_METADATA.to_owned()).unwrap();
            }

            #[test]
            fn yields_no_warnings() {
                assert_eq!(
                    TS.warnings_and_data_for_verifier.warnings,
                    vec![],
                    "left = TS.warnings_and_data_for_verifier.warnings"
                );
            }

            #[test]
            fn reveals_attributes_from_two_credentials() {
                assert_eq!(
                    TS.warnings_and_data_for_verifier
                        .result
                        .revealed_idxs_and_vals
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                    btreeset!(td::D_ISSUER_LABEL.to_owned(), td::S_ISSUER_LABEL.to_owned()),
                    "left = TS.warnings_and_data_for_verifier.result.revealed_idxs_and_vals.keys"
                );
            }

            #[test]
            fn reveals_correct_attributes_from_two_credentials() {
                assert_eq!(
                    TS.warnings_and_data_for_verifier
                        .result
                        .revealed_idxs_and_vals
                        .values()
                        .collect_concat::<BTreeSet<_>>(),
                    btreeset!(
                        (&td::D_META_IDX, &td::D_VALS[td::D_META_IDX as usize]),
                        (&td::S_META_IDX, &td::S_VALS[td::S_META_IDX as usize]),
                    ),
                    "left = TS.warnings_and_data_for_verifier.result.revealed_idxs_and_vals.values"
                )
            }
        }
    };
}

#[macro_export]
macro_rules! accum_spec {
    ($platform_api: expr) => {
        mod accum {
            use super::*;

            lazy_static! {
                static ref I_LBLS: Vec<tf::IssuerLabel> =
                    vec![td::D_ISSUER_LABEL.to_owned(), td::S_ISSUER_LABEL.to_owned()];
                static ref TS1: tf::TestState =
                    tf::start_test($platform_api, POK_AND_REVEAL_METADATA.to_owned()).unwrap();
            }

            #[test]
            fn creates_accumulators() {
                let accs = get_accums_for(&TS1, &I_LBLS);
                let acc_idxs = accs
                    .clone()
                    .into_iter()
                    .map(|x| x.into_keys().collect::<BTreeSet<_>>())
                    .collect::<BTreeSet<_>>();
                let asd = TS1.all_signer_data.values();
                // Check we have accumulators for the right set of indices for each schema
                assert_eq!(
                    acc_idxs,
                    asd.map(
                        |x| accumulator_indexes(&x.signer_public_data.signer_public_schema)
                            .into_iter()
                            .collect::<BTreeSet<_>>()
                    )
                    .collect::<BTreeSet<_>>(),
                    "acc_idxs != asd.map(|x| accumulator_indexes(x.signer_public_data.signer_public_schema))"
                );
                // There should not be any PublicAccumulatorUpdateInfo recorded yet
                assert_eq!(
                    accs.into_iter()
                        .map(|x| {
                            x.into_iter()
                                .map(|(k, (_, m))| (k, m.len()))
                                .collect::<BTreeMap<_, _>>()
                        })
                        .collect::<BTreeSet<_>>(),
                    btreeset!(
                        btreemap!(td::D_ACCUM_IDX => 0),
                        btreemap!(td::S_ACCUM_IDX => 0),
                    ),
                    "left = accs.map(|x| x.map(|(k, (_, m))| (k, m.len())))"
                );
            }

            lazy_static! {
                static ref TS2: tf::TestState =
                    tf::start_test($platform_api, [
                        POK_AND_REVEAL_METADATA.to_owned(),
                        ADD_TO_ACCUMS.to_owned()
                    ].concat()).unwrap();
            }

            #[test]
            fn adds_values_to_accumulators() {
                todo!()
            }

            #[test]
            fn add_witnesses_to_holder_state() {
                let sards = TS2.sigs_and_rel_data.get(&td::HOLDER_1.to_owned()).unwrap();
                println!("[debug] {:?}", sards.into_iter().map(|(k, x)| (k.clone(), &x.accum_wits)).collect::<BTreeMap<_, _>>());
                assert_eq!(
                    sards.into_iter().map(|(k, x)| (k.clone(), x.accum_wits.keys().cloned().collect::<BTreeSet<_>>())).collect::<BTreeMap<_, _>>(),
                    btreemap!(
                        td::D_ISSUER_LABEL.to_owned() => btreeset!(td::D_ACCUM_IDX.to_owned()),
                        td::S_ISSUER_LABEL.to_owned() => btreeset!(td::S_ACCUM_IDX.to_owned()),
                    ),
                    "left = sards.map(|(k, x)| (k, x.accum_wits.keys()))"
                )
            }

            lazy_static! {
                static ref PROOF_SUCCEEDS: Vec<tf::TestStep> = vec![
                    tf::TestStep::CreateAndVerifyProof("Holder1".to_owned(), tf::CreateVerifyExpectation::BothSucceedNoWarnings),
                ];
                static ref PROOF_FAILS: Vec<tf::TestStep> = vec![
                    tf::TestStep::CreateAndVerifyProof("Holder1".to_owned(), tf::CreateVerifyExpectation::CreateOrVerifyFails),
                ];
                static ref POK_AND_REVEAL_METADATA: Vec<tf::TestStep> = [
                    COMMON_SETUP.to_owned(),
                    PROOF_SUCCEEDS.to_owned(),
                ].concat();
                static ref ADD_TO_ACCUMS: Vec<tf::TestStep> = vec![
                    tf::TestStep::AccumulatorAddRemove(td::D_ISSUER_LABEL.to_owned(), td::D_ACCUM_IDX, hashmap!(td::HOLDER_1.to_owned() => td::D_VALS[td::D_ACCUM_IDX as usize].to_owned()), vec![]),
                    tf::TestStep::AccumulatorAddRemove(td::S_ISSUER_LABEL.to_owned(), td::S_ACCUM_IDX, hashmap!(td::HOLDER_1.to_owned() => td::S_VALS[td::S_ACCUM_IDX as usize].to_owned()), vec![]),
                ];
            }

            lazy_static! {
                static ref TS3: tf::TestState = tf::start_test(
                    $platform_api,
                    [
                        POK_AND_REVEAL_METADATA.to_owned(),
                        ADD_TO_ACCUMS.to_owned(),
                        IN_ACCUM_REQS.to_owned(),
                    ].concat()
                ).unwrap();
            }

            #[test]
            fn in_accum_created_for_holder_1_d_accum_idx() {
                validate_in_accum(
                    &td::HOLDER_1,
                    &td::D_ISSUER_LABEL,
                    td::D_ACCUM_IDX,
                    &TS3,
                )
            }

            #[test]
            fn in_accum_created_for_holder_1_s_accum_idx() {
                validate_in_accum(
                    &td::HOLDER_1,
                    &td::S_ISSUER_LABEL,
                    td::S_ACCUM_IDX,
                    &TS3,
                )
            }

            fn validate_in_accum(
                h_lbl: &tf::HolderLabel,
                i_lbl: &tf::IssuerLabel,
                a_idx: CredAttrIndex,
                ts: &tf::TestState,
            ) {
                let InAccum(in_accs) = &ts.preqs.get(h_lbl).unwrap().get(i_lbl).unwrap().in_accum;
                assert_eq!(in_accs.len(), 1, "left = in_accs.len()");
                let InAccumInfo {
                    index: i,
                    public_data_label: l0,
                    mem_prv_label: l1,
                    accumulator_seq_no: l2,
                    accumulator_label: sn,
                } = &in_accs[0];
                assert_eq!(*i, a_idx, "i != a_idx");
                assert!(ts.sparms.get(l0).is_some());
                assert!(ts.sparms.get(l1).is_some());
                assert!(ts.sparms.get(l2).is_some());
                assert!(ts.sparms.get(sn).is_some());
            }

            fn get_accums_for(
                ts: &tf::TestState,
                i_lbls: &[tf::IssuerLabel],
            ) -> Vec<tf::AccumsForSigner> {
                let asd = get_existing(&ts.all_signer_data, i_lbls);
                get_existing(
                    &ts.accums,
                    &asd.into_iter()
                        .map(|x| *x.signer_public_data)
                        .collect::<Vec<_>>(),
                )
            }

            fn get_existing<K: Eq + Hash, V: Clone>(m: &HashMap<K, V>, ks: &[K]) -> Vec<V> {
                ks.iter().map(|k| m[k].clone()).collect()
            }
        }
    };
}

#[macro_export]
macro_rules! initial_test_via_new_framework_spec {
    ($platform_api: expr, $lib_spec: expr) => {
        mod initial_test_framework_test {
            use super::*;

            #[test]
            fn rejects_duplicate_issuer_labels() {
                assert!(
                    tf::start_test($platform_api, vec![
                        CREATE_D_ISSUER.to_owned()
                    ])
                        .and_then(|mut ts| tf::extend_test($platform_api, vec![CREATE_D_ISSUER.to_owned()], &mut ts))
                        .is_err_containing("step_create_issuer; Duplicate issuer label; DMV"))}

            #[test]
            fn adds_issuers_signer_data() {
                let ts = tf::start_test($platform_api, vec![
                    CREATE_D_ISSUER.to_owned(),
                    CREATE_S_ISSUER.to_owned()
                ]).unwrap();
                assert_eq!(
                    ts.all_signer_data.into_keys().collect::<BTreeSet<_>>() ,
                    btreeset![ td::D_ISSUER_LABEL.to_owned(), td::S_ISSUER_LABEL.to_owned() ],
                    "left = ts.all_signer_data.keys"
                )
            }

            #[test]
            fn adds_issuers_public_data_to_sparms() {
                let mut ts = tf::start_test($platform_api, vec![CREATE_D_ISSUER.to_owned()]).unwrap();
                tf::extend_test($platform_api, vec![CREATE_S_ISSUER.to_owned()], &mut ts).unwrap();
                assert_eq!(
                    ts.sparms.into_keys().collect::<Vec<_>>().into_iter().collect::<BTreeSet<_>>() ,
                    btreeset![ td::D_ISSUER_LABEL.to_owned(), td::S_ISSUER_LABEL.to_owned() ],
                    "left = ts.sparms"
                );
            }

            #[test]
            fn adds_authority_public_data_to_sparms() {
                let ts = tf::start_test($platform_api, vec![CREATE_POLICE_AUTHORITY.to_owned()]).unwrap();
                assert_eq!(
                    ts.sparms.into_keys().collect::<Vec<_>>().into_iter().collect::<BTreeSet<_>>() ,
                    btreeset![ td::POLICE_AUTHORITY_LABEL.to_owned() ],
                    "left = ts.sparms"
                );
            }

            #[test]
            fn adds_decrypt_req() {
                let mut ts = tf::start_test($platform_api, vec![CREATE_POLICE_AUTHORITY.to_owned()]).unwrap();
                tf::extend_test($platform_api, vec![CREATE_D_ISSUER.to_owned(),sign_d_cred(td::HOLDER_1.to_owned())], &mut ts).unwrap();
                tf::extend_test($platform_api, vec![ENCRYPT_FOR_POLICE_AUTHORITY.to_owned(),], &mut ts).unwrap();
                tf::extend_test($platform_api, vec![DECRYPT_FOR_POLICE_AUTHORITY.to_owned(),], &mut ts).unwrap();
                let y = ts.decrypt_requests.get(&td::HOLDER_1.to_owned()).cloned().unwrap_or_default();
                let x = three_lvl_map_to_vec_of_tuples(&y);
                let x_len = x.len();
                match x[..] {
                    [(c_lbl, a_idx, a_lbl, api::DecryptRequest{..})] => {
                        assert_eq!(*c_lbl, td::D_ISSUER_LABEL.to_owned(), "credential labels match");
                        assert_eq!(*a_idx, td::D_SSN_IDX.to_owned(), "attribute indexes match");
                        assert_eq!(*a_lbl, td::POLICE_AUTHORITY_LABEL.to_owned());
                    },
                    _ => { panic!("unexpected result with {} entries", x_len) }
                }
            }

            #[test]
            fn signs_two_credentials() {
                let ts = tf::start_test($platform_api, vec![
                        CREATE_D_ISSUER.to_owned(),
                        CREATE_S_ISSUER.to_owned(),
                        sign_d_cred(td::HOLDER_1.to_owned()),
                        sign_s_cred(td::HOLDER_1.to_owned())
                ]).unwrap();
                assert_eq!(
                    ts.sigs_and_rel_data.into_values().map(|m| m.into_keys().collect::<Vec<_>>()).collect_concat::<BTreeSet<_>>(),
                    btreeset![ td::D_ISSUER_LABEL.to_owned(), td::S_ISSUER_LABEL.to_owned() ],
                    "left = ts.sigs_and_rel_data.values().map(|m| m.keys())"
                )
            }

            #[test]
            fn sets_up_proof_reqs_for_holder() {
                let ts = tf::start_test($platform_api, vec![
                    CREATE_D_ISSUER.to_owned(),
                    CREATE_S_ISSUER.to_owned(),
                    sign_d_cred(td::HOLDER_1.to_owned()),
                    sign_s_cred(td::HOLDER_1.to_owned())
                ]).unwrap();
                let keys = ts.preqs.into_keys().collect::<BTreeSet<tf::HolderLabel>>();
                assert_eq!(keys, btreeset![ td::HOLDER_1.to_owned() ], "left = keys");
            }

            #[test]
            fn sets_up_proof_reqs_for_signed_credentials() {
                let ts = tf::start_test($platform_api, vec![
                    CREATE_D_ISSUER.to_owned(),
                    CREATE_S_ISSUER.to_owned(),
                    sign_d_cred(td::HOLDER_1.to_owned()),
                    sign_s_cred(td::HOLDER_1.to_owned())
                ]).unwrap();
                assert_eq!(
                    ts.preqs.into_iter().map(|(k, v)| (k, v.into_iter().collect::<BTreeMap<_, _>>())).collect::<BTreeMap<_, BTreeMap<_, _>>>(),
                    btreemap![
                        td::HOLDER_1.to_owned() => btreemap!(
                            td::D_ISSUER_LABEL.to_owned() => tf::new_credential_reqs(td::D_ISSUER_LABEL.to_owned()),
                            td::S_ISSUER_LABEL.to_owned() => tf::new_credential_reqs(td::S_ISSUER_LABEL.to_owned()),
                        )
                    ],
                    "left = ts.preqs"
                )
            }

            #[test]
            fn finishes_the_test_sequence_successfully() {
                tf::run_test(
                    $platform_api,
                    vec![
                        CREATE_D_ISSUER.to_owned(),
                        CREATE_S_ISSUER.to_owned(),
                        sign_d_cred(td::HOLDER_1.to_owned()),
                        sign_s_cred(td::HOLDER_1.to_owned()),
                        tf::TestStep::Reveal(td::HOLDER_1.to_owned(), td::D_ISSUER_LABEL.to_owned(), vec![ td::D_META_IDX ]),
                        tf::TestStep::Reveal(td::HOLDER_1.to_owned(), td::S_ISSUER_LABEL.to_owned(), vec![ td::S_META_IDX ]),
                        tf::TestStep::CreateAndVerifyProof(td::HOLDER_1.to_owned(), tf::CreateVerifyExpectation::BothSucceedNoWarnings),
                    ],
                )
            }
        }
    };
}

// Utilities

mod tests {
    use crate::vcp::r#impl::general::testing_framework as tf;
    use credx::vcp::{
        api_utils::implement_platform_api_using, r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C,
    };
    use generate_tests_from_json::map_test_over_dir;
    use crate::vcp::r#impl::general::testing_framework::run_json_test_ac2c;

    generate_tests_from_json::map_test_over_dir! { run_json_test_ac2c,
                                                   "./tests/data/JSON/TestSequences/TestingFramework",
                                                   ""
    }
}
