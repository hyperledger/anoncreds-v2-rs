// ----------------------------------------------------------------------------
use credx::vcp::r#impl::general::presentation_request_setup::{get_proof_instructions, is_cred_resolved};
use credx::vcp::r#impl::json::util::encode_to_text;
use credx::vcp::primitives::types::*;
// ----------------------------------------------------------------------------
use crate::vcp::data_for_tests as td;
// ----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
use std::collections::HashMap;
// ----------------------------------------------------------------------------

mod spec {
    use super::*;
    mod get_proof_instructions {
        use super::*;

        lazy_static! {
            static ref INT_KEY: String = "intKey".to_string();
            static ref INT_VAL: SharedParamValue = SharedParamValue::SPVOne(DataValue::DVInt(42));
            static ref RPK_KEY: String = "rangeProvingKey".to_string();
            static ref RPK: SharedParamValue = SharedParamValue::SPVOne(DataValue::DVText(
                encode_to_text(&RangeProofProvingKey("bogus".to_string())).unwrap()
            ));
            static ref APD_KEY: String = "authorityPublicDataKey".to_string();
            static ref APD_VAL: SharedParamValue = SharedParamValue::SPVOne(DataValue::DVText(
                encode_to_text(&AuthorityPublicData("bogus".to_string())).unwrap()));
            static ref SPD_VAL: SharedParamValue = SharedParamValue::SPVOne(DataValue::DVText(
                encode_to_text(&SignerPublicData {
                    signer_public_setup_data: SignerPublicSetupData("bogus".to_string()),
                    signer_public_schema: td::D_CTS.to_owned()
                })
                .unwrap()
            ));
            static ref SHARED: HashMap<String, SharedParamValue> = hashmap!(
                td::D_SPD_KEY.to_owned() => SPD_VAL.to_owned(),
                td::S_SPD_KEY.to_owned() => SPD_VAL.to_owned(),
                RPK_KEY.to_owned() => RPK.to_owned(),
                INT_KEY.to_owned() => INT_VAL.to_owned(),
            );
            static ref PROOF_REQS: HashMap<CredentialLabel, CredentialReqs> = td::proof_reqs_with(
                (vec![], vec![]),
                (vec![], vec![]),
                (
                    vec![InRangeInfo {
                        index: 1,
                        min_label: INT_KEY.to_owned(),
                        max_label: INT_KEY.to_owned(),
                        range_proving_key_label: RPK_KEY.to_owned()
                    }],
                    vec![InRangeInfo {
                        index: 2,
                        min_label: INT_KEY.to_owned(),
                        max_label: INT_KEY.to_owned(),
                        range_proving_key_label: RPK_KEY.to_owned()
                    }]
                ),
                (vec![], vec![]),
                // TODO-VERIFIABLE-ENCRYPTION: APD
                // (
                //     vec![IndexAndLabel {
                //         index: td::D_SSN_IDX,
                //         label: APD_KEY.to_owned(),
                //     }],
                //     vec![IndexAndLabel {
                //         index: td::S_SSN_IDX,
                //         label: APD_KEY.to_owned(),
                //     }]
                // ),
                (vec![], vec![]),
            );
        }

        #[test]
        fn get_proof_instructions_for_range_proof() {
            // get_proof_instructions_for_range_proof_impl(&SHARED, &PROOF_REQS);
            let p_instrs = get_proof_instructions(
                &SHARED,
                &PROOF_REQS,
                // empty HashMap because we don't request revealing any attributes
                &hashmap!(
                    td::D_CRED_LABEL.to_owned() => hashmap!(),
                    td::S_CRED_LABEL.to_owned() => hashmap!(),
                ),
            )
            .unwrap();

            // TODO-VERIFIABLE-ENCRYPTION: APD
            // One PoKofSignature, one RangeProof, and one EncryptedFor for each credential
            // assert_eq!(p_instrs.len(), 6);
            assert_eq!(p_instrs.len(), 4);

            let idxs_and_prf_instrs: Vec<(usize, &ProofInstructionGeneral<ResolvedDisclosure>)> =
                p_instrs.iter().enumerate().collect();

            idxs_and_prf_instrs
                .iter()
                .filter(|(_, instr)| is_cred_resolved(instr))
                .for_each(|(i, instr)| check_cred_resolved_prf_instr(*i, instr));

            idxs_and_prf_instrs
                .iter()
                .filter(|(_, instr)| !is_cred_resolved(instr))
                .for_each(|(i, instr)| check_non_cred_resolved_prf_instr(&p_instrs, *i, instr));
        }

        /// Check that the supposedly CredentialResolved ProofInstruction really is one,
        /// and that its "related index" is its own index.
        fn check_cred_resolved_prf_instr(
            i: usize,
            instr: &ProofInstructionGeneral<ResolvedDisclosure>,
        ) {
            // println!("check_cred_resolved_prf_instr {:?}", instr);
            match &instr.discl_general {
                ResolvedDisclosure::CredentialResolvedWrapper(_) => {
                    assert_eq!(i, instr.related_pi_idx.0 as usize)
                }
                x => panic!("check_cred_resolved_prf_instr {x:?}"),
            }
        }

        /// Check that, if we look up the element of the list of ProofInstructions at
        /// index rIdx, we get a CredentialResolvedWrapper for the same credential
        /// label, i.e., that it is the proof instruction that will generate the
        /// PoKofSignature statement (true for both AC2C and DNC but most relevant to
        /// DNC as it refers to statements by index, not label)
        fn check_non_cred_resolved_prf_instr(
            all_pis: &[ProofInstructionGeneral<ResolvedDisclosure>],
            i: usize,
            // instr: &ProofInstructionGeneral<ResolvedDisclosure>,
            ProofInstructionGeneral {
                cred_label: c_lbl,
                related_pi_idx: RelatedIndex(r_idx),
                ..
            }: &ProofInstructionGeneral<ResolvedDisclosure>,
        ) {
            // println!("check_non_cred_resolved_prf_instr {:?} of {:?}", i, all_pis);
            assert!(is_cred_resolved_for(c_lbl, i, all_pis.get(*r_idx as usize)))
        }

        fn is_cred_resolved_for(
            c_lbl: &CredentialLabel,
            i: usize,
            opt_instr: Option<&ProofInstructionGeneral<ResolvedDisclosure>>,
        ) -> bool {
            match opt_instr {
                Some(ProofInstructionGeneral {
                    cred_label: c_lbl_,
                    related_pi_idx: RelatedIndex(r_idx),
                    discl_general: ResolvedDisclosure::CredentialResolvedWrapper(_),
                    ..
                }) => *r_idx as usize != i && c_lbl_ == c_lbl,
                _ => false,
            }
        }
    }

    // TODO: we need tests for equality_reqs_from_pres_reqs_general,
    // particularly to ensure that it keeps unrelated equivalence classes
    // separate
}
