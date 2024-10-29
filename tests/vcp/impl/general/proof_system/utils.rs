// -----------------------------------------------------------------------------
use credx::vcp::{Error, VCPResult};
use credx::vcp::api::PlatformApi;
use credx::vcp::r#impl::json::util::encode_to_text;
use credx::vcp::r#impl::util::{merge_maps, pp, three_lvl_map_to_vec_of_tuples};
use credx::vcp::types::*;
// -----------------------------------------------------------------------------
use crate::vcp::r#impl::general::proof_system::test_data as td;
use crate::vcp::r#impl::general::testing_framework::*;
use crate::vcp::r#impl::general::utility_functions::*;
// -----------------------------------------------------------------------------
use maplit::hashmap;
use std::collections::HashMap;
use std::hash::Hash;
// -----------------------------------------------------------------------------

// These are essentially the same as the definitions in generate-tests-from-json/src/lib.rs,
// but we cannot import them from there because of limitations of what proc_macro crates
// can currently export
pub type TestLabel = &'static str;
pub type LibrarySpecificTestHandlers = HashMap<TestLabel, TestHandler>;

#[derive(Clone)]
pub enum TestHandler {
    Skip(&'static str),
    Fail(&'static str),
    NotSoSlow,
}

// Use this to mark a test as slowslow, so it gets skipped if EITHER of the ignore_slow and
// ignore_slow_slow features is enabled
#[macro_export]
macro_rules! slow_slow_test {
    () => {
        #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"), ignore)]
    };
}

// Use this to mark a test as slow, so it gets skipped if ignore_slow feature is enabled,
// but will still be run if only the ignore_slow_slow feature is enabled
#[macro_export]
macro_rules! slow_test {
    () => {
        #[cfg_attr(feature = "ignore_slow", ignore)]
    };
}

pub fn it_with(lib_spec: &LibrarySpecificTestHandlers, label: TestLabel, k: impl Fn()) {
    match lib_spec.get(label) {
        None => k(),
        Some(TestHandler::NotSoSlow) => k(), // I can't quite directly translate the dynamic test label from Haskell
        Some(TestHandler::Skip(s)) => { println!("{:?} skipped because {:?}", label, s) },
        Some(TestHandler::Fail(s)) => panic!("not run because: {s}"),
    }
}

pub fn expect_flow_to_be_unsuccessful(
    platform_api: &PlatformApi,
    _lib_spec: &LibrarySpecificTestHandlers,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    d_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    s_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    decrypt_reqs: &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
) {
    let WarningsAndDataForVerifier { result: dfv, .. } =
        match do_create_proof(platform_api, proof_reqs, shared, d_sig_cd, s_sig_cd) {
            Err(_) => return,
            Ok(x) => x,
        };
    let x = match do_verify_proof(platform_api, proof_reqs, shared, dfv, decrypt_reqs) {
        Err(_) => return,
        Ok(x) => x,
    };
    panic!("expected failure; but succeeded with; {x:?}");
}

#[allow(clippy::too_many_arguments)]
pub fn expect_with_warnings(
    expect_warns_from_create_proof: impl Fn(&[Warning]),
    expect_warns_from_verify_proof: impl Fn(&[Warning]),
    platform_api: &PlatformApi,
    _lib_spec: &LibrarySpecificTestHandlers,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    d_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    s_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    decrypt_reqs: &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
) {
    // println!("EXPECT_WITH_WARNINGS");
    let WarningsAndDataForVerifier {
        warnings: warns_from_create_proof,
        result: dfv,
    }: WarningsAndDataForVerifier =
        do_create_proof(platform_api, proof_reqs, shared, d_sig_cd, s_sig_cd).unwrap();
    expect_warns_from_create_proof(&warns_from_create_proof);

    let discls = &dfv.revealed_idxs_and_vals;

    fn sort<T: Ord>(mut xs: Vec<T>) -> Vec<T> {
        xs.sort_unstable();
        xs
    }

    assert_eq!(
        sort(discls.clone().into_keys().collect::<Vec<_>>()),
        sort(vec![
            td::D_CRED_LABEL.to_string(),
            td::S_CRED_LABEL.to_string()
        ])
    );

    let validate_disclosures = |discls: &HashMap<CredentialLabel, HashMap<u64, DataValue>>,
                                c_lbl: &CredentialLabel,
                                vals: &[DataValue]|
     -> VCPResult<()> {
        let Disclosed(idxs) = &proof_reqs[c_lbl].disclosed;
        let idxs_and_vals = idxs
            .iter()
            .map(|idx| (*idx, vals[*idx as usize].clone()))
            .collect::<HashMap<_, _>>();
        let cred_discls = &discls[c_lbl];
        assert_eq!(&idxs_and_vals, cred_discls);
        Ok(())
    };

    vec![
        (td::D_CRED_LABEL.to_string(), td::D_VALS.to_vec()),
        (td::S_CRED_LABEL.to_string(), td::S_VALS.to_vec()),
    ]
    .into_iter()
    .for_each(|(cl, dvs)| validate_disclosures(discls, &cl, &dvs).unwrap());

    let WarningsAndDecryptResponses {
        statement_warnings: warns_from_verify_proof,
        decrypt_responses: decrypt_rsps,
    } = do_verify_proof(platform_api, proof_reqs, shared, dfv, decrypt_reqs).unwrap();
    expect_warns_from_verify_proof(&warns_from_verify_proof);

    // TODO: Generalise so it works for arbitrary number of requests
    match three_lvl_map_to_vec_of_tuples(&decrypt_rsps).as_slice() {
        [] => {
            assert_eq!(decrypt_rsps, hashmap! {});
        }
        [(cl, ai, a_lbl, DecryptResponse { .. })] => {
            let DataValue::DVText(t) = &td::D_VALS[**ai as usize] else {
                panic!("invalid DataValue in test_data::D_VALS")
            };
            let DecryptResponse { value: t_, .. } = &decrypt_rsps[*cl][*ai][*a_lbl];
            assert_eq!(t_, t); // THIS IS IT! <----------------
        }
        _ => panic!("invalid decrypt_rsps_vec"),
    }
}

pub fn expect(
    platform_api: &PlatformApi,
    lib_spec: &LibrarySpecificTestHandlers,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    d_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    s_sig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    decrypt_reqs: &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel,DecryptRequest>>>,
) {
    expect_with_warnings(
        |ws| {
            assert!(
                ws.is_empty(),
                "expected no warnings from `create_proof`, but got: {:?}",
                ws
            )
        },
        |ws| {
            assert!(
                ws.is_empty(),
                "expected no warnings from `verify_proof`, but got: {:?}",
                ws
            )
        },
        platform_api,
        lib_spec,
        proof_reqs,
        shared,
        d_sig_cd,
        s_sig_cd,
        decrypt_reqs,
    )
}

pub fn expect_create_proof_to_throw(
    platform_api: &PlatformApi,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    dsig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    ssig_cd: &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    fail_condition: impl Fn(Error) -> bool,
) {
    let err = do_create_proof(platform_api, proof_reqs, shared, dsig_cd, ssig_cd)
        .err()
        .unwrap();
    fail_condition(err);
}

// TODO: expect_verification_to_throw

#[allow(clippy::type_complexity)]
pub fn do_test_setup_with_additional_setup(
    update_sp: fn(
        HashMap<SharedParamKey, SharedParamValue>,
    ) -> VCPResult<HashMap<SharedParamKey, SharedParamValue>>,
    platform_api: &PlatformApi,
    signers: &HashMap<IssuerLabel, Vec<ClaimType>>,
    creds: &HashMap<CredentialLabel, (IssuerLabel, Vec<DataValue>)>,
) -> (
    HashMap<IssuerLabel, SignerData>,
    HashMap<CredentialLabel, (Signature, HashMap<CredAttrIndex, AccumulatorWitnesses>)>,
    HashMap<SharedParamKey, SharedParamValue>,
) {
    let signer_data: HashMap<IssuerLabel, SignerData> = signers
        .iter()
        .enumerate()
        .map(|(i, (s_lbl, schema))| {
            (
                s_lbl.clone(),
                (platform_api.create_signer_data)(i as u64, schema).unwrap(),
            )
        })
        .collect();

    let go = |signer_data: &HashMap<IssuerLabel, SignerData>,
              (i_lbl, vals): &(IssuerLabel, Vec<DataValue>)|
     -> Signature { (platform_api.sign)(0, vals, &signer_data[i_lbl]).unwrap() };

    let sigs: HashMap<IssuerLabel, Signature> = creds
        .iter()
        .map(|(k, v)| (k.clone(), go(&signer_data, v)))
        .collect();

    let create_wits_for = |(i_lbl, _)| -> HashMap<CredAttrIndex, HashMap<_, _>> {
        create_for_accumulator_fields(&signers[i_lbl], |_| Ok(hashmap!())).unwrap()
    };

    let wits: HashMap<
        CredentialLabel,
        HashMap<CredAttrIndex, HashMap<CredAttrIndex, AccumulatorMembershipWitness>>,
    > = creds
        .iter()
        .map(|(k, (i_lbl, dvs))| (k.clone(), create_wits_for((i_lbl, dvs))))
        .collect();

    let sigs_and_wits: HashMap<
        CredentialLabel,
        (
            Signature,
            HashMap<CredAttrIndex, HashMap<CredAttrIndex, AccumulatorMembershipWitness>>,
        ),
    > = merge_maps(sigs, wits).unwrap();

    let shared_params: HashMap<IssuerLabel, SharedParamValue> = signer_data
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                SharedParamValue::SPVOne(DataValue::DVText(
                    encode_to_text(&v.signer_public_data).unwrap(),
                )),
            )
        })
        .collect();

    let shared_params_ = update_sp(shared_params).unwrap();

    (signer_data, sigs_and_wits, shared_params_)
}

#[allow(clippy::type_complexity, unused)]
pub fn do_test_setup(
    platform_api: &PlatformApi,
    signers: &HashMap<IssuerLabel, Vec<ClaimType>>,
    creds: &HashMap<CredentialLabel, (IssuerLabel, Vec<DataValue>)>,
) -> (
    HashMap<CredentialLabel, SignerData>,
    HashMap<CredentialLabel, (Signature, HashMap<u64, AccumulatorWitnesses>)>,
    HashMap<SharedParamKey, SharedParamValue>,
) {
    do_test_setup_with_additional_setup(Ok, platform_api, signers, creds)
}

pub type SignersAndSigs = (
    SignerData,
    SignerData,
    (Signature, Vec<DataValue>, AccumulatorWitnesses),
    (Signature, Vec<DataValue>, AccumulatorWitnesses),
    HashMap<SharedParamKey, SharedParamValue>,
);

pub fn do_create_signers_shared_and_sigs(platform_api: &PlatformApi) -> SignersAndSigs {
    do_create_signers_shared_and_sigs_with_additional_setup(Ok, platform_api)
}

#[allow(clippy::type_complexity)]
pub fn do_create_signers_shared_and_sigs_with_additional_setup(
    update_sp: fn(
        HashMap<SharedParamKey, SharedParamValue>,
    ) -> VCPResult<HashMap<SharedParamKey, SharedParamValue>>,
    platform_api: &PlatformApi,
) -> SignersAndSigs {
    let (signer_data, sigs_and_aux, shared) = do_test_setup_with_additional_setup(
        update_sp,
        platform_api,
        &td::DEFAULT_ISSUERS,
        &td::DEFAULT_CREDS,
    );

    // Map k a -> Map k1 (a1, Map k2 c) -> k -> k1 -> k2 -> (a, a1, c)
    fn get_tuple<'a, 'b, K: Eq + Hash, A, K1: Eq + Hash, A1, K2: Eq + Hash, C>(
        sd: &'a HashMap<K, A>,
        saa: &'b HashMap<K1, (A1, HashMap<K2, C>)>,
        i_lbl: &K,
        c_lbl: &K1,
        acc_idx: &K2,
    ) -> (&'a A, &'b A1, &'b C) {
        (&sd[i_lbl], &saa[c_lbl].0, &saa[c_lbl].1[acc_idx])
    }

    let (dsd, d, d_aux) = get_tuple(
        &signer_data,
        &sigs_and_aux,
        &td::D_SPD_KEY,
        &td::D_CRED_LABEL,
        &td::D_ACCUM_IDX,
    );
    let (ssd, s, s_aux) = get_tuple(
        &signer_data,
        &sigs_and_aux,
        &td::S_SPD_KEY,
        &td::S_CRED_LABEL,
        &td::S_ACCUM_IDX,
    );

    // BONUS: rather than cloning everything, I could thoughtfully propogate
    // lifetimes in SignersAndSigs
    (
        dsd.clone(),
        ssd.clone(),
        (d.clone(), td::D_VALS.clone(), d_aux.clone()),
        (s.clone(), td::S_VALS.clone(), s_aux.clone()),
        shared,
    )
}

pub fn do_create_proof(
    platform_api: &PlatformApi,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    (d_sig, d_vals, d_wits): &(Signature, Vec<DataValue>, AccumulatorWitnesses),
    (s_sig, s_vals, s_wits): &(Signature, Vec<DataValue>, AccumulatorWitnesses),
) -> VCPResult<WarningsAndDataForVerifier> {
    let wr = (*platform_api.create_proof)(
        proof_reqs,
        shared,
        &hashmap! {
            td::D_CRED_LABEL.to_string() => SignatureAndRelatedData{ signature: d_sig.clone(), values: d_vals.clone(), accum_wits: d_wits.clone() },
            td::S_CRED_LABEL.to_string() => SignatureAndRelatedData{ signature: s_sig.clone(), values: s_vals.clone(), accum_wits: s_wits.clone()},
        },
        None,
    )?;
    pp("w", &wr.warnings);
    pp("proof", &wr.result);
    Ok(wr)
}

fn do_verify_proof(
    platform_api: &PlatformApi,
    proof_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared: &HashMap<SharedParamKey, SharedParamValue>,
    dfv: DataForVerifier,
    decrypt_reqs: &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
) -> VCPResult<WarningsAndDecryptResponses> {
    let v = (*platform_api.verify_proof)(proof_reqs, shared, &dfv, decrypt_reqs, None)?;
    pp("verify", &v);
    Ok(v)
}
