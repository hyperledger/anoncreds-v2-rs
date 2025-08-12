// ------------------------------------------------------------------------------
use credx::vcp;
use credx::vcp::VCPResult;
use credx::vcp::Error;
use credx::vcp::api::PlatformApi;
use credx::vcp::r#impl::json::util::encode_to_text;
use credx::vcp::interfaces::types::*;
use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS;
use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS;
use credx::vcp::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;
// ------------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
use std::collections::HashMap;
// ------------------------------------------------------------------------------

lazy_static! {
    static ref AC2C_BBS_API : PlatformApi =
        credx::vcp::api_utils::implement_platform_api_using(&CRYPTO_INTERFACE_AC2C_BBS);
    static ref AC2C_PS_API  : PlatformApi =
        credx::vcp::api_utils::implement_platform_api_using(&CRYPTO_INTERFACE_AC2C_PS);
    static ref DNC_API      : PlatformApi =
        credx::vcp::api_utils::implement_platform_api_using(&CRYPTO_INTERFACE_DNC);
}

// ------------------------------------------------------------------------------
// This test shows how to
// - create and update accumulators and witnesses, and
// - create and verify proofs containing them.

fn setup() {
    let _ = env_logger::builder().is_test(true).try_init();
}

macro_rules! run_vcp_membership_test_with {
    ($what:ident, $api:expr, $test_get_witness:expr) => {
        paste::item! {
            #[test]
            #[allow(non_snake_case)]
            fn [< vcp_membership_test_ $what _ $test_get_witness>]() {
                test_vcp_membership($api.clone(), $test_get_witness)
            }
        }
    }
}

#[derive(Eq, PartialEq)]
enum GetOrUpdateWitness { Get, Update }
use GetOrUpdateWitness::{ Get, Update };

run_vcp_membership_test_with!(ac2c_bbs_api, AC2C_BBS_API, Update);
run_vcp_membership_test_with!(ac2c_bbs_api, AC2C_BBS_API, Get);
run_vcp_membership_test_with!(ac2c_ps_api , AC2C_PS_API , Update);
run_vcp_membership_test_with!(ac2c_ps_api , AC2C_PS_API , Get);
run_vcp_membership_test_with!(dnc_api     , DNC_API     , Update);
run_vcp_membership_test_with!(dnc_api     , DNC_API     , Get);

fn test_vcp_membership(api: PlatformApi, test_get_witness: GetOrUpdateWitness) {
    setup();
    let nonce = "asd1234098(*#$#$(*U".into();
    let res   = vcp_membership(api, Some(nonce), test_get_witness);
    assert!(res.is_ok(), "{:?}", res);
}

// NOTE: variables are numbered according to "version" of the accumulator number they are using.
fn vcp_membership(
    api              : PlatformApi,
    nonce            : Option<String>,
    test_get_witness : GetOrUpdateWitness
) -> VCPResult<()> {

    // ------------------------------------------------------------------------------

    let create_signer_data                       = api.create_signer_data.clone();
    let sign                                     = api.sign.clone();
    let create_accumulator_data                  = api.create_accumulator_data.clone();
    let create_membership_proving_key            = api.create_membership_proving_key.clone();
    let create_accumulator_element               = api.create_accumulator_element.clone();
    let accumulator_add_remove                   = api.accumulator_add_remove.clone();
    let get_accumulator_witness                  = api.get_accumulator_witness.clone();
    let update_accumulator_witness               = api.update_accumulator_witness.clone();
    let create_proof                             = api.create_proof.clone();
    let verify_proof                             = api.verify_proof.clone();

    const CRED_LABEL                    : &str   = "CRED_LABEL";
    const SIGNER_LABEL                  : &str   = "SIGNER_SPD_LABEL";
    const ACCUMULATOR_PUBLIC_DATA_LABEL : &str   = "ACC_PD_LABEL";
    const MEMBERSHIP_PROVING_KEY_LABEL  : &str   = "MPK_LABEL";
    const ACCUMULATOR_LABEL             : &str   = "ACC_LABEL";
    const ACCUMULATOR_SEQ_NUM_LABEL     : &str   = "ACC_SEQ_LABEL";


    // ------------------------------------------------------------------------------
    // holder or issuer

    let accumulator_member : String              = "the membership element for test".into();
    let accum_element                            = create_accumulator_element(accumulator_member.clone())?;
    let values                                   = [DataValue::DVText(accumulator_member.clone())];
    const ACC_INDEX : CredAttrIndex              = 0;

    // ------------------------------------------------------------------------------
    // issuer

    let sd                                       = create_signer_data(
        0, &[ClaimType::CTAccumulatorMember], &[], ProofMode::Strict)?;

    let signature                                = sign(0, &values, &sd, ProofMode::Strict)?;

    // ------------------------------------------------------------------------------
    // accumulator manager

    let CreateAccumulatorResponse {
        accumulator_data : acc_data,
        accumulator      : acc_val_1
    }                                            = create_accumulator_data(0)?;
    let membership_proving_key                   = create_membership_proving_key(0)?;

    let hid                                      = HolderID(String::from("HID"));
    let add                                      = HashMap::from([(hid.clone(), accum_element.clone())]);
    let AccumulatorAddRemoveResponse {
        witness_update_info : _,
        witnesses_for_new   : wits_for_new_2,
        accumulator         : acc_val_2
    }                                            = accumulator_add_remove(
        &acc_data, &acc_val_1, &add, &[])?;

    let mem_witness_2a                           = wits_for_new_2.get(&hid).unwrap();
    let mem_witness_2b                           = get_accumulator_witness(&acc_data, &acc_val_2, &accum_element)?;
    assert_eq!(*mem_witness_2a, mem_witness_2b);
    let mem_witness_2 = if test_get_witness == Get { &mem_witness_2b } else { mem_witness_2a };
    println!("mem_witness_2a : {mem_witness_2a:?}");
    println!("mem_witness_2b : {mem_witness_2b:?}");

    // ------------------------------------------------------------------------------
    // verifier : create proof requirements

    let proof_reqs : HashMap<CredentialLabel, CredentialReqs> = hashmap!(
        CRED_LABEL.into() => CredentialReqs {
            signer_label  : SIGNER_LABEL.into(),
            disclosed     : Disclosed(vec![]),
            in_accum: InAccum(vec![InAccumInfo {
                index                         : 0,
                accumulator_public_data_label : ACCUMULATOR_PUBLIC_DATA_LABEL.into(),
                membership_proving_key_label  : MEMBERSHIP_PROVING_KEY_LABEL.into(),
                accumulator_label             : ACCUMULATOR_LABEL.into(),
                accumulator_seq_num_label     : ACCUMULATOR_SEQ_NUM_LABEL.into(),
            }]),
            not_in_accum  : NotInAccum(vec![]),
            in_range      : InRange(vec![]),
            encrypted_for : EncryptedFor(vec![]),
            equal_to      : EqualTo(vec![])
        }
    );

    let mut shared : HashMap<SharedParamKey, SharedParamValue> = hashmap!(
        SIGNER_LABEL.into() =>
            SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&sd.signer_public_data)?)),
        ACCUMULATOR_PUBLIC_DATA_LABEL.into() =>
            SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&acc_data.accumulator_public_data)?)),
        MEMBERSHIP_PROVING_KEY_LABEL.into() =>
            SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&membership_proving_key)?)),
        ACCUMULATOR_LABEL.into() =>
            SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&acc_val_2)?)),
        ACCUMULATOR_SEQ_NUM_LABEL.into() =>
            SharedParamValue::SPVOne(DataValue::DVInt(0)),
    );

    // ------------------------------------------------------------------------------
    // holder : create proof

    fn mk_sard(
        l: CredentialLabel,
        s: Signature,
        v: &[DataValue],
        w: AccumulatorMembershipWitness
    ) -> HashMap<CredentialLabel, SignatureAndRelatedData> {
        hashmap! {
            l.clone() =>
                SignatureAndRelatedData {
                    signature             : s,
                    values                : v.to_vec(),
                    accumulator_witnesses : hashmap! { ACC_INDEX => w }
                }
        }
    }

    let sard                                     = mk_sard(
        CRED_LABEL.into(), signature.clone(), &values, mem_witness_2.clone());
    let wadfv_2                                  = create_proof(
        &proof_reqs, &shared, &sard, ProofMode::Strict, nonce.clone())?;

    // ------------------------------------------------------------------------------
    // verifier : proof verification

    let v_2                                      = verify_proof(
        &proof_reqs, &shared, &wadfv_2.data_for_verifier, &hashmap! {}, ProofMode::Strict, nonce.clone())?;
    println!("v_2 verify succeeds : {v_2:?}");

    // ------------------------------------------------------------------------------
    // accumulator manager adds something to the accumulator

    let new_accum_elem  : AccumulatorElement     = create_accumulator_element("new_accum_member".into())?;
    let new_hid                                  = HolderID(String::from("NEW_HID"));
    let added                                    = HashMap::from([(new_hid, new_accum_elem)]);
    let AccumulatorAddRemoveResponse {
        witness_update_info : wit_update_info_3,
        witnesses_for_new   : _,
        accumulator         : acc_val_3
    }                                            = accumulator_add_remove(
        &acc_data, &acc_val_2, &added, &[])?;

    // ------------------------------------------------------------------------------
    // verifier : update to latest accumulator

    shared.insert(ACCUMULATOR_LABEL.into(),
                  SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&acc_val_3)?)));

    // ------------------------------------------------------------------------------
    // holder :
    // the accumulator change above causes mem_witness_2 to be out-of-date
    // so when holder creates another proof without updating its witness ...

    let wadfv_3                                  = create_proof(
        &proof_reqs, &shared, &sard, ProofMode::Strict, nonce.clone())?;

    // ------------------------------------------------------------------------------
    // verifier : ... the old witness will fail verification

    let v_3                                      = verify_proof(
        &proof_reqs, &shared, &wadfv_3.data_for_verifier, &hashmap! {}, ProofMode::Strict, nonce.clone());
    println!("v_3 verify should fail: {v_3:?}");

    match v_3  {
        Ok(_) => {
            return Err(vcp::Error::General("v_3 verify should have failed".into()))
        },
        Err(Error::General(e))
            // DNC
            if e.contains(&"DNC prf.verify VBAccumProofContributionFailed(1, PairingResponseInvalid)".to_string()) => {
                Ok(())
            },
        Err(Error::CryptoLibraryError(e))
            // AC2C
            if e.contains(&"the presentation proof failed, the expected challenge".to_string()) => {
                Ok(())
            },
        Err(_e) => {
            return Err(vcp::Error::General("v_3 verify returned unexpected error".into()))
        }
    }?;

    // ------------------------------------------------------------------------------
    // holder : update or get, depending on test_get_witness

    let mem_witness_3 =
        if test_get_witness == Get {
            get_accumulator_witness(&acc_data, &acc_val_3, &accum_element)?
        } else {
            update_accumulator_witness(mem_witness_2, &accum_element, &wit_update_info_3)?
        };

    // holder does a new proof with the updated witness
    let sard = mk_sard(CRED_LABEL.into(), signature.clone(), &values, mem_witness_3.clone());
    let wadfv_3a                                 = create_proof(
        &proof_reqs, &shared, &sard, ProofMode::Strict, nonce.clone())?;

    // ------------------------------------------------------------------------------
    // verifier : verification now succeeds

    let v_3a                                     = verify_proof(
        &proof_reqs, &shared, &wadfv_3a.data_for_verifier, &hashmap! {}, ProofMode::Strict, nonce.clone())?;
    println!("v_3a verify now succeeds: {v_3a:?}");

    // ------------------------------------------------------------------------------
    // accumulator manager : remove the holder's accumulator member (i.e., revocation)

    let empty_added : HashMap<HolderID, AccumulatorElement> = HashMap::new();
    let removed                                  = [accum_element.clone()];
    let AccumulatorAddRemoveResponse {
        witness_update_info : wit_update_info_4,
        witnesses_for_new   : _,
        accumulator         : acc_val_4
    }                                            = accumulator_add_remove(
        &acc_data, &acc_val_3, &empty_added, &removed)?;

    // ------------------------------------------------------------------------------
    // verifier : update to latest accumulator

    shared.insert(ACCUMULATOR_LABEL.into(),
                  SharedParamValue::SPVOne(DataValue::DVText(encode_to_text(&acc_val_4)?)));

    // ------------------------------------------------------------------------------
    // holder : attempts to update its witness
    // Since the element has been removed, this should fail somewhere in the process
    // (i.e., update or get, create proof, verify proof)
    // depending on which ZKP backend is in use.

    // NOTE: get_accumulator_witness should not be used after the element has been removed.
    // - AC2C, both UPDATE and GET return a value
    //   - the value returned by UPDATE fails later verification
    //   - the value returned by GET    passes later verification : SO IT SHOULD NOT BE USED.
    // - DNC
    //   - GET, when using InMemoryState, throws "get_accumulator_witness ElementAbsent".
    //   - GET, without    Inmemorystate, returns a value that passes later verification : SO IT SHOULD NOT BE USED.
    // NOTE:
    // - We could feature gate the test on "in_memory_state" and use GET for DNC, but
    //   the test would still fail for AC2C (unless we added InMemoryState to AC2C).
    // - Plus, we would need to extend the test to know which backend it is using
    //   so it would not use GET for AC2C (unless backed by InMemoryState).
    // - Bottom line: seems the test should just avoid using GET when
    //   the test knows GET should not be used.
    let mem_witness_4_option  = update_accumulator_witness(&mem_witness_3, &accum_element, &wit_update_info_4);

    // comment out the line above and uncomment this if to see what the NOTEs above are talking about.
    // let mem_witness_4_option  =
    //     if test_get_witness == Get {
    //         get_accumulator_witness(&acc_data, &acc_val_4, &accum_element)
    //     } else {
    //         update_accumulator_witness(&mem_witness_3, &accum_element, &wit_update_info_4)
    //     };

    println!("mem_witness_4_option: {mem_witness_4_option:?}");
    let mem_witness_4 : AccumulatorMembershipWitness = match mem_witness_4_option {
        Err(Error::General(e))
            // DNC get_accumulator_witness
            if e.contains(&"DNC get_accumulator_witness ElementAbsent".to_string()) => {
                println!("mem_witness_4 get fails DNC as expected"); // only thrown if using InMemoryState
                return Ok(())
            },
        Err(Error::General(e))
            // DNC update_accumulator_witness
            if e.contains(&"DNC update_accumulator_witness CannotBeZero".to_string()) => {
                println!("mem_witness_4 update fails DNC as expected");
                return Ok(())
            },
        Err(_) => return Err(vcp::Error::General("mem_witness_4 update returned unexpected error".into())),
        // AC2C does not fail when attempting to update a witness whose element has been removed.
        Ok(o)  => o
    };

    // NOTE: only AC2C gets here.

    let sard                                     = mk_sard(
        CRED_LABEL.into(), signature, &values, mem_witness_4.clone());

    // At this point, since the witness is not valid, either `create_proof` or `verify_proof` should fail.
    // With the current backends
    // - DNC correctly throws exceptions when trying to GET or UPDATE an invalid witness above
    // - AC2C does not fail at GET or UPDATE above
    //   - nor does it fail at `create_proof`
    //   - it does correctly throw an exception at `verify_proof`
    let wadfv_4                                  = create_proof(
        &proof_reqs, &shared, &sard, ProofMode::Strict, nonce.clone())?;
    println!("wadfv_4 after removing element {wadfv_4:?}");

    // ------------------------------------------------------------------------------
    // verifier : verification fails

    let v_4                                      = verify_proof(
        &proof_reqs, &shared, &wadfv_4.data_for_verifier, &hashmap! {}, ProofMode::Strict, nonce.clone());
    println!("v_4 verify should fail : {v_4:?}");
    match v_4  {
        Ok(_) => {
            println!("OK");
            return Err(vcp::Error::General("v_4 verify should have failed".into()))
        },
        Err(Error::CryptoLibraryError(e))
            if e.contains(&"the presentation proof failed, the expected challenge".to_string()) => {
                println!("AC2C");
                Ok(())
            },
        Err(Error::General(e))
            if e.contains(&"DNC update_accumulator_witness CannotBeZero".to_string()) => {
                println!("DNC");
                Ok(())
            },
        Err(_e) => {
            println!("UNEXPECTED");
            return Err(vcp::Error::General("v_4 verify returned unexpected error".into()))
        }
    }?;

    // // ------------------------------------------------------------------------------

    Ok(())
}

