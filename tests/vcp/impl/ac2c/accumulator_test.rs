// ------------------------------------------------------------------------------
use credx::vcp;
use credx::vcp::VCPResult;
use credx::vcp::r#impl::to_from::*;
use credx::vcp::r#impl::ac2c::accumulator::*;
use credx::vcp::interfaces::types::*;
// ------------------------------------------------------------------------------
use credx::claim::{HashedClaim, RevocationClaim};
use credx::knox::short_group_sig_core::{ProofMessage,HiddenMessage};
use credx::prelude::{
    vb20, ClaimSchema, ClaimType, CredentialBundle, CredentialSchema,
    Issuer, IssuerPublic, MembershipStatement,
};
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{RevocationStatement, SignatureStatement};
use credx::{error, random_string};
// ------------------------------------------------------------------------------
extern crate alloc;
use indexmap::indexmap;
use maplit::btreeset;
use rand::thread_rng;
use rand_core::RngCore;
use std::collections::HashMap;
use std::vec::Vec;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------
// This is the main "test" that shows how to create and update accumulators and witnesses
// and to create and verify proofs containing them.
//
// test_vcp_membership : the membership routines are all done from a VCP point-of-view.

fn setup() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_vcp_membership() {
    setup();
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    let res = vcp_membership(&nonce);
    assert!(res.is_ok(), "{:?}", res);
}

fn vcp_membership(nonce : &[u8],) -> VCPResult<()> {

    // -------------------------
    // accumulator manager

    let create_accumulator_data_ac2c             = create_accumulator_data();
    let create_accumulator_element_ac2c          = create_accumulator_element();
    let accumulator_add_remove_ac2c              = accumulator_add_remove();
    let update_accumulator_witness_ac2c          = update_accumulator_witness();
    let car                                      = create_accumulator_data_ac2c(0)?;

    // -------------------------
    // issuer

    let (issuer_public, mut issuer)              = create_issuer()?;

    // sign

    let membership_element                       = "the membership element for test".to_string();
    let credential_1                             = sign_credential(&mut issuer, &membership_element)?;

    // -------------------------
    // holder presentation/proof creation

    const MEMBERSHIP_ELEMENT_INDEX : usize       = 1;
    let accum_element                            = create_accumulator_element_ac2c(membership_element)?;
    let hid                                      = HolderID(String::from("HID"));
    let add                                      = HashMap::from([(hid.clone(),
                                                                   accum_element.clone())]);
    let AccumulatorAddRemoveResponse {
        witness_update_info : _,
        wits_for_new,
        updated_accum_data : accumulator_data_2,
        updated_accum_value: acc_value_1
    }                                            = accumulator_add_remove_ac2c(
        &car.new_accum_data, &car.new_accum_value, &add, &[])?;

    let mem_witness_1                            = wits_for_new.get(&hid).unwrap();

    let (sig_st_1, rvk_st_1)                     = create_sig_and_revoke_stmts(&issuer_public);
    let mem_st_1                                 = create_mem_stmt(
        &sig_st_1, &car.new_accum_data.public_data, &acc_value_1, MEMBERSHIP_ELEMENT_INDEX)?;

    let (presentation_schema_1, presentation_1)  = presentation_create(
        &credential_1, &sig_st_1, &rvk_st_1, &mem_st_1, mem_witness_1, nonce)?;

    // -------------------------
    // verifier presentation/proof verification

    presentation_verify(&presentation_schema_1, &presentation_1, nonce)?;

    // -------------------------
    // accumulator manager adds something to the accumulator

    let new_accum_elem  : AccumulatorElement     = to_api(vb20::Element::hash(b"5"))?;
    let new_hid                                  = HolderID(String::from("NEW_HID"));
    let added                                    = HashMap::from([(new_hid, new_accum_elem)]);
    let AccumulatorAddRemoveResponse {
        witness_update_info,
        wits_for_new : _,
        updated_accum_data : accumulator_data_3,
        updated_accum_value: acc_value_2
    }                                            = accumulator_add_remove_ac2c(
        &accumulator_data_2, &acc_value_1, &added, &[])?;

    // -------------------------
    // causes witness to be out-of-date
    // so when holder creates and presentation ...

    let mem_st_2                                 = create_mem_stmt(
        &sig_st_1, &accumulator_data_3.public_data, &acc_value_2, MEMBERSHIP_ELEMENT_INDEX)?;
    let (presentation_schema_2, presentation_2)  = presentation_create(
        &credential_1, &sig_st_1, &rvk_st_1, &mem_st_2, mem_witness_1, nonce)?;

    // -------------------------
    // ... the old witness will fail verification

    match presentation_verify(&presentation_schema_2, &presentation_2, nonce)
    {
        Ok(()) =>
            Err(vcp::Error::General("presentation_2.verify should have failed".to_string())),
        Err(vcp::Error::CredxError(error::Error::InvalidPresentationData)) =>
            Ok(()),
        Err(_e) =>
            Err(vcp::Error::General("presentation_2.verify returned incorrect error".to_string())),
    }?;

    // -------------------------
    // holder : update its witness

    let mem_witness_2                            = update_accumulator_witness_ac2c(
        mem_witness_1, &accum_element, &witness_update_info)?;

    // holder does a new presention/proof with the updated witness
    // TODO: Identical to mem_st_2?
    let mem_st_3                                 = create_mem_stmt(
        &sig_st_1, &accumulator_data_3.public_data, &acc_value_2, MEMBERSHIP_ELEMENT_INDEX)?;
    let (presentation_schema_3, presentation_3)  = presentation_create(
        &credential_1, &sig_st_1, &rvk_st_1, &mem_st_3, &mem_witness_2, nonce)?;

    // -------------------------
    // verification now succeeds

    presentation_verify(&presentation_schema_3, &presentation_3, nonce)?;

    // TODO : remove an accumulator member and verify old witness fails

    Ok(())
}

// ------------------------------------------------------------------------------
// Helper functions for the test above.

fn create_issuer() -> VCPResult<(IssuerPublic, Issuer)>
{
    const LABEL       : &str = "Test Schema";
    const DESCRIPTION : &str = "This is a test presentation schema";
    let schema_claims = [
        ClaimSchema {
            claim_type     : ClaimType::Revocation,
            label          : "identifier".to_string(),
            print_friendly : false,
            validators     : vec![],
        },
        ClaimSchema {
            claim_type     : ClaimType::Hashed,
            label          : "address".to_string(),
            print_friendly : true,
            validators     : vec![],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)
        .map_err(vcp::Error::CredxError)?;
    Ok(Issuer::new(&cred_schema))
}

fn sign_credential(issuer : &mut Issuer, membership_element : &String) -> VCPResult<CredentialBundle>
{
    issuer.sign_credential(&[
        RevocationClaim::from("CRED_156-6eda-45fb-a709-d22ebb5ec8a5").into(),
        HashedClaim::from(membership_element).into(),
    ]).map_err(vcp::Error::CredxError)
}

fn create_sig_and_revoke_stmts(
    issuer_public : &IssuerPublic,
) -> (SignatureStatement, RevocationStatement)
{
    let sig_st = SignatureStatement {
        disclosed        : btreeset! {},
        id               : random_string(16, rand::thread_rng()),
        issuer           : issuer_public.clone(),
    };
    let rvk_st = RevocationStatement {
        id               : random_string(16, rand::thread_rng()),
        reference_id     : sig_st.id.clone(),
        accumulator      : issuer_public.revocation_registry,
        verification_key : issuer_public.revocation_verifying_key,
        claim            : 0,
    };
    (sig_st, rvk_st)
}

fn create_mem_stmt(
    sig_st                   : &SignatureStatement,
    vk                       : &AccumulatorPublicData,
    acc                      : &credx::vcp::interfaces::types::Accumulator,
    idx                      : usize
) -> VCPResult<MembershipStatement>
{
    let accum_vk = from_api(vk)?;
    let mem_reg: vb20::Accumulator = from_api(acc)?;

    Ok(MembershipStatement {
        id               : random_string(16, thread_rng()),
        reference_id     : sig_st.id.clone(),
        accumulator      : mem_reg,
        verification_key : accum_vk,
        claim            : idx,
    })
}

fn presentation_create(
    credential : &CredentialBundle,
    sig_st     : &SignatureStatement,
    rvk_st     : &RevocationStatement,
    mem_st     : &MembershipStatement,
    amw        : &AccumulatorMembershipWitness,
    nonce      : &[u8],
) -> VCPResult<(PresentationSchema, Presentation)>
{
    let accum_membership_witness : vb20::MembershipWitness = from_api(amw)?;
    let credentials = indexmap! {
        sig_st.id.clone() => credential.credential.clone().into(),
        mem_st.id.clone() => accum_membership_witness.into(),
    };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.clone().into(),
        rvk_st.clone().into(),
        mem_st.clone().into(),
    ]);
    let presentation = Presentation::create(&credentials, &presentation_schema, nonce)
        .map_err(vcp::Error::CredxError)?;
    Ok((presentation_schema, presentation))
}

fn presentation_verify(
    presentation_schema : &PresentationSchema,
    presentation        : &Presentation,
    nonce               : &[u8],
) -> VCPResult<()>
{
    presentation.verify(presentation_schema, nonce).map_err(vcp::Error::CredxError)
}

// ------------------------------------------------------------------------------
// Same as knox/accumulator/vb20/witness.rs, except via API

#[test]
fn test_membership_batch_update() {
    let res = membership_batch_update();
    assert!(res.is_ok(), "{:?}", res);
}

fn membership_batch_update() -> VCPResult<()>
{
    let create_accumulator_data_ac2c
                            = create_accumulator_data();
    let ad0 = create_accumulator_data_ac2c(0)?;

    let elements            = [
        // These will be deleted later in the test.
        vb20::Element::hash(b"3"),vb20::Element::hash(b"4"),vb20::Element::hash(b"5"),
        // These will be kept. Element b"6" is Y
        vb20::Element::hash(b"6"),vb20::Element::hash(b"7"),vb20::Element::hash(b"8"),vb20::Element::hash(b"9"),];
    let (acc1,_)            = accumulator_add_remove_credx(&ad0.new_accum_data, &ad0.new_accum_value, &elements, &[])?;

    let y                   = elements[3];
    let accum_element       = to_api(y)?;
    let wit                 = create_accumulator_membership_witness(&ad0.new_accum_data, &acc1, &accum_element)?;
    assert!(witness_verify(&ad0.new_accum_data, &acc1, &wit, &y)?);

    let data                = [
        vb20::Element::hash(b"1"),vb20::Element::hash(b"2"),
        vb20::Element::hash(b"3"),vb20::Element::hash(b"4"),vb20::Element::hash(b"5"),
    ];
    let additions           = &data[0..2];
    let deletions           = &data[2..5];

    let (ad2, coefficients) = accumulator_add_remove_credx(&ad0.new_accum_data, &acc1, additions, deletions)?;
    let wit                 = witness_batch_update(&wit, &y, additions, deletions, &coefficients)?;
    assert!(witness_verify(&ad0.new_accum_data, &ad2, &wit, &y)?);

    Ok(())
}

// ------------------------------------------------------------------------------
// Same as src/knox/accumulator/vb20/accumulator.rs, except not "commmented out"
// and reduces iterations and sizes.

#[ignore]
#[test]
fn one_year_updates() {
    use std::time::SystemTime;

    const DAYS: usize                     = 2;

    let key                               = vb20::SecretKey::new(None);
    let pk                                = vb20::PublicKey::from(&key);
    let mut items: Vec<vb20::Element>     = (0..1_000_000).map(|_| vb20::Element::random()).collect();
    let mut acc                           = vb20::Accumulator::with_elements(&key, items.as_slice());

    let y                                 = *items.last().unwrap();
    let mut witness                       = vb20::MembershipWitness::new(y, acc, &key);
    let params                            = vb20::ProofParams::new(pk, None);
    let proof_message                     = ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(y.0));
    let committing                        = vb20::MembershipProofCommitting::new(proof_message, witness, params, pk);

    let mut transcript                    = merlin::Transcript::new(b"one_year_updates");
    committing.get_bytes_for_challenge(&mut transcript);

    let challenge                         = vb20::Element::from_transcript(b"challenge", &mut transcript);
    let proof                             = committing.gen_proof(challenge);
    let finalized                         = proof.finalize(acc, params, pk, challenge);
    let mut transcript                    = merlin::Transcript::new(b"one_year_updates");
    finalized.get_bytes_for_challenge(&mut transcript);
    let challenge2                        = vb20::Element::from_transcript(b"challenge", &mut transcript);
    assert_eq!(challenge2, challenge);

    let mut deltas                        = alloc::vec::Vec::with_capacity(DAYS);
    for i in 0..DAYS {
        let additions: Vec<vb20::Element> = (0..1000).map(|_| vb20::Element::random()).collect();
        let (deletions, titems)           = items.split_at(600);
        let t                             = titems.to_vec();
        let deletions                     = deletions.to_vec();
        items                             = t;
        println!("Update for single day: {}", i + 1);
        let before                        = SystemTime::now();
        let coefficients                  = acc.update_assign(&key, additions.as_slice(), deletions.as_slice());
        let time                          = SystemTime::now().duration_since(before).unwrap();
        println!("Time to complete: {:?}", time);
        deltas.push((additions, deletions, coefficients));
    }

    println!("Update witness");
    let before                            = SystemTime::now();
    witness.multi_batch_update_assign(y, deltas.as_slice());
    let time                              = SystemTime::now().duration_since(before).unwrap();
    println!("Time to complete: {:?}", time);
    let mut transcript                    = merlin::Transcript::new(b"one_year_updates");
    let committing                        = vb20::MembershipProofCommitting::new(proof_message, witness, params, pk);
    committing.get_bytes_for_challenge(&mut transcript);
    let challenge                         = vb20::Element::from_transcript(b"challenge", &mut transcript);
    let proof                             = committing.gen_proof(challenge);
    let finalized                         = proof.finalize(acc, params, pk, challenge);
    let mut transcript                    = merlin::Transcript::new(b"one_year_updates");
    finalized.get_bytes_for_challenge(&mut transcript);
    let challenge2                        = vb20::Element::from_transcript(b"challenge", &mut transcript);
    assert_eq!(challenge2, challenge);
}

// ------------------------------------------------------------------------------
// used by some tests above

// TODO: consistently use API versions for all arguments and return values?

fn accumulator_add_remove_credx(
    ad  : &AccumulatorData,
    acc : &credx::vcp::interfaces::types::Accumulator,
    add : &[vb20::Element], // DataValue
    rm  : &[vb20::Element], // DataValue
) -> VCPResult<(credx::vcp::interfaces::types::Accumulator, Vec<vb20::Coefficient>)>
{
    let AccumulatorData { secret_data: sd, .. } = ad;
    let sk = from_api(sd)?;
    let mem_reg: vb20::Accumulator = from_api(acc)?;
    let (acc2, coefficients): (vb20::Accumulator,_)  = mem_reg.update(&sk, add, rm);
    Ok((to_api(acc2)?, coefficients))
}

fn create_accumulator_membership_witness(
    ad  : &AccumulatorData,
    acc : &credx::vcp::interfaces::types::Accumulator,
    el  : &AccumulatorElement,
) -> VCPResult<AccumulatorMembershipWitness>
{
    let AccumulatorData { secret_data: sd, .. } = ad;
    let sk             = from_api(sd)?;
    let mc             = from_api(el)?;
    let mem_reg        = from_api(acc)?;
    let wit            = vb20::MembershipWitness::new(mc, mem_reg, &sk);
    to_api(wit)
}

fn witness_verify(
    ad  : &AccumulatorData,
    acc : &credx::vcp::interfaces::types::Accumulator,
    wit : &AccumulatorMembershipWitness,
    el  : &vb20::Element,
) -> VCPResult<bool>
{
    let AccumulatorData { public_data: pd, .. } = ad;
    let pk  = from_api(pd)?;
    let wit : vb20::MembershipWitness = from_api(wit)?;
    Ok(wit.verify(*el, pk, from_api(acc)?))
}

fn witness_batch_update(
    wit : &AccumulatorMembershipWitness,
    el  : &vb20::Element,
    add : &[vb20::Element],
    rm  : &[vb20::Element],
    coe : &Vec<vb20::Coefficient>,
) -> VCPResult<AccumulatorMembershipWitness>
{
    let wit : vb20::MembershipWitness = from_opaque_json(&wit.0)?;
    let wit2                          = wit.batch_update(*el, add, rm, coe.as_slice());
    Ok(AccumulatorMembershipWitness(to_opaque_json(&wit2)?))
}
