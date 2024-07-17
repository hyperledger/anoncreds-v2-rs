use blsful::inner_types::*;
use credx::claim::{
    ClaimType, NumberClaim, RevocationClaim,
};
use credx::error;
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::prelude::Issuer;
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{
    CommitmentStatement, RangeStatement, RevocationStatement, SignatureStatement,
};
use credx::{random_string, CredxResult};
use indexmap::indexmap;
use maplit::btreeset;
use rand::thread_rng;
use rand_core::RngCore;

fn setup() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn out_of_range_panic() {
    setup();
    let res = test_out_of_range_panic();
    assert_eq!(res, Err(error::Error::InvalidPresentationData));
}

#[allow(unused_variables)]
fn test_out_of_range_panic() -> CredxResult<()> {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;
    let (issuer_public, mut issuer) = Issuer::new(&cred_schema);
    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        NumberClaim::from(5).into(),
    ])?;

    // presentation/proof creation

    let sig_st = SignatureStatement {
        disclosed: btreeset! {},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let comm_st = CommitmentStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: 1,
    };
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 1,
        lower: Some(0),
        upper: Some(3),  // SIGNED VALUE OF 5 IS OUT OF THE REQUESTED RANGE
    };

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        range_st.into(),
    ]);
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    Presentation::create(&credentials, &presentation_schema, &nonce)?;

    Ok(())
}
