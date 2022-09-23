use credx::claim::{
    ClaimData, ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim,
};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::issuer::Issuer;
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{AccumulatorSetMembershipStatement, SignatureStatement, Statements};
use credx::{random_string, CredxResult};
use maplit::{btreemap, btreeset};
use rand_core::RngCore;

#[test]
fn presentation() {
    let res = test_presentation();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_presentation() -> CredxResult<()> {
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
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;

    let (issuer_public, issuer) = Issuer::new(&cred_schema);

    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = AccumulatorSetMembershipStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };

    let presentation_schema = PresentationSchema::new(&[sig_st.into(), acc_st.into()]);
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let credentials = btreemap! { CRED_ID.to_string() => credential.credential};
    let presentation = Presentation::create(
        &credentials,
        &presentation_schema,
        &nonce,
        rand::thread_rng(),
    )?;

    presentation.verify(&presentation_schema, &nonce)
}
