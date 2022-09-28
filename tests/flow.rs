use credx::claim::{ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::error::Error;
use credx::issuer::Issuer;
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{
    AccumulatorSetMembershipStatement, CommitmentStatement, SignatureStatement,
    VerifiableEncryptionStatement,
};
use credx::{random_string, CredxResult};
use maplit::{btreemap, btreeset};
use rand_core::RngCore;
use yeti::knox::bls12_381_plus::{ExpandMsgXmd, G1Projective};
use yeti::sha2;

#[test]
fn presentation_1_credential_works() {
    let res = test_presentation_1_credential_works();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_presentation_1_credential_works() -> CredxResult<()> {
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
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::generator(),
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
    };

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let credentials = btreemap! { sig_st.id.clone() => credential.credential};
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
    ]);
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;

    presentation.verify(&presentation_schema, &nonce)
}

#[test]
fn presentation_1_credential_alter_revealed_message_fails() {
    let res = test_presentation_1_credential_alter_revealed_message_fails();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_presentation_1_credential_alter_revealed_message_fails() -> CredxResult<()> {
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

    let sig_st_id = random_string(16, rand::thread_rng());
    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: sig_st_id.clone(),
        issuer: issuer_public.clone(),
    };
    let acc_st = AccumulatorSetMembershipStatement {
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
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::generator(),
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
    };

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let credentials = btreemap! { sig_st.id.clone() => credential.credential};
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
    ]);
    let mut presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;

    let disclosed_claim = presentation
        .disclosed_messages
        .get_mut(&sig_st_id)
        .unwrap()
        .get_mut("name")
        .unwrap();
    *disclosed_claim = HashedClaim::from("Jane Doe").into();

    match presentation.verify(&presentation_schema, &nonce) {
        Err(_) => Ok(()),
        Ok(_) => Err(Error::InvalidPresentationData),
    }
}