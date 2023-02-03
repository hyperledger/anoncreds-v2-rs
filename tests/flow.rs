use credx::blind::BlindCredentialRequest;
use credx::claim::{
    ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim, ScalarClaim,
};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::error::Error;
use credx::issuer::Issuer;
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{
    CommitmentStatement, RangeStatement, RevocationStatement, SignatureStatement,
    VerifiableEncryptionStatement,
};
use credx::{random_string, CredxResult};
use group::ff::Field;
use indexmap::indexmap;
use maplit::{btreemap, btreeset};
use rand::thread_rng;
use rand_core::RngCore;
use regex::Regex;
use yeti::knox::bls12_381_plus::{ExpandMsgXmd, G1Projective, Scalar};
use yeti::sha2;
use credx::prelude::{MembershipClaim, MembershipCredential, MembershipRegistry, MembershipSigningKey, MembershipStatement, MembershipVerificationKey};

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

    let (issuer_public, mut issuer) = Issuer::new(&cred_schema);

    let before = std::time::Instant::now();
    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;
    let after = std::time::Instant::now();
    println!("{:?}", after - before);

    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::random(thread_rng());
    let dummy_membership_credential = MembershipCredential::new(MembershipClaim::from(&credential.credential.claims[2]).0, dummy_registry, &dummy_sk);

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
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
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::generator(),
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
    };
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry,
        verification_key: dummy_vk,
        claim: 2,
    };

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into(), mem_st.id.clone() => dummy_membership_credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
        mem_st.into(),
    ]);
    println!("{}", serde_json::to_string(&presentation_schema).unwrap());
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
    presentation.verify(&presentation_schema, &nonce)?;
    let proof_data = serde_bare::to_vec(&presentation).unwrap();
    let presentation: Presentation = serde_bare::from_slice(&proof_data).unwrap();
    println!("proof size = {}", proof_data.len());
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
            validators: vec![
                ClaimValidator::Length {
                    min: None,
                    max: Some(u8::MAX as usize),
                },
                ClaimValidator::Regex(Regex::new(r#"[\w\s]+"#).unwrap()),
                ClaimValidator::AnyOne(vec![
                    NumberClaim::from(0).into(),
                    NumberClaim::from(2).into(),
                    NumberClaim::from(4).into(),
                    NumberClaim::from(6).into(),
                    NumberClaim::from(8).into(),
                    NumberClaim::from(10).into(),
                ]),
            ],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u32::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;

    println!("{}", serde_json::to_string(&cred_schema).unwrap());

    let (issuer_public, mut issuer) = Issuer::new(&cred_schema);

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
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::generator(),
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
    };
    let range_st = RangeStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
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

#[test]
fn blind_sign_request() {
    let res = test_blind_sign_request();
    assert!(res.is_ok(), "{:?}", res);
}

fn test_blind_sign_request() -> CredxResult<()> {
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
            claim_type: ClaimType::Scalar,
            label: "link_secret".to_string(),
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
    let cred_schema = CredentialSchema::new(
        Some(LABEL),
        Some(DESCRIPTION),
        &["link_secret"],
        &schema_claims,
    )?;

    let (issuer_public, mut issuer) = Issuer::new(&cred_schema);

    let blind_claims = btreemap! { "link_secret".to_string() => ScalarClaim::from(Scalar::random(rand_core::OsRng)).into() };
    let (request, blinder) = BlindCredentialRequest::new(&issuer_public, &blind_claims)?;

    let blind_bundle = issuer.blind_sign_credential(
        &request,
        &btreemap! {
            "identifier".to_string() => RevocationClaim::from(CRED_ID).into(),
            "name".to_string() => HashedClaim::from("John Doe").into(),
            "address".to_string() => HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            "age".to_string() => NumberClaim::from(30303).into(),
        },
    )?;

    let _ = blind_bundle.to_unblinded(&blind_claims, blinder)?;

    Ok(())
}
