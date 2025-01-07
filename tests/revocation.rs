use credx::claim::{ClaimData, ClaimType, ClaimValidator, HashedClaim, RevocationClaim};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::issuer::Issuer;
use credx::knox::accumulator::vb20::Element;
use credx::knox::bbs::BbsScheme;
use credx::prelude::{
    MembershipClaim, MembershipCredential, MembershipRegistry, MembershipSigningKey,
    MembershipStatement, MembershipVerificationKey,
};
use credx::presentation::{Presentation, PresentationCredential, PresentationSchema};
use credx::statement::{RevocationStatement, SignatureStatement};
use credx::{random_string, CredxResult};
use indexmap::{indexmap, IndexMap};
use maplit::btreeset;
use rand::thread_rng;
use rand_core::RngCore;
use std::time::Instant;

macro_rules! setup_issuer {
    ($issuer:ident, $issuer_public:ident) => {
        const LABEL: &str = "Test Schema";
        const DESCRIPTION: &str = "This is a test presentation schema";
        let schema_claims = [
            ClaimSchema {
                claim_type: ClaimType::Revocation,
                label: "identifier".to_string(),
                print_friendly: false,
                validators: vec![],
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
        ];
        let cred_schema =
            CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims).unwrap();

        let before = Instant::now();
        let ($issuer_public, mut $issuer) = Issuer::<BbsScheme>::new(&cred_schema);
        println!("key generation time = {:?}", before.elapsed());
    };
}

macro_rules! setup_cred {
    ($issuer:ident, $credential:ident, $cred_id:expr, $str_for_membership:expr) => {
        let before = std::time::Instant::now();
        let $credential = $issuer
            .sign_credential(&[
                RevocationClaim::from($cred_id).into(),
                HashedClaim::from($str_for_membership).into(),
            ])
            .unwrap();
        println!("sign credential {:?}", before.elapsed());
    };
}

fn create_and_verify(
    presentation_schema: PresentationSchema<BbsScheme>,
    credentials: IndexMap<String, PresentationCredential<BbsScheme>>,
) -> CredxResult<()> {
    // println!("{}", serde_json::to_string(&presentation_schema).unwrap());
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    let before = Instant::now();
    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
    println!("proof generation: {:?}", before.elapsed());
    presentation.verify(&presentation_schema, &nonce)?;
    let before = Instant::now();
    println!("proof verification: {:?}", before.elapsed());
    let proof_data = serde_bare::to_vec(&presentation).unwrap();
    let presentation: Presentation<BbsScheme> = serde_bare::from_slice(&proof_data).unwrap();
    println!("proof size = {}", proof_data.len());
    presentation.verify(&presentation_schema, &nonce)
}

macro_rules! define_sig_st {
    ($issuer_public:ident, $sig_st:ident) => {
        let $sig_st = SignatureStatement {
            disclosed: btreeset! {"name".to_string()},
            id: random_string(16, rand::thread_rng()),
            issuer: $issuer_public.clone(),
        };
    };
}

const CRED_ID_1: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
const CRED_ID_2: &str = "81742856-6eda-45fb-a709-d22ebb5ec8a5";

const STR_FOR_MEMBERSHIP_1: &str = "P Sherman 42 Wallaby Way Sydney";
const STR_FOR_MEMBERSHIP_2: &str = "Q Sherman 42 Wallaby Way Sydney";

fn element_from_membership_claim(s: &str) -> Element {
    MembershipClaim::from(ClaimData::from(HashedClaim::from(s))).0
}

#[test]
fn test_revocation() {
    setup_issuer!(issuer, issuer_public);
    setup_cred!(issuer, credential, CRED_ID_1, STR_FOR_MEMBERSHIP_1);
    define_sig_st!(issuer_public, sig_st);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.clone().into() };
    let acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let presentation_schema = PresentationSchema::new(&[sig_st.clone().into(), acc_st.into()]);

    // Test that Holder can succeed
    assert!(create_and_verify(presentation_schema.clone(), credentials.clone()).is_ok());

    // Revoke credential and test that Holder cannot convince Verifier that its credential is not revoked
    let updated_registry = issuer_public.revocation_registry.remove(
        &issuer.revocation_key,
        element_from_membership_claim(STR_FOR_MEMBERSHIP_1),
    );
    let acc_st_updated = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: updated_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let presentation_schema_updated =
        PresentationSchema::new(&[sig_st.clone().into(), acc_st_updated.into()]);
    assert!(create_and_verify(presentation_schema_updated.clone(), credentials).is_err());
}

#[test]
fn test_explicit_membership_after_removal() {
    setup_issuer!(issuer, issuer_public);
    setup_cred!(issuer, credential, CRED_ID_1, STR_FOR_MEMBERSHIP_1);

    // Initialise registry with one credential
    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::with_elements(
        &dummy_sk,
        &[element_from_membership_claim(STR_FOR_MEMBERSHIP_1)],
    );
    let dummy_membership_credential = MembershipCredential::new(
        MembershipClaim::from(&credential.credential.claims[1]).0,
        dummy_registry,
        &dummy_sk,
    );

    // Test that Holder can succeed proving membership with new credential
    define_sig_st!(issuer_public, sig_st);
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry,
        verification_key: dummy_vk,
        claim: 1,
    };

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.clone().into(),
    mem_st.id.clone() => dummy_membership_credential.into()  };
    let presentation_schema = PresentationSchema::new(&[sig_st.clone().into(), mem_st.into()]);
    assert!(create_and_verify(presentation_schema, credentials).is_ok());

    // Remove Holder's membership element from registry and test that it can no longer succeed
    let dummy_registry_updated = dummy_registry.remove(
        &dummy_sk,
        element_from_membership_claim(STR_FOR_MEMBERSHIP_1),
    );
    let mem_st_updated = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry_updated,
        verification_key: dummy_vk,
        claim: 1,
    };
    let credentials_updated = indexmap! { sig_st.id.clone() => credential.credential.into(),
    mem_st_updated.id.clone() => dummy_membership_credential.into()  };
    let presentation_schema_updated =
        PresentationSchema::new(&[sig_st.into(), mem_st_updated.into()]);
    assert!(create_and_verify(presentation_schema_updated, credentials_updated).is_err())
}

#[test]
fn test_explicit_membership_witness_sharing_attempt_after_removal() {
    setup_issuer!(issuer, issuer_public);
    setup_cred!(issuer, credential_1, CRED_ID_1, STR_FOR_MEMBERSHIP_1);
    setup_cred!(issuer, credential_2, CRED_ID_2, STR_FOR_MEMBERSHIP_2);

    // Initialise registry with two credentials
    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::with_elements(
        &dummy_sk,
        &[
            element_from_membership_claim(STR_FOR_MEMBERSHIP_1),
            element_from_membership_claim(STR_FOR_MEMBERSHIP_2),
        ],
    );

    // Get initial witnesses for two Holders
    let dummy_membership_credential_1 = MembershipCredential::new(
        MembershipClaim::from(&credential_1.credential.claims[1]).0,
        dummy_registry,
        &dummy_sk,
    );
    let dummy_membership_credential_2 = MembershipCredential::new(
        MembershipClaim::from(&credential_2.credential.claims[1]).0,
        dummy_registry,
        &dummy_sk,
    );

    // Remove Holder1's membership element from set and request proving membership in updated registry
    let (dummy_registry_updated, coefficients) = dummy_registry.update(
        &dummy_sk,
        &[],
        &[element_from_membership_claim(STR_FOR_MEMBERSHIP_1)],
    );
    define_sig_st!(issuer_public, sig_st);
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry_updated,
        verification_key: dummy_vk,
        claim: 1,
    };
    let presentation_schema =
        PresentationSchema::new(&[sig_st.clone().into(), mem_st.clone().into()]);

    // Test that Holder1 fails because its value has been removed
    let credentials_1 = indexmap! { sig_st.id.clone() => credential_1.credential.clone().into(),
    mem_st.id.clone() => dummy_membership_credential_1.into() };
    assert!(create_and_verify(presentation_schema.clone(), credentials_1).is_err());

    // Test that Holder1 still fails despite updating its witness
    let dummy_membership_credential_1_updated = dummy_membership_credential_1.batch_update(
        element_from_membership_claim(STR_FOR_MEMBERSHIP_2),
        &[],
        &[element_from_membership_claim(STR_FOR_MEMBERSHIP_1)],
        &coefficients,
    );
    let credentials_1_updated = indexmap! { sig_st.id.clone() => credential_1.credential.clone().into(),
    mem_st.id.clone() => dummy_membership_credential_1_updated.into() };
    assert!(create_and_verify(presentation_schema.clone(), credentials_1_updated).is_err());

    // Test that Holder2 fails because it has not updated its witness
    let credentials_2 = indexmap! { sig_st.id.clone() => credential_2.credential.clone().into(),
    mem_st.id.clone() => dummy_membership_credential_2.into() };
    assert!(create_and_verify(presentation_schema.clone(), credentials_2).is_err());

    // Test that Holder2 succeeds after updating its witness
    let dummy_membership_credential_2_updated = dummy_membership_credential_2.batch_update(
        element_from_membership_claim(STR_FOR_MEMBERSHIP_2),
        &[],
        &[element_from_membership_claim(STR_FOR_MEMBERSHIP_1)],
        &coefficients,
    );
    let credentials_2_updated = indexmap! { sig_st.id.clone() => credential_2.credential.into(),
    mem_st.id.clone() => dummy_membership_credential_2_updated.into() };
    assert!(create_and_verify(presentation_schema.clone(), credentials_2_updated).is_ok());

    // Test that Holder1 cannot succeed using Holder2's updated witness (dummy_membership_credential_2)
    let credentials_1_cheating = indexmap! { sig_st.id.clone() => credential_1.credential.into(),
    mem_st.id.clone() => dummy_membership_credential_2_updated.into() };
    assert!(create_and_verify(presentation_schema, credentials_1_cheating).is_err())
}
