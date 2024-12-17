use std::collections::HashMap;

use blsful::inner_types::{ExpandMsgXmd, G1Projective};
use chrono::{Duration, Local, NaiveDate};
use credx::knox::ps::PsScheme;
use credx::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use credx::{
    claim::{ClaimData, ClaimType, HashedClaim, NumberClaim, RevocationClaim},
    credential::{ClaimSchema, CredentialBundle, CredentialSchema},
    issuer::{Issuer, IssuerPublic},
    presentation::{Presentation, PresentationCredential, PresentationSchema},
    random_string,
    statement::{
        CommitmentStatement, EqualityStatement, RangeStatement, RevocationStatement,
        SignatureStatement, Statements, VerifiableEncryptionStatement,
    },
    CredxResult,
};
use indexmap::{indexmap, IndexMap};
use maplit::btreeset;
use rand::{thread_rng, RngCore};
use uuid::Uuid;

const SOC_SEC_CRED_LABEL: &str = "SOCIAL SECURITY";
const SOC_SEC_CRED_DESCRIPTION: &str = "This is a made up social security";
const PASSPORT_CRED_LABEL: &str = "PASSPORT";
const PASSPORT_CRED_DESCRIPTION: &str = "This is a made up passport";
const BANK_STMT_CRED_LABEL: &str = "BANK STATEMENT";
const BANK_STMT_CRED_DESCRIPTION: &str = "This is a made up bank statement";
const BANK_DID: &str = "did:vdra:bank";
const DOS_DID: &str = "did:gov:dos";
const SSA_DID: &str = "did:gov:ssa";

#[test]
fn real_id_implementation() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Setup: The issuers publish credential schemas in verifiable data registry (VDR)
    let (vdr, bank_wallet, dos_wallet, ssa_wallet) = issuer_setup::<PsScheme>();

    // Department of Public Safety (DPS) creates presentation schema for the claims it requires from various issuers to verify the applicant for the purpose of issuing a Real ID
    let real_id_presentation_schema = create_real_id_presentation_schema(&vdr);

    // Alice gets her social security verifiable credential
    let vc_soc_sec = request_social_security_credential(ssa_wallet).unwrap();
    //assert!(vc_soc_sec.is_ok(), "{:?}", vc_soc_sec);

    // Alice gets her passport verifiable credential
    let vc_passport = request_passport_credential(dos_wallet).unwrap();
    // assert!(vc_passport.is_ok(), "{:?}", vc_passport);

    // Alice gets her bank statement credential
    let vc_bank_stmt = request_bank_statement_credential(bank_wallet).unwrap();
    // assert!(vc_bank_stmt.is_ok(), "{:?}", vc_bank_stmt);

    // Alice prepares presentation for Real ID with selective disclosure from her credentials
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let alice_real_id_presentation = create_real_id_presentation_with_selective_disclosure(
        &real_id_presentation_schema,
        &vc_soc_sec,
        &vc_passport,
        &vc_bank_stmt,
        &nonce,
    );
    assert!(
        alice_real_id_presentation.is_ok(),
        "{:?}",
        alice_real_id_presentation
    );
    //println!("Aloice's Real ID presentation: {:?} ", alice_real_id_presentation.unwrap());

    // DPS verifies Alice's credentials and issues Real ID
    let verification_status = alice_real_id_presentation
        .unwrap()
        .verify(&real_id_presentation_schema, &nonce);
    assert!(verification_status.is_ok(), "{:?}", verification_status);
}

fn create_real_id_presentation_with_selective_disclosure<S: ShortGroupSignatureScheme>(
    real_id_presentation_schema: &PresentationSchema<S>,
    vc_soc_sec: &CredentialBundle<S>,
    vc_passport: &CredentialBundle<S>,
    vc_bank_stmt: &CredentialBundle<S>,
    nonce: &[u8],
) -> Result<Presentation<S>, credx::prelude::Error> {
    let mut soc_sec_sig_st_id = Default::default();
    let mut dos_passport_sig_st_id = Default::default();
    let mut bank_statement_sig_st_id = Default::default();

    for (_, v) in real_id_presentation_schema.statements.iter() {
        match v {
            Statements::Signature(sig) => {
                // println!("Signature {:?} {:?}", sig.id, sig.issuer.schema.label);
                let label = sig.issuer.schema.label.clone().unwrap();
                match label.as_str() {
                    SOC_SEC_CRED_LABEL => {
                        soc_sec_sig_st_id = sig.id.clone();
                    }
                    PASSPORT_CRED_LABEL => {
                        dos_passport_sig_st_id = sig.id.clone();
                    }
                    BANK_STMT_CRED_LABEL => {
                        bank_statement_sig_st_id = sig.id.clone();
                    }
                    &_ => println!("Not expected"),
                }
            }
            _ => (),
        }
    }

    let alice_credentials_for_real_id: IndexMap<String, PresentationCredential<S>> = indexmap! {
        soc_sec_sig_st_id => vc_soc_sec.credential.clone().into(),
        dos_passport_sig_st_id => vc_passport.credential.clone().into(),
        bank_statement_sig_st_id => vc_bank_stmt.credential.clone().into(),
    };

    let alice_real_id_presentation = Presentation::create(
        &alice_credentials_for_real_id,
        &real_id_presentation_schema,
        &nonce,
    );

    alice_real_id_presentation
}

fn create_real_id_presentation_schema<S: ShortGroupSignatureScheme>(
    vdr: &HashMap<String, IssuerPublic<S>>,
) -> PresentationSchema<S> {
    // Claims needed from Social Security Card issued by SSA
    let ssa_soc_sec_statements = create_soc_sec_statements_for_realid(&vdr);
    let soc_security_schema = vdr.get(SSA_DID).unwrap().schema.clone();

    // Claims needed from passport issued by DoS
    let dos_passport_statements = create_dos_passport_statements_for_realid(&vdr);
    let passport_schema = vdr.get(DOS_DID).unwrap().schema.clone();

    // Claims need from Bank Statement
    let bank_statement_statements = create_bank_statement_statements_for_realid(&vdr);
    let bank_statement_schema = vdr.get(BANK_DID).unwrap().schema.clone();

    // EqualityStatement is used to check that a non-disclosed claim is the same across multiple other statements.
    // name check
    let soc_sec_sig_st_id = ssa_soc_sec_statements[0].id();
    let dos_passport_sig_st_id = dos_passport_statements[0].id();
    let bank_statement_sig_st_id = bank_statement_statements[0].id();

    let real_id_eq_st_name = EqualityStatement {
        id: random_string(16, rand::thread_rng()),
        ref_id_claim_index: indexmap! {
            soc_sec_sig_st_id.clone() => soc_security_schema.claim_indices.get_index_of("first_last_name").unwrap(),
            dos_passport_sig_st_id.clone() => passport_schema.claim_indices.get_index_of("first_last_name").unwrap(),
            bank_statement_sig_st_id.clone() => bank_statement_schema.claim_indices.get_index_of("first_last_name").unwrap(),
        },
    };

    // Final step for creating the presentation schema
    let mut real_id_statements: Vec<Statements<S>> = Vec::new();
    real_id_statements.append(&mut ssa_soc_sec_statements.to_vec());
    real_id_statements.append(&mut dos_passport_statements.to_vec());
    real_id_statements.append(&mut bank_statement_statements.to_vec());
    real_id_statements.append(&mut [real_id_eq_st_name.into()].to_vec());

    let real_id_presentation_schema = PresentationSchema::new(&real_id_statements);

    real_id_presentation_schema
}

fn create_bank_statement_statements_for_realid<S: ShortGroupSignatureScheme>(
    vdr: &HashMap<String, IssuerPublic<S>>,
) -> [Statements<S>; 5] {
    let bank_public = vdr.get(&BANK_DID.to_string()).unwrap();
    let current_date = Local::now().date_naive();
    let schema = bank_public.schema.clone();

    // Undisclosed or hidden attributes: Account Number, Full Name, Start Date, End Date,
    // No further action is needed.

    // SignatureStatement defines which issuer a signature must come from and which claims must be disclosed.
    // “Address Line1”, “Address Line2”, “State”, and “ZIP” from Bank Statement
    let bank_statement_sig_st = SignatureStatement {
        id: random_string(16, rand::thread_rng()),
        issuer: bank_public.clone(),
        disclosed: btreeset! {
            "address_line1".to_string(),
            "address_line2".to_string(),
            "address_state".to_string(),
            "address_zip".to_string(),
        },
    };

    // Revocation Statement
    let bank_statement_acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: bank_statement_sig_st.id.clone(),
        accumulator: bank_public.revocation_registry,
        verification_key: bank_public.revocation_verifying_key,
        claim: schema.claim_indices.get_index_of("identifier").unwrap(),
    };

    // CommtimentStatement creates a unique value based on a claim. Is also used to link to range statements.
    let bank_statement_comm_st_start_date = CommitmentStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: bank_statement_sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: schema.claim_indices.get_index_of("start_date").unwrap(),
    };

    // RangeStatement defines a proof where a claim is in a range. Requires a commitment statement for the specified claim.
    // Check that the bank statement is not older than sixty days: “Start Date” > current date — 60 days

    let sixty_days_ago = current_date - Duration::days(60);
    let start_date_lower = days_since_1_jan_1900(sixty_days_ago).unwrap();

    // start date upper is today
    let start_date_upper = days_since_1_jan_1900(current_date).unwrap();

    let bank_statement_range_st_start_date = RangeStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: bank_statement_comm_st_start_date.id.clone(),
        signature_id: bank_statement_sig_st.id.clone(),
        claim: schema.claim_indices.get_index_of("start_date").unwrap(),
        lower: Some(start_date_lower.try_into().unwrap()),
        upper: Some(start_date_upper.try_into().unwrap()),
    };

    // VerifiableEncryptionStatement defines a proof where a claim is proven to be encrypted in a ciphertext.
    // number

    let bank_statement_verenc_st = VerifiableEncryptionStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: bank_statement_sig_st.id.clone(),
        message_generator: G1Projective::GENERATOR,
        encryption_key: bank_public.verifiable_encryption_key,
        claim: schema.claim_indices.get_index_of("account_number").unwrap(),
    };

    let bank_statement_statements: [Statements<S>; 5] = [
        bank_statement_sig_st.into(),
        bank_statement_acc_st.into(),
        bank_statement_comm_st_start_date.into(),
        bank_statement_range_st_start_date.into(),
        bank_statement_verenc_st.into(),
    ];

    bank_statement_statements
}

fn create_dos_passport_statements_for_realid<S: ShortGroupSignatureScheme>(
    vdr: &HashMap<String, IssuerPublic<S>>,
) -> [Statements<S>; 7] {
    let dos_public = vdr.get(&DOS_DID.to_string()).unwrap();
    let schema = dos_public.schema.clone();
    let current_date = Local::now().date_naive();

    // Undisclosed or hidden attributes: full name, nationality, sex, place of birth, date of issue, authority.
    // No further action is needed.

    // SignatureStatement defines which issuer a signature must come from and which claims must be disclosed.
    // disclosing none
    let dos_passport_sig_st = SignatureStatement {
        id: random_string(16, rand::thread_rng()),
        issuer: dos_public.clone(),
        disclosed: btreeset! {},
    };

    // Revocation Statement
    let dos_passport_acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_sig_st.id.clone(),
        accumulator: dos_public.revocation_registry,
        verification_key: dos_public.revocation_verifying_key,
        claim: schema.claim_indices.get_index_of("identifier").unwrap(),
    };

    // CommtimentStatement creates a unique value based on a claim. Is also used to link to range statements.
    let dos_passport_comm_st_dob = CommitmentStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: schema.claim_indices.get_index_of("dob").unwrap(),
    };

    let dos_passport_comm_st_date_of_expiration = CommitmentStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: schema
            .claim_indices
            .get_index_of("date_of_expiration")
            .unwrap(),
    };

    // RangeStatement defines a proof where a claim is in a range. Requires a commitment statement for the specified claim.
    // dob, date of expiration

    // dob lower is Jan 1, 1900
    let dob_lower_date = chrono::NaiveDate::from_ymd_opt(1900, 01, 01).unwrap();
    let dob_lower = days_since_1_jan_1900(dob_lower_date).unwrap();

    // dob upper is the current date minus 16 years
    let sixteen_years_ago = current_date - Duration::days(16 * 365); // Assuming 365 days per year
    let dob_upper = days_since_1_jan_1900(sixteen_years_ago).unwrap();

    let dos_passport_range_st_dob = RangeStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_comm_st_dob.id.clone(),
        signature_id: dos_passport_sig_st.id.clone(),
        claim: schema.claim_indices.get_index_of("dob").unwrap(),
        lower: Some(dob_lower.try_into().unwrap()),
        upper: Some(dob_upper.try_into().unwrap()),
    };

    // date of expiration is greater than today + 6 months => date_of_expiration_lower
    // date_of_expiration upper is today + 20 years
    let date_of_expiration_lower = current_date + Duration::days(180);
    let date_of_expiration_lower_since_1900 =
        days_since_1_jan_1900(date_of_expiration_lower).unwrap();
    let date_of_expiration_upper = current_date + Duration::days(20 * 365);
    let date_of_expiration_upper_since_1900 =
        days_since_1_jan_1900(date_of_expiration_upper).unwrap();

    let dos_passport_range_st_date_of_expiration = RangeStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_comm_st_date_of_expiration.id.clone(),
        signature_id: dos_passport_sig_st.id.clone(),
        claim: schema
            .claim_indices
            .get_index_of("date_of_expiration")
            .unwrap(),
        lower: Some(date_of_expiration_lower_since_1900.try_into().unwrap()),
        upper: Some(date_of_expiration_upper_since_1900.try_into().unwrap()),
    };

    // VerifiableEncryptionStatement defines a proof where a claim is proven to be encrypted in a ciphertext.
    // number

    let dos_passport_verenc_st = VerifiableEncryptionStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: dos_passport_sig_st.id.clone(),
        message_generator: G1Projective::GENERATOR,
        encryption_key: dos_public.verifiable_encryption_key,
        claim: schema
            .claim_indices
            .get_index_of("passport_number")
            .unwrap(),
    };

    let dos_passport_statements: [Statements<S>; 7] = [
        dos_passport_sig_st.into(),
        dos_passport_acc_st.into(),
        dos_passport_comm_st_dob.into(),
        dos_passport_comm_st_date_of_expiration.into(),
        dos_passport_range_st_dob.into(),
        dos_passport_range_st_date_of_expiration.into(),
        dos_passport_verenc_st.into(),
    ];

    dos_passport_statements
}

fn create_soc_sec_statements_for_realid<S: ShortGroupSignatureScheme>(
    vdr: &HashMap<String, IssuerPublic<S>>,
) -> [Statements<S>; 3] {
    let ssa_public = vdr.get(&SSA_DID.to_string()).unwrap();
    let schema = ssa_public.schema.clone();

    let soc_sec_sig_st = SignatureStatement {
        id: random_string(16, rand::thread_rng()),
        issuer: ssa_public.clone(),
        disclosed: btreeset! {},
    };

    let soc_sec_acc_st = RevocationStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: soc_sec_sig_st.id.clone(),
        accumulator: ssa_public.revocation_registry,
        verification_key: ssa_public.revocation_verifying_key,
        claim: schema.claim_indices.get_index_of("identifier").unwrap(),
    };

    let soc_sec_verenc_st = VerifiableEncryptionStatement {
        id: random_string(16, rand::thread_rng()),
        reference_id: soc_sec_sig_st.id.clone(),
        message_generator: G1Projective::GENERATOR,
        encryption_key: ssa_public.verifiable_encryption_key,
        claim: schema.claim_indices.get_index_of("soc_sec_number").unwrap(),
    };

    let soc_sec_statements: [Statements<S>; 3] = [
        soc_sec_sig_st.into(),
        soc_sec_acc_st.into(),
        soc_sec_verenc_st.into(),
    ];

    soc_sec_statements
}

fn issuer_setup<S: ShortGroupSignatureScheme>() -> (
    HashMap<String, IssuerPublic<S>>,
    HashMap<String, Issuer<S>>,
    HashMap<String, Issuer<S>>,
    HashMap<String, Issuer<S>>,
) {
    // issuer setup
    let mut vdr: HashMap<String, IssuerPublic<S>> = HashMap::new();
    // setup bank
    let bank_wallet = setup_bank(&mut vdr);
    // setup dos
    let dos_wallet = setup_dos(&mut vdr);
    // setup ssa
    let ssa_wallet = setup_ssa(&mut vdr);

    (vdr, bank_wallet, dos_wallet, ssa_wallet)
}

fn setup_ssa<S: ShortGroupSignatureScheme>(
    vdr: &mut HashMap<String, IssuerPublic<S>>,
) -> HashMap<String, Issuer<S>> {
    let mut ssa_wallet: HashMap<String, Issuer<S>> = HashMap::new();

    let soc_sec_claims = define_soc_sec_claims_schemas();
    assert!(!soc_sec_claims.is_empty(), "{:?}", soc_sec_claims);

    let vc_soc_sec_schema = CredentialSchema::new(
        Some(SOC_SEC_CRED_LABEL),
        Some(SOC_SEC_CRED_DESCRIPTION),
        &[],
        &soc_sec_claims,
    )
    .unwrap();

    let (ssa_public, mut ssa) = Issuer::new(&vc_soc_sec_schema);
    vdr.insert(SSA_DID.to_string(), ssa_public);
    ssa_wallet.insert(SSA_DID.to_string(), ssa);

    ssa_wallet
}

fn setup_dos<S: ShortGroupSignatureScheme>(
    vdr: &mut HashMap<String, IssuerPublic<S>>,
) -> HashMap<String, Issuer<S>> {
    let mut dos_wallet: HashMap<String, Issuer<S>> = HashMap::new();

    // Passport Claim Schemas
    let passport_claims = define_passport_claims_schemas();
    assert!(!passport_claims.is_empty(), "{:?}", passport_claims);

    let vc_passport_schema = CredentialSchema::new(
        Some(PASSPORT_CRED_LABEL),
        Some(PASSPORT_CRED_DESCRIPTION),
        &[],
        &passport_claims,
    )
    .unwrap();

    let (dos_public, mut dos) = Issuer::new(&vc_passport_schema);
    vdr.insert(DOS_DID.to_string(), dos_public);
    dos_wallet.insert(DOS_DID.to_string(), dos);

    dos_wallet
}

fn setup_bank<S: ShortGroupSignatureScheme>(
    vdr: &mut HashMap<String, IssuerPublic<S>>,
) -> HashMap<String, Issuer<S>> {
    let mut bank_wallet: HashMap<String, Issuer<S>> = HashMap::new();
    let bank_stmt_claims = define_bank_statement_claims_schemas();
    assert!(!bank_stmt_claims.is_empty(), "{:?}", bank_stmt_claims);

    let vc_bank_stmt_schema = CredentialSchema::new(
        Some(BANK_STMT_CRED_LABEL),
        Some(BANK_STMT_CRED_DESCRIPTION),
        &[],
        &bank_stmt_claims,
    )
    .unwrap();

    let (bank_a_public, mut bank_a) = Issuer::new(&vc_bank_stmt_schema);
    vdr.insert(BANK_DID.to_string(), bank_a_public);
    bank_wallet.insert(BANK_DID.to_string(), bank_a);

    bank_wallet
}

fn define_soc_sec_claims_schemas() -> Vec<ClaimSchema> {
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "soc_sec_number".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "first_last_name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    schema_claims.to_vec()
}

fn define_passport_claims_schemas() -> Vec<ClaimSchema> {
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "passport_number".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "first_last_name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "nationality".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "dob".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "sex".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "place_of_birth".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "date_of_issue".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "date_of_expiration".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "claim_issuing_authority".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    schema_claims.to_vec()
}

fn define_bank_statement_claims_schemas() -> Vec<ClaimSchema> {
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "account_number".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "first_last_name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "start_date".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "end_date".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address_line1".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address_line2".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address_state".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address_zip".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    schema_claims.to_vec()
}

fn request_bank_statement_credential<S: ShortGroupSignatureScheme>(
    bank_wallet: HashMap<String, Issuer<S>>,
) -> CredxResult<CredentialBundle<S>> {
    let current_date = Local::now().date_naive();
    let mut bank_a: Issuer<S> = bank_wallet.get(&BANK_DID.to_string()).unwrap().to_owned();

    // Start date is 45 days in the past. Map dates to integers - it's the number of days since 1/1/1900
    let forty_five_days_ago = current_date - Duration::days(45);
    let start_date_since_1900 = days_since_1_jan_1900(forty_five_days_ago)?;

    // End date is 30 days from the start date
    let end_date_since_1900 = start_date_since_1900 + 30;

    let claims: [ClaimData; 9] = [
        RevocationClaim::from(Uuid::new_v4().to_string()).into(),
        HashedClaim::from("A00000224").into(),
        HashedClaim::from("Alice Verifiable").into(),
        NumberClaim::from(start_date_since_1900).into(),
        NumberClaim::from(end_date_since_1900).into(),
        HashedClaim::from("3245 Digital Street").into(),
        HashedClaim::from("").into(),
        HashedClaim::from("IL").into(),
        HashedClaim::from("12345").into(),
    ];

    let vc_bank_stmt = bank_a.sign_credential(&claims)?;
    Ok(vc_bank_stmt)
}

fn request_passport_credential<S: ShortGroupSignatureScheme>(
    dos_wallet: HashMap<String, Issuer<S>>,
) -> CredxResult<CredentialBundle<S>> {
    // Map dates to integers - it's the number of days since 1/1/1900
    let dob = chrono::NaiveDate::from_ymd_opt(2000, 02, 17).unwrap();
    let dob_since_1900 = days_since_1_jan_1900(dob)?;
    let date_of_issue = chrono::NaiveDate::from_ymd_opt(2020, 02, 15).unwrap();
    let date_of_issue_since_1900 = days_since_1_jan_1900(date_of_issue)?;
    let date_of_expiration = chrono::NaiveDate::from_ymd_opt(2030, 02, 14).unwrap();
    let date_of_expiration_since_1900 = days_since_1_jan_1900(date_of_expiration)?;

    let claims: [ClaimData; 10] = [
        RevocationClaim::from(Uuid::new_v4().to_string()).into(),
        HashedClaim::from("F00000217").into(),
        HashedClaim::from("Alice Verifiable").into(),
        HashedClaim::from("USA").into(),
        NumberClaim::from(dob_since_1900).into(),
        HashedClaim::from("F").into(),
        HashedClaim::from("St. Paul, MN").into(),
        NumberClaim::from(date_of_issue_since_1900).into(),
        NumberClaim::from(date_of_expiration_since_1900).into(),
        HashedClaim::from("US DoS").into(),
    ];

    let mut dos = dos_wallet.get(&DOS_DID.to_string()).unwrap().to_owned();
    let vc_passport = dos.sign_credential(&claims)?;
    Ok(vc_passport)
}

fn request_social_security_credential<S: ShortGroupSignatureScheme>(
    ssa_wallet: HashMap<String, Issuer<S>>,
) -> CredxResult<CredentialBundle<S>> {
    let claims: [ClaimData; 3] = [
        RevocationClaim::from(Uuid::new_v4().to_string()).into(),
        HashedClaim::from("123-456-789").into(),
        HashedClaim::from("Alice Verifiable").into(),
    ];

    let mut ssa = ssa_wallet.get(&SSA_DID.to_string()).unwrap().to_owned();
    let vc_soc_sec = ssa.sign_credential(&claims)?;

    Ok(vc_soc_sec)
}

fn days_since_1_jan_1900(date: NaiveDate) -> CredxResult<i64> {
    let base_date = chrono::NaiveDate::from_ymd_opt(1900, 01, 01).unwrap();
    let days_since_base = (date - base_date).num_days();
    Ok(days_since_base)
}
