use blsful::inner_types::*;
use credx::claim::{ClaimType, HashedClaim, NumberClaim, RevocationClaim};
use credx::credential::{ClaimSchema, CredentialSchema};
use credx::issuer::Issuer;
use credx::knox::bbs::BbsScheme;
use credx::knox::ps::PsScheme;
use credx::presentation::{Presentation, PresentationSchema};
use credx::statement::{CommitmentStatement, RangeStatement, SignatureStatement};
use credx::{random_string, CredxResult};
use indexmap::indexmap;
use maplit::btreeset;
use rand::{thread_rng, RngCore};

macro_rules! range_test_with {
    ($name: ident, $val:expr, $lower:expr, $upper:expr, $expected_to_fail:expr) => {
        #[test]
        fn $name() -> CredxResult<()> {
            let _ = env_logger::builder().is_test(true).try_init();
            let res = test_range_proof_works($val, $lower, $upper, $expected_to_fail);
            assert!(res.is_ok(), "{:?}", res);
            Ok(())
        }
    };
}

// These tests are expected to pass (expected_to_fail argument is false)
range_test_with!(in_range_from_flow_test, 30303, Some(0), Some(44829), false);
range_test_with!(in_range_min, 0, Some(0), Some(isize::MAX), false);
range_test_with!(
    in_range_max_explicit,
    isize::MAX,
    Some(0),
    Some(isize::MAX),
    false
);
range_test_with!(in_range_max_implicit, isize::MAX, Some(0), None, false);

// These tests are expected to fail (expected_to_fail argument is true)
range_test_with!(out_of_range_below, 0, Some(1), Some(isize::MAX), true);
range_test_with!(out_of_range_above, 1001, Some(0), Some(1000), true);

#[test]
fn test_out_of_range_above() {
    assert!(test_range_proof_works(1000, Some(0), Some(1000), false).is_ok());
}

fn test_range_proof_works(
    val: isize,
    lower: Option<isize>,
    upper: Option<isize>,
    expected_to_fail: bool,
) -> Result<(), String> {
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
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)
        .map_err(|e| format!("unexpected, CredentialSchema::new failed {e:?}"))?;

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    let credential = issuer
        .sign_credential(&[
            RevocationClaim::from(CRED_ID).into(),
            HashedClaim::from("John Doe").into(),
            HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
            NumberClaim::from(val).into(),
        ])
        .map_err(|e| format!("unexpected, sign credential failed {e:?}"))?;

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: random_string(16, rand::thread_rng()),
        issuer: issuer_public.clone(),
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
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower,
        upper,
    };

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into() };
    let presentation_schema =
        PresentationSchema::new(&[sig_st.into(), comm_st.into(), range_st.into()]);
    match Presentation::create(&credentials, &presentation_schema, &nonce) {
        Err(e) => {
            if expected_to_fail {
                Ok(())
            } else {
                Err(format!("create presentation failed: {e:?}"))
            }
        }
        Ok(presentation) => match presentation.verify(&presentation_schema, &nonce) {
            Err(e) => {
                if expected_to_fail {
                    Ok(())
                } else {
                    Err(format!("verify presentation failed: {e:?}"))
                }
            }
            Ok(_) => {
                if expected_to_fail {
                    Err("verification passed, but was expected to fail".to_string())
                } else {
                    Ok(())
                }
            }
        },
    }
}
