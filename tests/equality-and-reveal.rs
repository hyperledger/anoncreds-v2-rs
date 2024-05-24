#[cfg(test)]
mod reveal_and_equality_tests {
    use credx::claim::ClaimData;
    use credx::claim::{ClaimType, ClaimValidator, HashedClaim, RevocationClaim};
    use credx::credential::{ClaimSchema, CredentialSchema};
    use credx::error::Error;
    use credx::issuer::Issuer;
    use credx::prelude::IssuerPublic;
    use credx::presentation::{Presentation, PresentationSchema};
    use credx::statement::{EqualityStatement, SignatureStatement};
    use credx::{random_string, CredxResult};
    use indexmap::{indexmap, IndexMap};
    use lazy_static::lazy_static;
    use maplit::btreeset;
    use rand::thread_rng;
    use rand_core::RngCore;
    use std::collections::BTreeSet;
    use std::fmt::Debug;

    // -------------------------------------------------------------------------
    // Setup some names for readability

    const SSN_IX:  usize = 0;
    const NAME_IX: usize = 1;

    const ID_LBL:   &str = "id";
    const NAME_LBL: &str = "name";
    const SSN_LBL:  &str = "social-security-number";
    const SSN:      &str = "123-12-1234";
    const SS_ID_A:  &str = "SignatureStatement ID A";
    const SS_ID_B:  &str = "SignatureStatement ID B";

    type DisclosureReqs = BTreeSet<String>;

    lazy_static! {
        static ref REV_NONE: DisclosureReqs = btreeset! {};
        static ref REV_SSN:  DisclosureReqs = btreeset! {SSN_LBL.to_string()};
    }

    /* -------------------------------------------------------------------------

    Overview of tests
    -----------------

    The tests exercise various combinations of equality and reveal requirements.

    run_test creates a simple schema with name and social security claims (in
    addition to a revocation claim that is required, but not used or relevant to
    these tests), and creates and Issuer and signs two credentials (using the
    same Issuer) according to provided parameters.  The name of the first is
    always Alice and the name of the second is provided by each test to enable
    testing equal and non-equal examples.

    Test setup
    ----------

    Each test specifies:

    - the name for the second credential (the name for the first is always Alice)
    - a set of attributes to reveal from the first credential (REV_NONE requests
      no attributes to be revealed, and REV_SSN) requests the
      social-security-number attribute to be revealed)
    - similarly for attributes to be revealed for the second credential
    - an optional index for attributes to be subject to equality constraints

    Expected outcome
    ----------------

    Each test specifies one of

    - Expected success (via validate_disclosures), with a set of attribute
      values expected to be revealed

    - Expected failure (via assert_matches_error), with an Error specifying a
      pattern for expected failure. For example, an error matches
      Error::InvalidClaimData("XYZ") if it is an Error::InvalidClaimData with a
      string containing XYZ.

    ---------------------------------------------------------------------------- */
    // Tests

    // Request: reveal first SSN
    // Expected: verification succeeds, first SSN revealed
    #[test]
    fn t00_reveal_ssn_a_no_equality() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "_", &REV_SSN, &REV_NONE, None);
        validate_disclosures(r, &REV_SSN, &REV_NONE)
    }

    // Request: reveal first SSN, non-equal names equal
    // Expected: verification fails due to different names
    #[test]
    fn t01_reveal_ssn_a_eq_names_unequal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "Bob", &REV_SSN, &REV_NONE, Some(NAME_IX));
        assert_matches_error(
            r,
            Error::InvalidClaimData("equality statement - claims are not all the same"),
        );
    }

    // Request: reveal no attributes, equal names equal
    // Expected: verification succeeds, no attributes revealed
    #[test]
    fn t02_no_reveal_eq_names_equal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "Alice", &REV_NONE, &REV_NONE, Some(NAME_IX));
        validate_disclosures(r, &REV_NONE, &REV_NONE)
    }

    // Request: reveal first SSN, equal names equal
    // Expected: verification succeeds, first SSN revealed
    #[test]
    fn t03_reveal_ssn_a_eq_names_equal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "Alice", &REV_SSN, &REV_NONE, Some(NAME_IX));
        validate_disclosures(r, &REV_SSN, &REV_NONE)
    }

    // Request: reveal second SSN, equal SSNs equal
    // Expected: EITHER verification succeeds and second SSN revealed
    //           OR     presentation creation fails with informative error
    //                  message that it does not make sense to request equality
    //                  of revealed attributes
    #[test]
    // NOTE: the expected outcome expressed below is that verificaton succeeds
    // and NO attributes are revealed, and the test is annotated with
    // should_panic.  Thus, this test failing indicates that verification
    // succeeded and no attributes were revealed, which is not correct behaviour
    // according to either of the alternative expected scenarios.
    #[should_panic]
    fn t04_reveal_ssn_b_eq_ssns_equal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "_", &REV_NONE, &REV_SSN, Some(SSN_IX));
        validate_disclosures(r, &REV_NONE, &REV_NONE)
    }

    // Request: reveal first SSN, equal SSNs equal
    // Expected: verification fails with informative error
    #[test]
    fn t05_reveal_ssn_a_eq_ssns_equal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "_", &REV_SSN, &REV_NONE, Some(SSN_IX));
        assert_matches_error(
            r,
            Error::InvalidClaimData("revealed claim cannot be used with equality proof"),
        );
    }

    // Request: reveal second SSN, equal SSNs equal
    // Expected: verification fails with informative error
    #[test]
    fn t06_reveal_ssn_b_eq_ssns_equal() {
        let (isspub, iss) = setup_issuer();
        let r = run_test(&isspub, iss, "_", &REV_NONE, &REV_SSN, Some(SSN_IX));
        assert_matches_error(
            r,
            Error::InvalidClaimData("revealed claim cannot be used with equality proof"),
        );
    }

    // -------------------------------------------------------------------------
    // Test setup

    type Disclosures = IndexMap<String, IndexMap<String, ClaimData>>;

    fn run_test(
        issuer_public:  &IssuerPublic,
        mut issuer:     Issuer,
        name_b:         &str,
        reveal_a:       &DisclosureReqs,
        reveal_b:       &DisclosureReqs,
        equality_index: Option<usize>,
    ) -> CredxResult<Disclosures> {
        const CRED_ID_A: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
        let credential_a = issuer.sign_credential(&[
            HashedClaim::from(SSN.to_string()).into(),
            HashedClaim::from("Alice").into(),
            RevocationClaim::from(CRED_ID_A).into(),
        ])?;

        const CRED_ID_B: &str = "12345678-6eda-45fb-a709-d22ebb5ec8a5";
        let credential_b = issuer.sign_credential(&[
            HashedClaim::from(SSN.to_string()).into(),
            HashedClaim::from(name_b).into(),
            RevocationClaim::from(CRED_ID_B).into(),
        ])?;

        let sig_st_a = SignatureStatement {
            disclosed: reveal_a.clone(),
            id: SS_ID_A.to_string(),
            issuer: issuer_public.clone(),
        };

        let sig_st_b = SignatureStatement {
            disclosed: reveal_b.clone(),
            id: SS_ID_B.to_string(),
            issuer: issuer_public.clone(),
        };

        let mut nonce = [0u8; 16];
        thread_rng().fill_bytes(&mut nonce);

        let credentials = indexmap! {
            sig_st_a.id.clone() => credential_a.credential.into(),
            sig_st_b.id.clone() => credential_b.credential.into() };

        let presentation_schema: PresentationSchema = match equality_index {
            None => PresentationSchema::new(&[sig_st_a.into(), sig_st_b.into()]),
            Some(i) => {
                let eq_st = EqualityStatement {
                    id: random_string(16, rand::thread_rng()),
                    ref_id_claim_index: indexmap! {
                        sig_st_a.id.clone() => i,
                        sig_st_b.id.clone() => i },
                };
                PresentationSchema::new(&[sig_st_a.into(), sig_st_b.into(), eq_st.into()])
            }
        };

        let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
        presentation.verify(&presentation_schema, &nonce)?;
        Ok(presentation.disclosed_messages)
    }

    fn setup_issuer() -> (IssuerPublic, Issuer) {
        const LABEL: &str = "Test Schema";
        const DESCRIPTION: &str = "This is a test presentation schema";

        let schema_claims = [
            ClaimSchema {
                claim_type: ClaimType::Hashed,
                label: SSN_LBL.to_string(),
                print_friendly: true,
                validators: vec![ClaimValidator::Length {
                    min: Some(3),
                    max: Some(u8::MAX as usize),
                }],
            },
            ClaimSchema {
                claim_type: ClaimType::Hashed,
                label: NAME_LBL.to_string(),
                print_friendly: true,
                validators: vec![ClaimValidator::Length {
                    min: None,
                    max: Some(u8::MAX as usize),
                }],
            },
            ClaimSchema {
                claim_type: ClaimType::Revocation,
                label: ID_LBL.to_string(),
                print_friendly: false,
                validators: vec![],
            },
        ];

        let cred_schema =
            CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims).unwrap();
        Issuer::new(&cred_schema)
    }

    // -------------------------------------------------------------------------
    // Test-specific test utilities

    fn validate_disclosure(d: &Disclosures, id: &str, req: &DisclosureReqs) {
        match d.get(id) {
            None => panic!("No disclosures for {:?} in {:?}", id, d),
            Some(disclosures_for_id) => {
                // First check that we got the requested number of disclosures
                assert_eq!(req.len(), disclosures_for_id.len(),
                         "number of disclosures expected from {:?} does not equal number received in {:?}",
                         d, disclosures_for_id);
                // Then validate the disclosures received.
                // NOTE: this is not very general, as it assumes req contains at most one value, which is
                // SSN_LBL ("social-security-number") if it exists, and that the expected value is SSN
                let _: Vec<_> = req
                    .iter()
                    .map(|k| {
                        assert_eq!(*k, SSN_LBL.to_string());
                        match disclosures_for_id.get(k) {
                            None => panic!(
                                "Expected disclosure for {:?} not found for {:?} in {:?}",
                                k, id, d
                            ),
                            Some(ClaimData::Hashed(v)) => {
                                assert_eq!(HashedClaim::from(SSN.to_string()), *v)
                            }
                            Some(cd) => panic!("Expected HashedClaim, got {:?}", cd),
                        }
                    })
                    .collect();
            }
        }
    }

    fn validate_disclosures(
        r:     Result<Disclosures, Error>,
        req_a: &DisclosureReqs,
        req_b: &DisclosureReqs,
    ) {
        match &r {
            Err(e) => panic!(
                "Expected successful verification, but received error: {:?}",
                e
            ),
            Ok(d) => {
                validate_disclosure(d, SS_ID_A, req_a);
                validate_disclosure(d, SS_ID_B, req_b);
            }
        }
    }

    // -------------------------------------------------------------------------
    // General test utilities
    // These utilities could be moved somewhere more general for use in other
    // tests
    macro_rules! match_err_with_one_string {
        ($constr:path, $s:expr, $expected:expr) => {
            match $expected {
                $constr(exp_str) => assert!(
                    $s.contains(exp_str),
                    "error {:?} does not match expected {:?}",
                    $constr($s),
                    $expected
                ),
                _ => panic!(
                    "error {:?} does not match expected {:?}",
                    $constr($s),
                    $expected
                ),
            }
        };
    }

    fn assert_matches_error_detail(e: Error, expected: Error) {
        match e {
            Error::InvalidClaimData(s) => {
                match_err_with_one_string!(Error::InvalidClaimData, s, expected)
            }
            Error::General(s) => match_err_with_one_string!(Error::General, s, expected),
            err => {
                if err != expected {
                    panic!("error {:?} does not match expected {:?}", err, expected)
                }
            }
        }
    }

    fn assert_matches_error<R: Debug>(r: Result<R, Error>, expected: Error) {
        match r {
            Ok(_) => assert!(
                r.is_err(),
                "succeeded but expected error matching {:?}",
                expected
            ),
            Err(e) => assert_matches_error_detail(e, expected),
        }
    }
}
