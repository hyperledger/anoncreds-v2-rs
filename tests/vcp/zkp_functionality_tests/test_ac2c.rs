// -----------------------------------------------------------------------------
use crate::vcp::zkp_functionality_tests::test_definitions::*;
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
// -----------------------------------------------------------------------------

// TODO: generalise to include testing with provided CRYPTO_INTERFACE
crate::per_crypto_library_test! {
    &credx::vcp::api_utils::implement_platform_api_using(
        credx::vcp::r#impl::zkp_backends::ac2c::crypto_interface_ac2c::CRYPTO_INTERFACE_AC2C_PS.to_owned()),
    &crate::vcp::zkp_functionality_tests::test_ac2c::SPECIFIC_TEST_OUTCOMES
}

lazy_static! {
    static ref SPECIFIC_TEST_OUTCOMES: LibrarySpecificTestHandlers = hashmap! {
        "RANGE_PROOF_IN_RANGE_GENERIC" =>
            TestHandler::NotSoSlow,
        "RANGE_PROOF_OUT_OF_RANGE_SPECIFIC_EXCEPTIONS" =>
            TestHandler::Skip("test has DNC-specific expectations, so AC2C fails"),
        "RANGE_PROOF_OUT_OF_RANGE_CHEATING_PROVER_DNC_SPECIFIC" =>
            TestHandler::Skip("AC2C does not enable cheating prover"),
        "DOES_NOT_EXIST" =>
            TestHandler::Fail("A placeholder to suppress a warning that noone uses Fail, until we do"),
    };
}
