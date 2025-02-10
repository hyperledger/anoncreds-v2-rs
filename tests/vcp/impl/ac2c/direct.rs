// -----------------------------------------------------------------------------
use crate::vcp::r#impl::general::proof_system::utils::{LibrarySpecificTestHandlers, TestHandler};
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
// -----------------------------------------------------------------------------

crate::per_crypto_library_spec! {
    &credx::vcp::api_utils::implement_platform_api_using(credx::vcp::r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C.to_owned()),
    &crate::vcp::r#impl::ac2c::direct::SPECIFIC_TEST_OUTCOMES
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
