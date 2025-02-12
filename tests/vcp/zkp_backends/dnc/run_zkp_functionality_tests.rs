// -----------------------------------------------------------------------------
use crate::vcp::zkp_functionality_tests::test_definitions::*;
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
// -----------------------------------------------------------------------------

use credx::vcp::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;

crate::per_crypto_library_test! {
    CRYPTO_INTERFACE_DNC,
    &SPECIFIC_TEST_OUTCOMES
}

lazy_static! {
    static ref SPECIFIC_TEST_OUTCOMES: LibrarySpecificTestHandlers = hashmap! { };
}
