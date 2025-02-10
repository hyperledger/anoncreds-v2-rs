#![allow(unused_imports)]
// ------------------------------------------------------------------------------
use credx::vcp::*;
use credx::vcp::VCPResult;
use credx::vcp::r#impl::zkp_backends::ac2c::crypto_interface_ac2c::CRYPTO_INTERFACE_AC2C;
// ------------------------------------------------------------------------------
use crate::vcp::data_for_tests as td;
use crate::vcp::test_framework as tf;
// ------------------------------------------------------------------------------

mod tests {
    use credx::vcp::api_utils::implement_platform_api_using;
    use crate::vcp::json_test_runner_ac2c::run_json_test_ac2c;
    use crate::vcp::test_framework as tf;
    use generate_tests_from_json::map_test_over_dir;

    generate_tests_from_json::map_test_over_dir! {
        run_json_test_ac2c,
        "./tests/data/JSON/TestSequences/TestingFramework",
        ""
    }
}
