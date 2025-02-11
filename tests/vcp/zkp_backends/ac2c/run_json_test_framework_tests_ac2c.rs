#![allow(unused_imports)]
// ------------------------------------------------------------------------------
use credx::vcp::*;
use credx::vcp::VCPResult;
// ------------------------------------------------------------------------------
use crate::vcp::data_for_tests as td;
use crate::vcp::test_framework as tf;
// ------------------------------------------------------------------------------

// TODO: generalise to include testing with provided CRYPTO_INTERFACE
mod tests {
    use credx::vcp::api_utils::implement_platform_api_using;
    use crate::vcp::test_framework as tf;
    use crate::vcp::zkp_backends::ac2c::json_test_runner_ac2c::run_json_test_ac2c;
    use generate_tests_from_json::map_test_over_dir;

    generate_tests_from_json::map_test_over_dir! {
        run_json_test_ac2c,
        "./tests/data/JSON/TestSequences/TestingFramework",
        ""
    }
}
