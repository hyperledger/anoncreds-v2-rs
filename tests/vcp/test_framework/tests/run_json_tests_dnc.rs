#![allow(unused_imports)]
// ------------------------------------------------------------------------------
use credx::vcp::*;
use credx::vcp::VCPResult;
// ------------------------------------------------------------------------------
use crate::vcp::data_for_tests as td;
use crate::vcp::test_framework as tf;
// ------------------------------------------------------------------------------

mod tests {
    use credx::vcp::api_utils::implement_platform_api_using;
    use crate::vcp::json_test_runner_dnc::run_json_test_dnc;
    use crate::vcp::test_framework as tf;
    use generate_tests_from_json::map_test_over_dir;

    generate_tests_from_json::map_test_over_dir! {
        run_json_test_dnc,
        "./tests/data/JSON/TestSequences/TestingFramework",
        ""
    }
}
