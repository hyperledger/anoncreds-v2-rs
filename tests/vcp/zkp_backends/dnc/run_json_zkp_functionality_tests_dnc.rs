// ------------------------------------------------------------------------------
use crate::vcp::zkp_backends::dnc::json_test_runner_dnc::run_json_test_dnc;
// ------------------------------------------------------------------------------
// Note: the directory path must be given statically, as it is read directly
// at compile-time and not evaluated
// (so, don't try to define a const for "./tests/data/JSON/TestSequences" somewhere).
generate_tests_from_json::map_test_over_dir! {
    run_json_test_dnc,
    "./tests/data/JSON/TestSequences/LicenseSubscription",
    "./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/DNC.json"
}

