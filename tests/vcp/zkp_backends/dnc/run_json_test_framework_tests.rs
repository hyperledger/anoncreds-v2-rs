#![allow(unused_imports)]
// ------------------------------------------------------------------------------

mod tests {
    use credx::vcp::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;

    generate_tests_from_json::map_test_over_dir! {
        CRYPTO_INTERFACE_DNC,
        "./tests/data/JSON/TestSequences/TestingFramework",
        ""
    }
}
