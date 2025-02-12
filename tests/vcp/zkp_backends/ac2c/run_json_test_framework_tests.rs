#![allow(unused_imports)]
// ------------------------------------------------------------------------------

mod tests {
    mod ps {
        use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS;

        generate_tests_from_json::map_test_over_dir! {
            CRYPTO_INTERFACE_AC2C_PS,
            "./tests/data/JSON/TestSequences/TestingFramework",
            ""
        }
    }

    mod bbs {
        use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS;

        generate_tests_from_json::map_test_over_dir! {
            CRYPTO_INTERFACE_AC2C_BBS,
            "./tests/data/JSON/TestSequences/TestingFramework",
            ""
        }
    }
}
