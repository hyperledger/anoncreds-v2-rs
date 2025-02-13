
mod ps {
    use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS;
    // Note: the directory path must be given statically, as it is read directly
    // at compile-time and not evaluated
    // (so, don't try to define a const for "./tests/data/JSON/TestSequences" somewhere).
    generate_tests_from_json::map_test_over_dir! {
        CRYPTO_INTERFACE_AC2C_PS,
        "./tests/data/JSON/TestSequences/LicenseSubscription",
        "./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json"
    }
}

mod bbs {
    use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS;
    generate_tests_from_json::map_test_over_dir! {
        CRYPTO_INTERFACE_AC2C_BBS,
        "./tests/data/JSON/TestSequences/LicenseSubscription",
        "./tests/data/JSON/TestSequences/LicenseSubscription/LibrarySpecificOverrides/AC2C.json"
    }
}
