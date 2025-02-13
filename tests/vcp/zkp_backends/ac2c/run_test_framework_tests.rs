#![allow(unused_imports)]
// ------------------------------------------------------------------------------
mod tests {
    use crate::testing_framework_test;
    mod ps {
        use super::*;
        use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS;
        testing_framework_test! { CRYPTO_INTERFACE_AC2C_PS }
    }

    mod bbs {
        use super::*;
        use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS;
        testing_framework_test! { CRYPTO_INTERFACE_AC2C_BBS }
    }
}
