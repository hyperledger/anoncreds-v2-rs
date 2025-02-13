#![allow(unused_imports)]
// ------------------------------------------------------------------------------
mod tests {
    use crate::testing_framework_test;
    use credx::vcp::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;
    testing_framework_test! { CRYPTO_INTERFACE_DNC }
}
