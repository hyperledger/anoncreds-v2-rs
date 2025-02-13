// ------------------------------------------------------------------------------
use credx::vcp::api_utils::implement_platform_api_using;
use credx::vcp::r#impl::zkp_backends::dnc::crypto_interface_dnc::CRYPTO_INTERFACE_DNC;
// ------------------------------------------------------------------------------
use crate::vcp::test_framework::run_test_from_json_file;
// ------------------------------------------------------------------------------

pub fn run_json_test_dnc(file_path: &str) {
    if let Err(e) =
        run_test_from_json_file(&implement_platform_api_using(CRYPTO_INTERFACE_DNC.to_owned()),
                                file_path.to_string())
    {
        panic!("run_json_test_dnc failed with {:?}", e)
    }
}
