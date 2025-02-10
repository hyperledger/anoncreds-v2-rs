use credx::vcp::api_utils::implement_platform_api_using;
use credx::vcp::r#impl::zkp_backends::ac2c::crypto_interface_ac2c::CRYPTO_INTERFACE_AC2C;
use crate::vcp::test_framework::run_test_from_json_file;

pub fn run_json_test_ac2c(file_path: &str) {
    if let Err(e) =
        run_test_from_json_file(&implement_platform_api_using(CRYPTO_INTERFACE_AC2C.to_owned()),
                                file_path.to_string())
    {
        panic!("run_json_test_ac2c failed with {:?}", e)
    }
}
