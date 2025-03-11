// ------------------------------------------------------------------------------
use credx::vcp::api::PlatformApi;
use credx::vcp::api_utils::implement_platform_api_using;
use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS;
use credx::vcp::zkp_backends::ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS;
use credx::vcp::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;
// ------------------------------------------------------------------------------
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_okapi::okapi::schemars;
// ------------------------------------------------------------------------------

use crate::query_param_guards::*;

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
pub struct Error {
    pub reason   : String,
    pub location : String,
}

// for unmarshalling post bodies
pub type DataResult<'a, T> =
    std::result::Result<rocket::serde::json::Json<T>,
                        rocket::serde::json::Error<'a>>;

pub fn vcpErr<A>(
    e   : credx::vcp::Error,
    msg : &str
) -> Result<A, (Status, Json<Error>)>
{
    err(format!("{:?}", e), msg)
}

pub fn err<A>(
    reason   : String,
    location : &str
) -> Result<A, (Status, Json<Error>)>
{
    Err((Status::BadRequest,
         Json(Error { reason,
                      location : location.to_string() })))
}

pub fn getSeedAndApi(
    x        : RngSeedAndZkpLibQueryParams,
    location : &str
) -> Result<(u64, PlatformApi), (Status, Json<Error>)> {
    Ok((getRngSeed(x.rngSeed), getApi(x.zkpLib, location)?))
}


pub fn getRngSeed(x : Option<u64>) -> u64
{
    x.unwrap_or(0)
}

pub fn getApiFromQP(
    x        : ZkpLibQueryParam,
    location : &str,
 ) -> Result<PlatformApi, (Status, Json<Error>)>
{
    getApi(Some(x.zkpLib), location)
}

fn getApi(
    x        : Option<String>,
    location : &str
) -> Result<PlatformApi, (Status, Json<Error>)> {
    match x
    {
        Some(x) => {
            match x.to_lowercase().as_str()
            {
                "ac2c_bbs" => {
                    let AC2C = &implement_platform_api_using(&CRYPTO_INTERFACE_AC2C_BBS);
                    Ok(AC2C.clone())
                },
                "ac2c_ps" => {
                    let AC2C = &implement_platform_api_using(&CRYPTO_INTERFACE_AC2C_PS);
                    Ok(AC2C.clone())
                },
                "dnc"  => {
                    let DNC  = &implement_platform_api_using(&CRYPTO_INTERFACE_DNC);
                    Ok(DNC.clone())
                },
                e      => err(format!("unknown 'zkp' query parameter '{e}'"), location)
            }
        }
        None => {
            err("'zkp' query parameter missing".to_string(), location)
        },
    }
}

