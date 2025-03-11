// ------------------------------------------------------------------------------
use rocket::form::FromForm;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
// ------------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
// ------------------------------------------------------------------------------

/// Query Guard
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, FromForm)]
pub struct RngSeedAndZkpLibQueryParams {
    /// Which ZKP library to use. AC2C_BBS, AC2C_PS or DNC (error if missing).
    pub zkpLib  : Option<String>,
    /// A seed for a random number generator. Defaults to zero if not given.
    pub rngSeed : Option<u64>,
}

/// Query Guard
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, FromForm)]
pub struct ZkpLibQueryParam {
    /// Which ZKP library to use. AC2C_BBS, AC2C_PS or DNC (error if missing).
    pub zkpLib : String,
}

/// Query Guard
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, FromForm)]
pub struct RngSeedQueryParam {
    /// A seed for a random number generator. Defaults to zero if not given.
    pub rngSeed : u64,
}

