// ------------------------------------------------------------------------------
use crate::vcp::{self, Error, SerdeCborError, SerdeJsonError, VCPResult};
// ------------------------------------------------------------------------------
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_cbor::*;
use std::str;
// ------------------------------------------------------------------------------

pub trait VcpTryFrom<T>: Sized {
    fn vcp_try_from(value: T) -> VCPResult<Self>;
}

pub fn to_api<FROM, API: VcpTryFrom<FROM>>(from: FROM) -> VCPResult<API>
{
    API::vcp_try_from(from)
}

pub fn from_api<API, TO: VcpTryFrom<API>>(api: API) -> VCPResult<TO> {
    TO::vcp_try_from(api)
}

// ------------------------------------------------------------------------------

pub fn to_opaque_json<T: Serialize>(t: &T) -> VCPResult<String> {
    let s = serde_json::to_string(t).map_err(|err| Error::SerdeError(SerdeJsonError(err)))?;
    Ok(to_opaque(s))
}

pub fn from_opaque_json<T: for<'de> Deserialize<'de>>(s: &str) -> VCPResult<T> {
    let s = from_opaque(s)?;
    serde_json::from_slice::<T>(s.as_bytes()).map_err(|e| Error::SerdeError(SerdeJsonError(e)))
}

// ------------------------------------------------------------------------------

// TODO: remove these when possible.  These should not be needed, but currently are, due to a
// serialization bug in bulletproofs; see tests/vcp/range_proof_serialization_test.rs
pub fn to_opaque_cbor<T: Serialize>(t: &T) -> VCPResult<String> {
    let s = to_vec(t).map_err(|err| Error::SerdeCborError(SerdeCborError(err)))?;
    Ok(to_opaque(s))
}
pub fn from_opaque_cbor<T: for<'de> Deserialize<'de>>(s: &str) -> VCPResult<T> {
    let v = from_opaque_to_vec(s)?;
    let s = from_slice(&v).map_err(|err| Error::SerdeCborError(SerdeCborError(err)))?;
    Ok(s)
}

// ------------------------------------------------------------------------------

fn to_opaque<S: AsRef<[u8]>>(s: S) -> String {
    BASE64_STANDARD.encode(s)
}

// pub for testing
pub fn from_opaque(s_b64: &str) -> VCPResult<String> {
    let s_bytes = BASE64_STANDARD
        .decode(s_b64)
        .map_err(Error::B64DecodeError)?;
    let s_utf8 = str::from_utf8(&s_bytes)
        .map_err(|err| Error::General(format!("from_opaque_json: {err}")))?;
    Ok(s_utf8.to_string())
}

fn from_opaque_to_vec(s_b64: &str) -> VCPResult<Vec<u8>> {
    let s_bytes = BASE64_STANDARD
        .decode(s_b64)
        .map_err(Error::B64DecodeError)?;
    Ok(s_bytes)
}
