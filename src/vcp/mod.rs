#![allow(missing_docs)]
#![allow(unused)]
// ------------------------------------------------------------------------------
use crate::prelude;
// ------------------------------------------------------------------------------
use serde_json;
use std::backtrace::Backtrace;
use std::fmt::Debug;
// ------------------------------------------------------------------------------

pub mod api_utils;
pub mod r#impl;
pub mod interfaces;
pub use interfaces::*;
pub mod api;

pub type VCPResult<T> = Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    B64DecodeError(base64::DecodeError),
    B64DecodeSliceError(base64::DecodeSliceError),
    CredxError(prelude::Error),
    FileError(String),
    FromUtf8Error(std::string::FromUtf8Error),
    General(String),
    SerdeCborError(SerdeCborError),
    SerdeError(SerdeJsonError),
    UnexpectedError(UnexpectedError),
    Utf8Error(std::str::Utf8Error),
}

#[derive(Debug)]
pub struct SerdeJsonError(serde_json::Error);

impl PartialEq for SerdeJsonError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

#[derive(Debug)]
pub struct SerdeCborError(serde_cbor::Error);

impl PartialEq for SerdeCborError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

#[derive(Debug)]
pub struct UnexpectedError {
    pub reason    : String,
    pub backtrace : Backtrace,
}

impl PartialEq for UnexpectedError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

/// Enable a variant of is_err() that succeeds only if the result is an
/// error containing a specified string
pub trait ResultExt<T, E> {
    fn is_err_containing(&self, substring: &str) -> bool;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: Debug,
{
    fn is_err_containing(&self, substring: &str) -> bool {
        if let Err(err) = self {
            format!("{:?}",err).contains(substring)
        } else {
            false
        }
    }
}

#[macro_export]
macro_rules! check_errors_in {
    ($res:expr, $($val:expr),*) => {
        $(
            assert!($res.is_err_containing($val));
        )*
    }
}

