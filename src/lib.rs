//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

#[macro_use]
extern crate maplit;

use rand_core::{CryptoRng, RngCore};

/// The result type for this crate
pub type CredxResult<T> = Result<T, error::Error>;

/// Generate a hex random string with `length` bytes.
pub(crate) fn random_string(length: usize, mut rng: impl RngCore + CryptoRng) -> String {
    let mut buffer = vec![0u8; length];
    rng.fill_bytes(&mut buffer);
    hex::encode(&buffer)
}

/// Claim related methods
pub mod claim;
/// Credential related methods
pub mod credential;
/// Errors produced by this library
pub mod error;
/// Issuer related methods
pub mod issuer;
/// Presentation related methods
pub mod presentation;
/// Revocation registry methods
pub mod revocation_registry;
/// Presentation statements
pub mod statement;
/// Presentation verifiers
mod verifier;

mod utils;

extern crate core;
/// Re-export yeti
pub extern crate yeti;
