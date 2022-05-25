//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

extern crate core;

use rand_core::{CryptoRng, RngCore};

/// The result type for this crate
pub type CredxResult<T> = Result<T, error::Error>;

fn random_string(length: usize, mut rng: impl RngCore + CryptoRng) -> String {
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
