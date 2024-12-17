//! A map implementation

use rand_core::{CryptoRng, RngCore};

/// The result type for this crate
pub type CredxResult<T> = Result<T, error::Error>;

/// Generate a hex random string with `length` bytes.
pub fn random_string(length: usize, mut rng: impl RngCore + CryptoRng) -> String {
    let mut buffer = vec![0u8; length];
    rng.fill_bytes(&mut buffer);
    hex::encode(&buffer)
}

pub use indexmap;
pub use regex;

/// The blind credential operations
pub mod blind;
/// Claim related methods
pub mod claim;
/// Credential related methods
pub mod credential;
/// Errors produced by this library
pub mod error;
/// Issuer related methods
pub mod issuer;
/// Internal crypto primitives
pub mod knox;
/// Presentation related methods
pub mod presentation;
/// Revocation registry methods
pub mod revocation_registry;
/// Presentation statements
pub mod statement;
mod utils;
/// Presentation verifiers
mod verifier;

/// One import to rule them all
pub mod prelude {
    use super::*;

    pub use super::CredxResult;
    pub use blind::*;
    pub use claim::*;
    pub use credential::*;
    pub use error::*;
    pub use issuer::*;
    pub use knox::{accumulator::vb20, bbs, ps, Knox};
    pub use presentation::*;
    pub use revocation_registry::*;
    pub use statement::*;

    pub use blsful;
}

mod mapping {
    #![allow(dead_code)]
    #![allow(unused_assignments)]
    pub mod map_credential;
    pub mod map_presentation;
}
