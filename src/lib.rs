//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Claim related methods
pub mod claim;
/// Credential related methods
pub mod credential;
/// Presentation related methods
pub mod presentation;
