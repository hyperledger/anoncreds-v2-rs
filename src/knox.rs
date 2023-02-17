/// Accumulator methods
pub mod accumulator;
/// ECC group operations
pub mod ecc_group;
/// Pointcheval Sanders signatures
pub mod ps;
/// Operations for short group signatures
pub mod short_group_sig_core;

use rand_core::{RngCore, CryptoRng};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use signature_bls::*;

/// General purpose crypto operations
pub struct Knox {}

impl Knox {
    /// Compute a variable length hash
    pub fn xof_digest<X: Default + ExtendableOutput + Update>(input: &[u8], output: &mut [u8]) {
        let mut r = X::default().chain(input.as_ref()).finalize_xof();
        r.read(output);
    }

    /// New BLS Keys w/G1 public keys
    pub fn new_bls381g1_keys(
        rng: impl RngCore + CryptoRng,
    ) -> (PublicKeyVt, SecretKey) {
        let sk = SecretKey::random(rng).unwrap();
        (PublicKeyVt::from(&sk), sk)
    }

    /// New BLS Keys w/G2 public keys
    pub fn new_bls381g2_keys(
        rng: impl RngCore + CryptoRng,
    ) -> (PublicKey, SecretKey) {
        let sk = SecretKey::random(rng).unwrap();
        (PublicKey::from(&sk), sk)
    }
}