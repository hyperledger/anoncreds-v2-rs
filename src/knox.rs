#![allow(clippy::all)]
/// Accumulator methods
pub mod accumulator;
/// ECC group operations
pub mod ecc_group;
/// Pointcheval Sanders signatures
pub mod ps;
/// Operations for short group signatures
pub mod short_group_sig_core;

use blsful::*;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};

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
    ) -> (PublicKey<Bls12381G1Impl>, SecretKey<Bls12381G1Impl>) {
        let sk = Bls12381G1::random_secret_key(rng);
        (sk.public_key(), sk)
    }

    /// New BLS Keys w/G2 public keys
    pub fn new_bls381g2_keys(
        rng: impl RngCore + CryptoRng,
    ) -> (PublicKey<Bls12381G2Impl>, SecretKey<Bls12381G2Impl>) {
        let sk = Bls12381G2::random_secret_key(rng);
        (sk.public_key(), sk)
    }
}
