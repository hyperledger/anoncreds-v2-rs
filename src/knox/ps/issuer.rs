use super::{BlindSignature, BlindSignatureContext, PublicKey, SecretKey, Signature};
use crate::error::Error;
use crate::CredxResult;
use blsful::inner_types::{ff::Field, Scalar};
use rand_core::{CryptoRng, RngCore};

/// This struct represents an Issuer of signatures or Signer.
/// Provided are methods for signing regularly where all messages are known
/// and 2PC where some are only known to the holder and a blind signature
/// is created.
///
/// The issuer generates keys and uses those to sign
/// credentials. There are two types of public keys and a secret key.
/// `PublicKey` is used for verification and `MessageGenerators` are purely
/// for creating blind signatures.
pub struct Issuer;

impl Issuer {
    /// Create a keypair capable of signing up to `count` messages
    pub fn new_keys(
        count: usize,
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(PublicKey, SecretKey)> {
        SecretKey::random(count, rng)
            .map(|sk| {
                let pk = PublicKey::from(&sk);
                (pk, sk)
            })
            .ok_or(Error::General("invalid key generation"))
    }

    /// Create a signature with no hidden messages
    pub fn sign<M>(sk: &SecretKey, msgs: M) -> CredxResult<Signature>
    where
        M: AsRef<[Scalar]>,
    {
        Signature::new(sk, msgs)
    }

    /// Verify a proof of committed messages and generate a blind signature
    pub fn blind_sign(
        ctx: &BlindSignatureContext,
        sk: &SecretKey,
        msgs: &[(usize, Scalar)],
        nonce: Scalar,
    ) -> CredxResult<BlindSignature> {
        // Known messages are less than total, max at 128
        let tv1 = msgs.iter().map(|(i, _)| *i).collect::<Vec<usize>>();
        if ctx.verify(tv1.as_ref(), sk, nonce)? {
            BlindSignature::new(ctx.commitment, sk, msgs)
        } else {
            Err(Error::General("BlindSignatureError"))
        }
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce(rng: impl RngCore + CryptoRng) -> Scalar {
        Scalar::random(rng)
    }
}
