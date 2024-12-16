use crate::knox::bbs::{PublicKey, SecretKey, Signature};
use crate::CredxResult;
use blsful::inner_types::Scalar;
use elliptic_curve::Field;
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
    pub fn new_keys(rng: impl RngCore + CryptoRng) -> CredxResult<(PublicKey, SecretKey)> {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        Ok((pk, sk))
    }

    /// Create a signature with no hidden messages
    pub fn sign<M>(sk: &SecretKey, msgs: M) -> CredxResult<Signature>
    where
        M: AsRef<[Scalar]>,
    {
        Signature::new(sk, msgs)
    }

    /// Create a nonce used for the blind signing context
    pub fn generate_signing_nonce(rng: impl RngCore + CryptoRng) -> Scalar {
        Scalar::random(rng)
    }
}
