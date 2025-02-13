use super::{PublicKey, SecretKey};
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::Signature as SignatureTrait;
use crate::CredxResult;
use blsful::inner_types::{
    multi_miller_loop, Curve, Field, G1Projective, G2Affine, G2Prepared, G2Projective, Group,
    MillerLoopResult, Scalar,
};
use elliptic_curve::{group::prime::PrimeCurveAffine, hash2curve::ExpandMsgXmd};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable};

const DST: &[u8] = b"H2S_";

/// A BBS signature
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
}

impl ConditionallySelectable for Signature {
    fn conditional_select(lhs: &Self, rhs: &Self, choice: Choice) -> Self {
        let a = G1Projective::conditional_select(&lhs.a, &rhs.a, choice);
        let e = Scalar::conditional_select(&lhs.e, &rhs.e, choice);
        Self { a, e }
    }
}

impl SignatureTrait for Signature {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;

    fn create(sk: &Self::SecretKey, msgs: &[Scalar]) -> CredxResult<Self> {
        Self::new(sk, msgs)
    }

    fn verify(&self, pk: &Self::PublicKey, msgs: &[Scalar]) -> CredxResult<()> {
        if self.verify(pk, msgs).into() {
            Ok(())
        } else {
            Err(Error::General("Invalid signature"))
        }
    }
}

impl Signature {
    /// The size in bytes of the signature
    pub const BYTES: usize = 80;

    /// Generate a new signature where all messages are known to the signer
    pub fn new<M>(sk: &SecretKey, msgs: M) -> CredxResult<Self>
    where
        M: AsRef<[Scalar]>,
    {
        if sk.is_invalid() {
            return Err(Error::General("Invalid secret key"));
        }

        let msgs = msgs.as_ref();
        if msgs.len() > sk.max_messages {
            return Err(Error::General("Too many messages"));
        }

        let pub_key = PublicKey::from(sk);
        let domain = domain_calculation(&pub_key);
        let e = compute_e(sk, msgs, domain);

        let ske = (sk.x + e).invert();
        if ske.is_none().into() {
            // only fails if sk + e is zero
            return Err(Error::General("Invalid signature"));
        }

        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&pub_key.y, msgs);

        let a = b * ske.expect("a valid scalar");

        Ok(Self { a, e })
    }

    /// Verify a signature
    pub fn verify<M>(&self, pk: &PublicKey, msgs: M) -> Choice
    where
        M: AsRef<[Scalar]>,
    {
        if (pk.is_invalid() | self.is_invalid()).into() {
            return Choice::from(0);
        }
        let msgs = msgs.as_ref();
        if msgs.is_empty() || msgs.len() > pk.y.len() {
            return Choice::from(0);
        }

        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&pk.y, msgs);
        let lhs_pk = G2Projective::GENERATOR * self.e + pk.w;

        multi_miller_loop(&[
            (&self.a.to_affine(), &G2Prepared::from(lhs_pk.to_affine())),
            (&b.to_affine(), &G2Prepared::from(-G2Affine::generator())),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Check if the signature is invalid
    pub fn is_invalid(&self) -> Choice {
        self.a.is_identity() | self.e.is_zero()
    }

    /// Convert the signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_bare::to_vec(self).expect("to serialize Signature")
    }

    /// Convert bytes to a signature
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_bare::from_slice(bytes).ok()
    }
}

pub(crate) fn compute_e(sk: &SecretKey, msgs: &[Scalar], domain: Scalar) -> Scalar {
    let mut bytes = Vec::with_capacity(32 * msgs.len() + 64);
    bytes.extend_from_slice(&sk.to_bytes());
    for msg in msgs {
        bytes.extend_from_slice(&msg.to_be_bytes());
    }
    bytes.extend_from_slice(&domain.to_be_bytes());
    Scalar::hash::<ExpandMsgXmd<Sha256>>(&bytes, DST)
}

pub(crate) fn domain_calculation(pk: &PublicKey) -> Scalar {
    let mut bytes = Vec::with_capacity(8 + 96 + 48 * pk.y.len());
    bytes.extend_from_slice(&pk.w.to_compressed());
    bytes.extend_from_slice(&((pk.y.len() + 1) as u64).to_be_bytes());
    bytes.extend_from_slice(&G1Projective::GENERATOR.to_compressed());
    for gen in &pk.y {
        bytes.extend_from_slice(&gen.to_compressed());
    }
    bytes.extend_from_slice(&[0u8; 8]);
    Scalar::hash::<ExpandMsgXmd<Sha256>>(&bytes, DST)
}
