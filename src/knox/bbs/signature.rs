use super::{MessageGenerators, PublicKey, SecretKey};
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::Signature as SignatureTrait;
use crate::CredxResult;
use blsful::inner_types::{
    multi_miller_loop, Curve, Field, G1Projective, G2Affine, G2Prepared, G2Projective, Group,
    MillerLoopResult, PrimeField, Scalar,
};
use elliptic_curve::{group::prime::PrimeCurveAffine, hash2curve::ExpandMsgXmd};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::num::NonZeroUsize;
use subtle::{Choice, ConditionallySelectable, CtOption};

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
        let msg_count = NonZeroUsize::new(msgs.len()).ok_or(Error::General("No messages"))?;
        let pub_key = PublicKey::from(sk);
        let msg_generators = MessageGenerators::with_api_id(msg_count, Some(&pub_key.to_bytes()));
        let domain = domain_calculation(&pub_key, &msg_generators);
        let mut e_input_bytes = Vec::with_capacity(32 * msgs.len() + 2);
        e_input_bytes.extend_from_slice(&sk.to_bytes());
        for msg in msgs {
            e_input_bytes.extend_from_slice(msg.to_repr().as_ref());
        }
        e_input_bytes.extend_from_slice(domain.to_repr().as_ref());
        let e = Scalar::hash::<ExpandMsgXmd<Sha256>>(&e_input_bytes, DST);

        let ske = (sk.0 + e).invert();
        if ske.is_none().into() {
            // only fails if sk + e is zero
            return Err(Error::General("Invalid signature"));
        }

        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&msg_generators.0, msgs);

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
        if msgs.is_empty() {
            return Choice::from(0);
        }
        let msg_count = NonZeroUsize::new(msgs.len()).expect("at least 1 message");
        let msg_generators = MessageGenerators::with_api_id(msg_count, Some(&pk.to_bytes()));

        let b = G1Projective::GENERATOR + G1Projective::sum_of_products(&msg_generators.0, msgs);
        let lhs_pk = G2Projective::GENERATOR * self.e + pk.0;

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
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[..G1Projective::COMPRESSED_BYTES].copy_from_slice(&self.a.to_compressed());
        bytes[G1Projective::COMPRESSED_BYTES..].copy_from_slice(&self.e.to_be_bytes());
        bytes
    }

    /// Convert bytes to a signature
    pub fn from_bytes(bytes: &[u8]) -> CtOption<Self> {
        let a_bytes = (&bytes[..G1Projective::COMPRESSED_BYTES])
            .try_into()
            .expect("Invalid length");
        let a = G1Projective::from_compressed(&a_bytes);
        let e_bytes = (&bytes[G1Projective::COMPRESSED_BYTES..])
            .try_into()
            .expect("Invalid length");
        let e = Scalar::from_be_bytes(&e_bytes);

        a.and_then(|a| e.map(|e| Self { a, e }))
    }
}

fn domain_calculation(pk: &PublicKey, msg_generators: &MessageGenerators) -> Scalar {
    let mut bytes = Vec::with_capacity(8 + 96 + 48 * msg_generators.0.len());
    bytes.extend_from_slice(&pk.to_bytes());
    bytes.extend_from_slice(&((msg_generators.0.len() + 1) as u64).to_be_bytes());
    bytes.extend_from_slice(&G1Projective::GENERATOR.to_compressed());
    for gen in &msg_generators.0 {
        bytes.extend_from_slice(&gen.to_compressed());
    }
    bytes.extend_from_slice(&[0u8; 8]);
    Scalar::hash::<ExpandMsgXmd<Sha256>>(&bytes, DST)
}
