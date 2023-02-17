use super::{PublicKey, SecretKey};
use signature_bls::bls12_381_plus::{
    multi_miller_loop, ExpandMsgXof, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
    Scalar,
};
use core::convert::TryFrom;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use ff::PrimeField;
use group::{Curve, Group};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, CtOption};
use crate::CredxResult;
use crate::error::Error;

/// A Pointcheval Saunders signature
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub(crate) sigma_1: G1Projective,
    pub(crate) sigma_2: G1Projective,
    pub(crate) m_tick: Scalar,
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            sigma_1: G1Projective::IDENTITY,
            sigma_2: G1Projective::IDENTITY,
            m_tick: Scalar::ZERO,
        }
    }
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let sigma_1 = G1Projective::conditional_select(&a.sigma_1, &b.sigma_1, choice);
        let sigma_2 = G1Projective::conditional_select(&a.sigma_2, &b.sigma_2, choice);
        let m_tick = Scalar::conditional_select(&a.m_tick, &b.m_tick, choice);
        Self {
            sigma_1,
            sigma_2,
            m_tick,
        }
    }
}

impl Signature {
    /// The size in bytes of the signature
    pub const BYTES: usize = 128;

    const DST: &'static [u8] = b"PS_SIG_BLS12381G1_XMD:BLAKE2B_SSWU_RO_";

    /// Generate a new signature where all messages are known to the signer
    pub fn new<M>(sk: &SecretKey, msgs: M) -> CredxResult<Self>
    where
        M: AsRef<[Scalar]>,
    {
        let msgs = msgs.as_ref();
        if sk.is_invalid() {
            return Err(Error::General("Key generation error"));
        }
        if sk.y.len() < msgs.len() {
            return Err(Error::General("Key generation error"));
        }

        let m_tick = Self::compute_m_tick(msgs);
        let sigma_1 =
            G1Projective::hash::<ExpandMsgXof<sha3::Shake256>>(&m_tick.to_bytes()[..], Self::DST);
        let mut exp = sk.x + sk.w * m_tick;

        for (ski, m) in msgs.iter().zip(sk.y.iter()) {
            exp += *ski * *m;
        }
        let sigma_2 = sigma_1 * exp;
        Ok(Self {
            sigma_1,
            sigma_2,
            m_tick,
        })
    }

    /// Verify a signature
    pub fn verify<M>(&self, pk: &PublicKey, msgs: M) -> Choice
    where
        M: AsRef<[Scalar]>,
    {
        let msgs = msgs.as_ref();
        if pk.y.len() < msgs.len() {
            return Choice::from(0);
        }
        if pk.is_invalid().unwrap_u8() == 1 {
            return Choice::from(0);
        }
        if (self.sigma_1.is_identity() | self.sigma_2.is_identity()).unwrap_u8() == 1u8 {
            return Choice::from(0);
        }

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        points.push(pk.x);
        scalars.push(Scalar::ONE);

        points.push(pk.w);
        scalars.push(self.m_tick);

        for (i, m) in msgs.iter().enumerate() {
            points.push(pk.y[i]);
            scalars.push(*m);
        }

        // Y_m = X_tilde * W_tilde^m' * Y_tilde[1]^m_1 * Y_tilde[2]^m_2 * ...Y_tilde[i]^m_i
        let y_m = G2Projective::sum_of_products_in_place(points.as_ref(), scalars.as_mut());

        // e(sigma_1, Y_m) == e(sigma_2, G2) or
        // e(sigma_1 + sigma_2, Y_m - G2) == GT_1
        multi_miller_loop(&[
            (
                &self.sigma_1.to_affine(),
                &G2Prepared::from(y_m.to_affine()),
            ),
            (
                &self.sigma_2.to_affine(),
                &G2Prepared::from(-G2Affine::generator()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Get the byte representation of this signature
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[..48].copy_from_slice(&self.sigma_1.to_affine().to_compressed());
        bytes[48..96].copy_from_slice(&self.sigma_2.to_affine().to_compressed());
        bytes[96..].copy_from_slice(&self.m_tick.to_bytes());
        bytes
    }

    /// Convert a byte sequence into a signature
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let s1 = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[..48]).unwrap())
            .map(G1Projective::from);
        let s2 = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[48..96]).unwrap())
            .map(G1Projective::from);
        let m = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[96..]).unwrap());

        s1.and_then(|sigma_1| {
            s2.and_then(|sigma_2| {
                m.and_then(|m_tick| {
                    CtOption::new(
                        Signature {
                            sigma_1,
                            sigma_2,
                            m_tick,
                        },
                        Choice::from(1),
                    )
                })
            })
        })
    }

    pub(crate) fn compute_m_tick(msgs: &[Scalar]) -> Scalar {
        let mut hasher = sha3::Shake256::default();
        for m in msgs {
            hasher.update(m.to_repr().as_ref());
        }

        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 64];
        reader.read(&mut out);
        let a = Scalar::from_bytes_wide(&out);
        reader.read(&mut out);
        Scalar::from_bytes_wide(&out) + a
    }
}
