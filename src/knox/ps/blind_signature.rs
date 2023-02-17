use super::{SecretKey, Signature};
use signature_bls::bls12_381_plus::{G1Projective, Scalar};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use serde::{Deserialize, Serialize};
use subtle::CtOption;
use crate::CredxResult;

/// A PS blind signature
/// structurally identical to `Signature` but is used to
/// help with misuse and confusion.
///
/// 1 or more messages have been hidden by the signature recipient
/// so the signer only knows a subset of the messages to be signed
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindSignature(pub(crate) Signature);

impl BlindSignature {
    /// The size of the signature in bytes
    pub const BYTES: usize = 128;

    /// Generate a new signature where all messages are known to the signer
    pub fn new(
        commitment: G1Projective,
        sk: &SecretKey,
        msgs: &[(usize, Scalar)],
    ) -> CredxResult<Self> {
        if sk.y.len() < msgs.len() {
            return Err(crate::error::Error::InvalidSigningOperation);
        }
        if sk.is_invalid() {
            return Err(crate::error::Error::InvalidSigningOperation);
        }

        let t_msgs = msgs.iter().map(|(_, m)| *m).collect::<Vec<Scalar>>();
        let m_tick = Signature::compute_m_tick(t_msgs.as_slice());

        let mut hasher = sha3::Shake256::default();
        hasher.update(&sk.to_bytes());
        t_msgs.iter().for_each(|m| hasher.update(&m.to_bytes()));

        let mut reader = hasher.finalize_xof();
        let mut okm = [0u8; 64];
        reader.read(&mut okm);

        // Should yield non-zero values for `u` and m', very small likelihood of it being zero
        let u = Scalar::from_bytes_wide(&okm);
        let sigma_1 = G1Projective::GENERATOR * u;

        let mut exp = sk.x + m_tick * sk.w;
        for (i, msg) in msgs {
            exp += sk.y[*i] * msg;
        }
        let mut sigma_2 = (G1Projective::GENERATOR * exp) + commitment;
        sigma_2 *= u;
        Ok(Self(Signature {
            sigma_1,
            sigma_2,
            m_tick,
        }))
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding factor used in the commitment.
    pub fn to_unblinded(self, blinding: Scalar) -> Signature {
        Signature {
            sigma_1: self.0.sigma_1,
            sigma_2: self.0.sigma_2 - (self.0.sigma_1 * blinding),
            m_tick: self.0.m_tick,
        }
    }

    /// Get the byte representation of this signature
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_bytes()
    }

    /// Convert a byte sequence into a signature
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        Signature::from_bytes(data).map(Self)
    }
}
