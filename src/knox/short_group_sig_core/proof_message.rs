use super::super::ecc_group::ScalarOps;
use super::hidden_message::HiddenMessage;
use blsful::inner_types::ff::PrimeField;
use rand_core::{CryptoRng, RngCore};

/// A message classification by the prover
#[derive(Copy, Clone, Debug)]
pub enum ProofMessage<S>
where
    S: PrimeField + ScalarOps<Scalar = S>,
{
    /// Message will be revealed to a verifier
    Revealed(S),
    /// Message will be hidden from a verifier
    Hidden(HiddenMessage<S>),
}

impl<S> ProofMessage<S>
where
    S: PrimeField + ScalarOps<Scalar = S>,
{
    /// Extract the internal message
    pub fn get_message(&self) -> S {
        match *self {
            ProofMessage::Revealed(r) => r,
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(p)) => p,
            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(p, _)) => p,
        }
    }

    /// Get the blinding factor
    pub fn get_blinder(&self, rng: impl RngCore + CryptoRng) -> Option<S> {
        match *self {
            ProofMessage::Revealed(_) => None,
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(_)) => Some(S::random(rng)),
            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(_, s)) => Some(s),
        }
    }
}
