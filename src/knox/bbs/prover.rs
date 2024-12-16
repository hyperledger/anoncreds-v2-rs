use crate::knox::bbs::{ExpandedPublicKey, PokSignature, Signature};
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledgeContribution;
use crate::knox::short_group_sig_core::ProofMessage;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use rand_core::{CryptoRng, RngCore};

/// A Prover is whoever receives signatures or uses them to generate proofs.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover;

impl Prover {
    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    pub fn commit_signature_pok(
        signature: Signature,
        public_key: &ExpandedPublicKey,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<PokSignature> {
        PokSignature::commit(signature, public_key, messages, rng)
    }
}
