//! Traits for abstracting public keys, secret keys, signatures, blind signatures,
//! and zero-knowledge proofs of message and signature knowledge
use crate::knox::short_group_sig_core::ProofMessage;
use crate::CredxResult;
use blsful::inner_types::{Group, GroupEncoding, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

/// Trait for abstracting public keys
pub trait PublicKey: Sized {
    /// The generator type used for signing messages
    /// and creating proofs of message knowledge
    type MessageGenerator: Group + GroupEncoding + Default;
    /// The generator type used for creating blind signatures
    type BlindMessageGenerator: Group + GroupEncoding + Default;
}

/// Trait for abstracting secret keys
pub trait SecretKey: Sized {
    /// The public key type
    type PublicKey: PublicKey;

    /// Return a public key from the secret key
    fn public_key(&self) -> Self::PublicKey;
}

/// Trait for abstracting signatures
pub trait Signature: Sized {
    /// The secret key type
    type SecretKey: SecretKey;
    /// The public key type
    type PublicKey: PublicKey;

    /// Generate a new signature where all messages are known to the signer
    fn create(sk: &Self::SecretKey, msgs: &[Scalar]) -> CredxResult<Self>;
    /// Verify a signature
    fn verify(&self, pk: &Self::PublicKey, msgs: &[Scalar]) -> CredxResult<()>;
}

/// Trait for abstracting blind signatures
pub trait BlindSignature: Sized {
    /// The secret key type
    type SecretKey: SecretKey;
    /// The public key type
    type PublicKey: PublicKey;
    /// The unblinded signature type
    type Signature: Signature;

    /// Generate a new signature where a subset of messages are known to the signer
    /// and the rest are hidden in the commitment
    fn new(
        commitment: <Self::PublicKey as PublicKey>::BlindMessageGenerator,
        sk: &Self::SecretKey,
        msgs: &[(usize, Scalar)],
    ) -> CredxResult<Self>;
    /// Unblind the signature
    fn to_unblinded(self, blinding: Scalar) -> Self::Signature;
}

/// Trait for abstracting zero-knowledge proofs for signature proofs knowledge
/// This trait represents the prover side of the proof and the commitment to the
/// signature and the signed messages.
pub trait ProofOfSignatureKnowledgeContribution: Sized {
    /// The signature type
    type Signature: Signature;
    /// The public key type
    type PublicKey: PublicKey;
    /// The proof of knowledge type
    type ProofOfKnowledge: ProofOfSignatureKnowledge;

    /// Commit to the signature and the signed messages which is the 1st step to
    /// creating the proof.
    fn commit(
        signature: Self::Signature,
        public_key: &Self::PublicKey,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self>;
    /// Add the proof contribution to the transcript
    fn add_proof_contribution(&self, transcript: &mut Transcript);
    /// Generate the proof
    fn generate_proof(self, challenge: Scalar) -> CredxResult<Self::ProofOfKnowledge>;
}

/// Trait for abstracting zero-knowledge proofs for signature proofs knowledge
pub trait ProofOfSignatureKnowledge: Sized {
    /// The public key type
    type PublicKey: PublicKey;

    /// Add the proof contribution to the transcript
    fn add_proof_contribution(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
        challenge: Scalar,
        transcript: &mut Transcript,
    );

    /// Verify the signature proof of knowledge
    fn verify(
        &self,
        revealed_messages: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
    ) -> CredxResult<()>;

    /// Get the hidden message proofs
    fn get_hidden_message_proofs(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
    ) -> CredxResult<BTreeMap<usize, Scalar>>;
}
