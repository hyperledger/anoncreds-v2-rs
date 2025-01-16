//! Traits for abstracting public keys, secret keys, signatures, blind signatures,
//! and zero-knowledge proofs of message and signature knowledge
use crate::knox::short_group_sig_core::ProofMessage;
use crate::CredxResult;
use blsful::inner_types::{Group, GroupEncoding, Scalar};
use elliptic_curve::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;

/// Trait for abstracting public keys
pub trait PublicKey: Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de> {
    /// The generator type used for signing messages
    /// and creating proofs of message knowledge
    type MessageGenerator: Group + GroupEncoding + Default + Serialize + for<'de> Deserialize<'de>;
    /// The generator type used for creating blind signatures
    type BlindMessageGenerator: Group
        + GroupEncoding
        + Default
        + Serialize
        + for<'de> Deserialize<'de>;

    /// Serialize the public key to bytes
    fn to_bytes(&self) -> Vec<u8> {
        serde_bare::to_vec(&self).expect("to serialize public key")
    }
}

/// Trait for abstracting secret keys
pub trait SecretKey: Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de> {
    /// The public key type
    type PublicKey: PublicKey;

    /// Return a public key from the secret key
    fn public_key(&self) -> Self::PublicKey;
}

/// Trait for abstracting signatures
pub trait Signature: Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de> {
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
pub trait BlindSignature: Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de> {
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
pub trait BlindSignatureContext:
    Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de>
{
    /// The secret key type
    type SecretKey: SecretKey;
    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another way
    fn verify(
        &self,
        known_messages: &[usize],
        sk: &Self::SecretKey,
        nonce: Scalar,
    ) -> CredxResult<bool>;
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
        signature: &Self::Signature,
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
pub trait ProofOfSignatureKnowledge:
    Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de>
{
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
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
        challenge: Scalar,
    ) -> CredxResult<()>;

    /// Get the hidden message proofs
    fn get_hidden_message_proofs(
        &self,
        public_key: &Self::PublicKey,
        revealed_messages: &[(usize, Scalar)],
    ) -> CredxResult<BTreeMap<usize, Scalar>>;
}

/// Trait for abstracting a short group signature scheme
pub trait ShortGroupSignatureScheme:
    Sized + Clone + Debug + Serialize + for<'de> Deserialize<'de>
{
    /// The public key type
    type PublicKey: PublicKey;
    /// The secret key type
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>;
    /// The signature type
    type Signature: Signature<PublicKey = Self::PublicKey, SecretKey = Self::SecretKey>;
    /// The blind signature context type
    type BlindSignatureContext: BlindSignatureContext<SecretKey = Self::SecretKey>;
    /// The blind signature type
    type BlindSignature: BlindSignature<
        PublicKey = Self::PublicKey,
        SecretKey = Self::SecretKey,
        Signature = Self::Signature,
    >;
    /// The proof of signature knowledge type
    type ProofOfSignatureKnowledge: ProofOfSignatureKnowledge<PublicKey = Self::PublicKey>;
    /// The proof of signature knowledge contribution type
    type ProofOfSignatureKnowledgeContribution: ProofOfSignatureKnowledgeContribution<
        Signature = Self::Signature,
        PublicKey = Self::PublicKey,
        ProofOfKnowledge = Self::ProofOfSignatureKnowledge,
    >;

    /// Create a keypair capable of signing up to `count` messages
    fn new_keys(
        count: NonZeroUsize,
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(Self::PublicKey, Self::SecretKey)>;

    /// Create a signature with no hidden messages
    fn sign<M>(sk: &Self::SecretKey, msgs: M) -> CredxResult<Self::Signature>
    where
        M: AsRef<[Scalar]>;

    /// Verify a proof of committed messages and generate a blind signature
    fn blind_sign(
        ctx: &Self::BlindSignatureContext,
        sk: &Self::SecretKey,
        msgs: &[(usize, Scalar)],
        nonce: Scalar,
    ) -> CredxResult<Self::BlindSignature>;

    /// Create a nonce used for the blind signing context
    fn generate_signing_nonce(rng: impl RngCore + CryptoRng) -> Scalar {
        Scalar::random(rng)
    }

    /// Create the structures need to send to an issuer to complete a blinded signature
    /// `messages` is an index to message map where the index corresponds to the index in `generators`
    fn new_blind_signature_context(
        messages: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
        nonce: Scalar,
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<(Self::BlindSignatureContext, Scalar)>;

    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    fn commit_signature_pok(
        signature: Self::Signature,
        public_key: &Self::PublicKey,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
    ) -> CredxResult<Self::ProofOfSignatureKnowledgeContribution>;

    /// Check a signature proof of knowledge and selective disclosure proof
    fn verify_signature_pok(
        revealed_msgs: &[(usize, Scalar)],
        public_key: &Self::PublicKey,
        proof: &Self::ProofOfSignatureKnowledge,
        nonce: Scalar,
        challenge: Scalar,
    ) -> bool;
}
