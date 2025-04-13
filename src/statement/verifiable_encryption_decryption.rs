use crate::statement::Statement;
use blsful::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Group;
use elliptic_curve_tools::group;
use merlin::Transcript;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;

/// Verifiable encryption that also allows decryption.
///
/// Use this statement when complete decryption is desired.
/// The resulting proof is much larger than the one from [`VerifiableEncryptionStatement`]
/// and slightly slower to generate.
///
/// The value encrypted and decrypted is a scalar value and not
/// the original value. This is not meant to encrypt arbitrary data since
/// arbitrary data can be of any length and cannot be proven in zero-knowledge.
/// Instead, this is meant to encrypt a scalar value that can be proven in zero-knowledge
/// and that's the best that can be achieved.
///
/// When arbitrary data is allowed,
/// we use the proof to generate an AES key to encrypt
/// arbitrary data then prove the encryption key is correct. But, again, this
/// doesn't prove the encrypted data is correct. For that, verifiable decryption
/// is needed. So the ciphertext when decrypted is proven to be correct but
/// verifiers don't usually decrypt the data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiableEncryptionDecryptionStatement<
    P: Group + GroupEncoding + Serialize + DeserializeOwned,
> {
    /// The generator for the message element
    #[serde(with = "group")]
    pub message_generator: P,
    /// The encryption key for this ciphertext
    pub encryption_key: PublicKey<Bls12381G2Impl>,
    /// The statement id
    pub id: String,
    /// The other statement id
    pub reference_id: String,
    /// The claim index in the other statement
    pub claim: usize,
}

impl<P: Group + GroupEncoding + DeserializeOwned + Serialize> Statement
    for VerifiableEncryptionDecryptionStatement<P>
{
    fn id(&self) -> String {
        self.id.clone()
    }

    fn reference_ids(&self) -> Vec<String> {
        vec![self.reference_id.clone()]
    }

    fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(
            b"statement type",
            b"el-gamal verifiable encryption w/decryption",
        );
        transcript.append_message(b"statement id", self.id.as_bytes());
        transcript.append_message(b"reference statement id", self.reference_id.as_bytes());
        transcript.append_message(b"claim index", &Uint::from(self.claim).to_vec());
        transcript.append_message(
            b"message generator",
            self.message_generator.to_bytes().as_ref(),
        );
        transcript.append_message(b"encryption key", self.encryption_key.0.to_bytes().as_ref());
    }

    fn get_claim_index(&self, _reference_id: &str) -> usize {
        self.claim
    }
}
