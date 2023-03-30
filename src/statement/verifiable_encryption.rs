use crate::statement::Statement;
use crate::utils::*;
use blsful::bls12_381_plus::group::{Group, GroupEncoding};
use merlin::Transcript;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uint_zigzag::Uint;

/// Verifiable encryption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiableEncryptionStatement<P: Group + GroupEncoding + Serialize + DeserializeOwned> {
    /// The generator for the message element
    #[serde(
        serialize_with = "serialize_point",
        deserialize_with = "deserialize_point"
    )]
    pub message_generator: P,
    /// The encryption key for this ciphertext
    pub encryption_key: blsful::PublicKeyVt,
    /// The statement id
    pub id: String,
    /// The other statement id
    pub reference_id: String,
    /// The claim index in the other statement
    pub claim: usize,
}

impl<P: Group + GroupEncoding + DeserializeOwned + Serialize> Statement
    for VerifiableEncryptionStatement<P>
{
    fn id(&self) -> String {
        self.id.clone()
    }

    fn reference_ids(&self) -> Vec<String> {
        vec![self.reference_id.clone()]
    }

    fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"statement type", b"el-gamal verifiable encryption");
        transcript.append_message(b"statement id", self.id.as_bytes());
        transcript.append_message(b"reference statement id", self.reference_id.as_bytes());
        transcript.append_message(b"claim index", &Uint::from(self.claim).to_vec());
        transcript.append_message(
            b"message generator",
            self.message_generator.to_bytes().as_ref(),
        );
        transcript.append_message(b"encryption key", self.encryption_key.to_bytes().as_ref());
    }

    fn get_claim_index(&self, _reference_id: &str) -> usize {
        self.claim
    }
}
