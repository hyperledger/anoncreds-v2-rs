use crate::claim::ClaimData;
use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{PresentationBuilder, PresentationProofs};
use crate::statement::VerifiableEncryptionDecryptionStatement;
use crate::CredxResult;
use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes128Gcm, KeyInit, Nonce};
use blsful::inner_types::{G1Projective, Scalar};
use blsful::{Bls12381G2Impl, SecretKey};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use elliptic_curve::Field;
use elliptic_curve_tools::{group_array, prime_field};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub(crate) struct VerifiableEncryptionDecryptionBuilder<'a> {
    c1: G1Projective,
    c2: G1Projective,
    statement: &'a VerifiableEncryptionDecryptionStatement<G1Projective>,
    b: Scalar,
    r: Scalar,
    message_bytes: [u8; 32],
    byte_blinders: [Scalar; 32],
    blinder_blinders: [Scalar; 32],
    byte_ciphertext: Ciphertext,
    arbitrary_data_ciphertext: Vec<u8>,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S>
    for VerifiableEncryptionDecryptionBuilder<'_>
{
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        let bp_gens = BulletproofGens::new(8, self.message_bytes.len());
        let pedersen_gen = PedersenGens {
            B: self.statement.message_generator,
            B_blinding: self.statement.encryption_key.0,
        };

        let mut transcript = Transcript::new(b"PresentationEncryptionDecryption byte range proof");
        transcript.append_message(b"challenge", &challenge.to_be_bytes());
        let key_segments = self
            .message_bytes
            .iter()
            .map(|b| *b as u64)
            .collect::<Vec<_>>();
        let (range_proof, _) = RangeProof::prove_multiple(
            &bp_gens,
            &pedersen_gen,
            &mut transcript,
            &key_segments,
            &self.byte_blinders,
            8,
        )
        .expect("range proof to work");
        let blinder_proof = self.r + challenge * self.b;
        let mut byte_proofs = [ByteProof::default(); 32];
        for ((byte_proof, byte_blinder), (message_byte, blinder_blinder)) in byte_proofs
            .iter_mut()
            .zip(self.byte_blinders.iter())
            .zip(self.message_bytes.iter().zip(self.blinder_blinders.iter()))
        {
            *byte_proof = ByteProof {
                message: byte_blinder + challenge * Scalar::from(*message_byte),
                blinder: blinder_blinder + challenge * byte_blinder,
            };
        }
        VerifiableEncryptionDecryptionProof {
            id: self.statement.id.clone(),
            message_generator: self.statement.message_generator,
            byte_proofs,
            range_proof,
            c1: self.c1,
            c2: self.c2,
            blinder_proof,
            byte_ciphertext: self.byte_ciphertext,
            ciphertext: self.arbitrary_data_ciphertext,
        }
        .into()
    }
}

impl<'a> VerifiableEncryptionDecryptionBuilder<'a> {
    pub fn commit(
        statement: &'a VerifiableEncryptionDecryptionStatement<G1Projective>,
        message: &ClaimData,
        msg: Scalar,
        b: Scalar,
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let r = Scalar::random(&mut rng);

        let c1 = G1Projective::GENERATOR * b;
        let c2 = statement.message_generator * msg + statement.encryption_key.0 * b;

        let r1 = G1Projective::GENERATOR * r;
        let r2 = statement.message_generator * b + statement.encryption_key.0 * r;

        let message_bytes = msg.to_be_bytes();
        // The idea is for the byte blinders to sum to `b`
        // Need to generate `message_bytes.len() - 1` random scalars
        // and the last one will be `b` - sum(all others)
        let mut byte_ciphertext = Ciphertext::default();
        let mut byte_blinders = [Scalar::ZERO; 32];
        let mut blinder_blinders = [Scalar::ZERO; 32];
        let mut sum = Scalar::ZERO;

        let shift = Scalar::from(256u16);
        for i in 0..message_bytes.len() - 1 {
            let blinder = Scalar::random(&mut rng);

            sum += blinder * shift.pow([31u64 - i as u64]);

            blinder_blinders[i] = Scalar::random(&mut rng);
            byte_blinders[i] = blinder;

            byte_ciphertext.c1[i] = G1Projective::GENERATOR * blinder;
            byte_ciphertext.c2[i] = statement.message_generator * Scalar::from(message_bytes[i])
                + statement.encryption_key.0 * blinder;
        }
        blinder_blinders[31] = Scalar::random(&mut rng);
        byte_blinders[31] = b - sum;
        byte_ciphertext.c1[31] = G1Projective::GENERATOR * byte_blinders[31];
        byte_ciphertext.c2[31] = statement.message_generator * Scalar::from(message_bytes[31])
            + statement.encryption_key.0 * byte_blinders[31];

        transcript.append_message(b"", statement.id.as_bytes());
        transcript.append_message(b"c1", c1.to_compressed().as_slice());
        transcript.append_message(b"c2", c2.to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_compressed().as_slice());

        for i in 0..message_bytes.len() {
            transcript.append_u64(
                b"verifiable_encryption_decryption_message_byte_index",
                i as u64,
            );
            transcript.append_message(
                b"byte_proof_c1",
                byte_ciphertext.c1[i].to_compressed().as_slice(),
            );
            transcript.append_message(
                b"byte_proof_c2",
                byte_ciphertext.c2[i].to_compressed().as_slice(),
            );
            let inner_r1 = G1Projective::GENERATOR * blinder_blinders[i];
            let inner_r2 = statement.message_generator * byte_blinders[i]
                + statement.encryption_key.0 * blinder_blinders[i];

            transcript.append_message(b"byte_proof_r1", inner_r1.to_compressed().as_slice());
            transcript.append_message(b"byte_proof_r2", inner_r2.to_compressed().as_slice());
        }

        let arbitrary_data = message.to_text();
        let mut aes_transcript =
            Transcript::new(b"PresentationEncryptionDecryption arbitrary data derive aes key");
        let input = statement.encryption_key.0 * b;
        aes_transcript.append_message(b"key ikm", input.to_compressed().as_slice());
        let mut okm = [0u8; 32];
        aes_transcript.challenge_bytes(b"aes key", &mut okm);
        let nonce = Aes128Gcm::generate_nonce(&mut rng);
        let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&okm[..16]);
        let aad = okm[16..]
            .iter()
            .copied()
            .chain(c1.to_compressed())
            .chain(c2.to_compressed())
            .collect::<Vec<_>>();
        let cipher = Aes128Gcm::new(key);
        let payload = aes_gcm::aead::Payload {
            msg: arbitrary_data.as_bytes(),
            aad: &aad,
        };
        let mut ciphertext = nonce.to_vec();
        ciphertext.append(
            &mut cipher
                .encrypt(&nonce, payload)
                .expect("encryption message to be encrypted"),
        );
        transcript.append_message(b"arbitrary_data_ciphertext", &ciphertext);
        let arbitrary_data_ciphertext = ciphertext;

        Ok(Self {
            c1,
            c2,
            statement,
            b,
            r,
            message_bytes,
            byte_blinders,
            blinder_blinders,
            byte_ciphertext,
            arbitrary_data_ciphertext,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableEncryptionDecryptionProof {
    /// The statement identifier
    pub id: String,
    /// The original message generator
    pub message_generator: G1Projective,
    /// The message decomposed into schnorr byte proofs
    pub byte_proofs: [ByteProof; 32],
    /// Byte range proofs
    pub range_proof: RangeProof,
    /// DLog proof
    pub c1: G1Projective,
    /// DLog proof
    pub c2: G1Projective,
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
    /// The byte ciphertext
    pub byte_ciphertext: Ciphertext,
    /// The encrypted arbitrary data if the statement included it
    pub ciphertext: Vec<u8>,
}

impl VerifiableEncryptionDecryptionProof {
    pub fn decrypt_and_verify(
        &self,
        decryption_key: &SecretKey<Bls12381G2Impl>,
    ) -> CredxResult<ClaimData> {
        // 12 for the nonce
        // 16 for the tag
        if self.ciphertext.len() < 12 + 16 {
            return Err(Error::General("arbitrary data ciphertext is too short"));
        }

        let input = self.c1 * decryption_key.0;
        let expected_commitment = self.c2 - input;
        let nonce = Nonce::from_slice(&self.ciphertext[..12]);

        let mut aes_transcript =
            Transcript::new(b"PresentationEncryptionDecryption arbitrary data derive aes key");
        aes_transcript.append_message(b"key ikm", input.to_compressed().as_slice());
        let mut okm = [0u8; 32];
        aes_transcript.challenge_bytes(b"aes key", &mut okm);

        let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&okm[..16]);
        let aad = okm[16..]
            .iter()
            .copied()
            .chain(self.c1.to_compressed())
            .chain(self.c2.to_compressed())
            .collect::<Vec<_>>();
        let cipher = Aes128Gcm::new(key);
        let payload = aes_gcm::aead::Payload {
            msg: &self.ciphertext[12..],
            aad: &aad,
        };
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::General("unable to decrypt arbitrary data: aes-128-gcm"))?;
        let plaintext = String::from_utf8(plaintext)
            .map_err(|_| Error::General("unable to convert decrypted data to utf-8"))?;
        let claim = ClaimData::from_text(&plaintext)?;
        let computed_commitment = self.message_generator * claim.to_scalar();
        if computed_commitment != expected_commitment {
            return Err(Error::General(
                "Invalid decrypted data. Computed commitment does not match expected commitment.",
            ));
        }
        Ok(claim)
    }
}

/// A schnorr proof of knowledge of a byte
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct ByteProof {
    /// The message schnorr proof
    #[serde(with = "prime_field")]
    pub message: Scalar,
    /// The blinder schnorr proof
    #[serde(with = "prime_field")]
    pub blinder: Scalar,
}

/// A ciphertext that encodes a scalar
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The El-Gamal C1 values
    #[serde(with = "group_array")]
    pub c1: [G1Projective; 32],
    /// The El-Gamal C2 values
    #[serde(with = "group_array")]
    pub c2: [G1Projective; 32],
}
