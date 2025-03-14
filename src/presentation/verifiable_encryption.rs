use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::VerifiableEncryptionStatement;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use blsful::{Bls12381G2Impl, SecretKey};
use elliptic_curve::ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Verifiable encryption builder
pub(crate) struct VerifiableEncryptionBuilder<'a> {
    pub(crate) c1: G1Projective,
    pub(crate) c2: G1Projective,
    pub(crate) statement: &'a VerifiableEncryptionStatement<G1Projective>,
    pub(crate) b: Scalar,
    pub(crate) r: Scalar,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S> for VerifiableEncryptionBuilder<'_> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        let blinder_proof = self.r + challenge * self.b;
        VerifiableEncryptionProof {
            id: self.statement.id.clone(),
            c1: self.c1,
            c2: self.c2,
            blinder_proof,
        }
        .into()
    }
}

impl<'a> VerifiableEncryptionBuilder<'a> {
    /// Create a new verifiable encryption builder
    pub fn commit(
        statement: &'a VerifiableEncryptionStatement<G1Projective>,
        message: Scalar,
        b: Scalar,
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let r = Scalar::random(&mut rng);

        let c1 = G1Projective::GENERATOR * b;
        let c2 = statement.message_generator * message + statement.encryption_key.0 * b;

        let r1 = G1Projective::GENERATOR * r;
        let r2 = statement.message_generator * b + statement.encryption_key.0 * r;

        transcript.append_message(b"", statement.id.as_bytes());
        transcript.append_message(b"c1", c1.to_compressed().as_slice());
        transcript.append_message(b"c2", c2.to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_compressed().as_slice());

        Ok(Self {
            c1,
            c2,
            statement,
            b,
            r,
        })
    }
}

/// A verifiable encryption proof
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiableEncryptionProof {
    /// The statement identifier
    pub id: String,
    /// The C1 El-Gamal component
    pub c1: G1Projective,
    /// The C2 El-Gamal component
    pub c2: G1Projective,
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
}

impl VerifiableEncryptionProof {
    /// Unmask the committed message. The value will be in the exponent
    /// of the group element.
    pub fn decrypt(&self, key: &SecretKey<Bls12381G2Impl>) -> G1Projective {
        self.c2 - self.c1 * key.0
    }
}
