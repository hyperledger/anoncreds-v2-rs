use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::VerifiableEncryptionStatement;
use crate::CredxResult;
use blsful::bls12_381_plus::{ff::Field, group::Curve, G1Projective, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Verifiable encryption builder
pub(crate) struct VerifiableEncryptionBuilder<'a> {
    c1: G1Projective,
    c2: G1Projective,
    statement: &'a VerifiableEncryptionStatement<G1Projective>,
    message: Scalar,
    b: Scalar,
    r: Scalar,
}

impl<'a> PresentationBuilder for VerifiableEncryptionBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let message_proof = self.b + challenge * self.message;
        let blinder_proof = self.r + challenge * self.b;
        VerifiableEncryptionProof {
            id: self.statement.id.clone(),
            c1: self.c1,
            c2: self.c2,
            message_proof,
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
        transcript.append_message(b"c1", c1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"c2", c2.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_affine().to_compressed().as_slice());

        Ok(Self {
            c1,
            c2,
            statement,
            message,
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
    /// The schnorr message proof
    pub message_proof: Scalar,
    /// The schnorr blinder proof
    pub blinder_proof: Scalar,
}
