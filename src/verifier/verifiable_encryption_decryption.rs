use crate::error::Error;
use crate::prelude::VerifiableEncryptionDecryptionStatement;
use crate::presentation::VerifiableEncryptionDecryptionProof;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::{Curve, G1Projective, Scalar};
use bulletproofs::{BulletproofGens, PedersenGens};
use elliptic_curve::bigint::U384;
use elliptic_curve::scalar::FromUintUnchecked;
use merlin::Transcript;

pub struct VerifiableEncryptionDecryptionVerifier<'a, 'b> {
    pub statement: &'a VerifiableEncryptionDecryptionStatement<G1Projective>,
    pub proof: &'b VerifiableEncryptionDecryptionProof,
    pub message_proof: Scalar,
}

impl ProofVerifier for VerifiableEncryptionDecryptionVerifier<'_, '_> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let challenge = -challenge;
        let r1 = self.proof.c1 * challenge + G1Projective::GENERATOR * self.proof.blinder_proof;
        let r2 = self.proof.c2 * challenge
            + self.statement.message_generator * self.message_proof
            + self.statement.encryption_key.0 * self.proof.blinder_proof;

        transcript.append_message(b"", self.statement.id.as_bytes());
        transcript.append_message(b"c1", self.proof.c1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"c2", self.proof.c2.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r1", r1.to_affine().to_compressed().as_slice());
        transcript.append_message(b"r2", r2.to_affine().to_compressed().as_slice());

        for i in 0..self.proof.byte_proofs.len() {
            transcript.append_u64(
                b"verifiable_encryption_decryption_message_byte_index",
                i as u64,
            );

            transcript.append_message(
                b"byte_proof_c1",
                self.proof.byte_ciphertext.c1[i].to_compressed().as_slice(),
            );
            transcript.append_message(
                b"byte_proof_c2",
                self.proof.byte_ciphertext.c2[i].to_compressed().as_slice(),
            );
            let inner_r1 = self.proof.byte_ciphertext.c1[i] * challenge
                + G1Projective::GENERATOR * self.proof.byte_proofs[i].blinder;
            let inner_r2 = self.proof.byte_ciphertext.c2[i] * challenge
                + self.statement.encryption_key.0 * self.proof.byte_proofs[i].blinder
                + self.statement.message_generator * self.proof.byte_proofs[i].message;
            transcript.append_message(b"byte_proof_r1", inner_r1.to_compressed().as_slice());
            transcript.append_message(b"byte_proof_r2", inner_r2.to_compressed().as_slice());
        }
        transcript.append_message(b"arbitrary_data_ciphertext", &self.proof.ciphertext);

        Ok(())
    }

    fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        let bp_gens = BulletproofGens::new(8, self.proof.byte_proofs.len());
        let pedersen_gen = PedersenGens {
            B: self.statement.message_generator,
            B_blinding: self.statement.encryption_key.0,
        };

        let mut transcript = Transcript::new(b"PresentationEncryptionDecryption byte range proof");
        transcript.append_message(b"challenge", &challenge.to_be_bytes());
        // Prove each byte is in the range [0, 255]
        self.proof
            .range_proof
            .verify_multiple(
                &bp_gens,
                &pedersen_gen,
                &mut transcript,
                &self.proof.byte_ciphertext.c2,
                8,
            )
            .map_err(|_| Error::General("Range proof verification failed"))?;

        let eight = U384::from_u8(8);
        let mut shift = U384::ZERO;
        let mut sum = G1Projective::IDENTITY;

        for c2 in &self.proof.byte_ciphertext.c2 {
            let multiplier = Scalar::from_uint_unchecked(shift);
            sum += c2 * multiplier;
            shift = shift.wrapping_add(&eight);
        }

        if sum != self.proof.c2 {
            return Err(Error::General(
                "Sum of byte ciphertexts does not match the ciphertext",
            ));
        }
        Ok(())
    }
}
