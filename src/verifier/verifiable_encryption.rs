use crate::error::Error;
use crate::presentation::VerifiableEncryptionProof;
use crate::statement::VerifiableEncryptionStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::{G1Projective, Scalar};
use bulletproofs::{BulletproofGens, PedersenGens};
use elliptic_curve::group::Curve;
use merlin::Transcript;

pub struct VerifiableEncryptionVerifier<'a, 'b> {
    pub statement: &'a VerifiableEncryptionStatement<G1Projective>,
    pub proof: &'b VerifiableEncryptionProof,
    pub message_proof: Scalar,
}

impl ProofVerifier for VerifiableEncryptionVerifier<'_, '_> {
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

        if let Some(decryptable_proof) = self.proof.decryptable_scalar_proof.as_ref() {
            for i in 0..decryptable_proof.byte_proofs.len() {
                transcript.append_u64(
                    b"verifiable_encryption_decryptable_message_byte_index",
                    i as u64,
                );

                transcript.append_message(
                    b"byte_proof_c1",
                    decryptable_proof.byte_ciphertext.c1[i]
                        .to_compressed()
                        .as_slice(),
                );
                transcript.append_message(
                    b"byte_proof_c2",
                    decryptable_proof.byte_ciphertext.c2[i]
                        .to_compressed()
                        .as_slice(),
                );
                let inner_r1 = decryptable_proof.byte_ciphertext.c1[i] * challenge
                    + G1Projective::GENERATOR * decryptable_proof.byte_proofs[i].blinder;
                let inner_r2 = decryptable_proof.byte_ciphertext.c2[i] * challenge
                    + self.statement.encryption_key.0 * decryptable_proof.byte_proofs[i].blinder
                    + self.statement.message_generator * decryptable_proof.byte_proofs[i].message;

                transcript.append_message(b"byte_proof_r1", inner_r1.to_compressed().as_slice());
                transcript.append_message(b"byte_proof_r2", inner_r2.to_compressed().as_slice());
            }
        }

        Ok(())
    }

    fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        if let Some(decryptable_proof) = self.proof.decryptable_scalar_proof.as_ref() {
            let bp_gens = BulletproofGens::new(8, decryptable_proof.byte_proofs.len());
            let pedersen_gen = PedersenGens {
                B: self.statement.message_generator,
                B_blinding: self.statement.encryption_key.0,
            };

            let mut transcript =
                Transcript::new(b"PresentationEncryptionDecryption byte range proof");
            transcript.append_message(b"challenge", &challenge.to_be_bytes());
            // Prove each byte is in the range [0, 255]
            decryptable_proof
                .range_proof
                .verify_multiple(
                    &bp_gens,
                    &pedersen_gen,
                    &mut transcript,
                    &decryptable_proof.byte_ciphertext.c2,
                    8,
                )
                .map_err(|_| Error::General("Range proof verification failed"))?;

            let shift = Scalar::from(256u16);
            let mut sum = G1Projective::IDENTITY;

            for c2 in &decryptable_proof.byte_ciphertext.c2 {
                sum *= shift;
                sum += c2;
            }

            if sum != self.proof.c2 {
                return Err(Error::General(
                    "Sum of byte ciphertexts does not match the ciphertext",
                ));
            }
        }
        Ok(())
    }
}
