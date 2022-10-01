use crate::error::Error;
use crate::presentation::RangeProof;
use crate::statement::{CommitmentStatement, RangeStatement};
use crate::utils::{get_num_scalar, zero_center};
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use group::Curve;
use merlin::Transcript;
use yeti::knox::bls12_381_plus::{G1Projective, Scalar};

pub struct RangeProofVerifier<'a, 'b, 'c> {
    pub statement: &'a RangeStatement,
    pub commitment_statement: &'b CommitmentStatement<G1Projective>,
    pub proof: &'c RangeProof,
    pub commitment: G1Projective,
}

impl<'a, 'b, 'c> ProofVerifier for RangeProofVerifier<'a, 'b, 'c> {
    fn add_challenge_contribution(
        &self,
        _challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        transcript.append_message(b"", self.statement.id.as_bytes());
        transcript.append_message(
            b"used commitment",
            &self.commitment.to_affine().to_compressed(),
        );
        transcript.append_u64(b"range proof bits", 64);

        match (self.statement.lower, self.statement.upper) {
            (Some(lower), Some(upper)) => {
                let sc_lower = get_num_scalar(lower);
                let adjusted_lower_commitment =
                    self.commitment - self.commitment_statement.message_generator * sc_lower;
                let sc_upper = Scalar::from(u64::MAX - zero_center(upper));
                let adjusted_upper_commitment =
                    self.commitment + self.commitment_statement.message_generator * sc_upper;
                transcript.append_message(b"range proof version", &[3]);
                transcript.append_message(
                    b"adjusted upper commitment",
                    &adjusted_upper_commitment.to_affine().to_compressed(),
                );
                transcript.append_message(
                    b"adjusted lower commitment",
                    &adjusted_lower_commitment.to_affine().to_compressed(),
                );
                Ok(())
            }
            (None, Some(upper)) => {
                let sc_upper = Scalar::from(u64::MAX - zero_center(upper));
                let adjusted_upper_commitment =
                    self.commitment + self.commitment_statement.message_generator * sc_upper;
                transcript.append_message(b"range proof version", &[2]);
                transcript.append_message(
                    b"adjusted upper commitment",
                    &adjusted_upper_commitment.to_affine().to_compressed(),
                );
                Ok(())
            }
            (Some(lower), None) => {
                let sc_lower = get_num_scalar(lower);
                let adjusted_lower_commitment =
                    self.commitment - self.commitment_statement.message_generator * sc_lower;
                transcript.append_message(b"range proof version", &[1]);
                transcript.append_message(
                    b"adjusted lower commitment",
                    &adjusted_lower_commitment.to_affine().to_compressed(),
                );
                Ok(())
            }
            (None, None) => {
                return Err(Error::InvalidPresentationData);
            }
        }
    }

    fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        let pedersen_gen = bulletproofs::PedersenGens {
            B: self.commitment_statement.message_generator,
            B_blinding: self.commitment_statement.blinder_generator,
        };

        let mut transcript = Transcript::new(b"credx range proof");
        transcript.append_message(b"challenge", &challenge.to_bytes());

        match (self.statement.lower, self.statement.upper) {
            (Some(lower), Some(upper)) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 2);
                let sc_lower = get_num_scalar(lower);
                let adjusted_lower_commitment =
                    self.commitment - self.commitment_statement.message_generator * sc_lower;
                let sc_upper = Scalar::from(u64::MAX - zero_center(upper));
                let adjusted_upper_commitment =
                    self.commitment + self.commitment_statement.message_generator * sc_upper;
                self.proof
                    .proof
                    .verify_multiple(
                        &bulletproof_gens,
                        &pedersen_gen,
                        &mut transcript,
                        &[adjusted_upper_commitment, adjusted_lower_commitment],
                        64,
                    )
                    .map_err(|_| Error::InvalidBulletproofRange)
            }
            (None, Some(upper)) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 1);
                let sc_upper = Scalar::from(u64::MAX - zero_center(upper));
                let adjusted_upper_commitment =
                    self.commitment + self.commitment_statement.message_generator * sc_upper;
                self.proof
                    .proof
                    .verify_single(
                        &bulletproof_gens,
                        &pedersen_gen,
                        &mut transcript,
                        &adjusted_upper_commitment,
                        64,
                    )
                    .map_err(|_| Error::InvalidBulletproofRange)
            }
            (Some(lower), None) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 1);
                let sc_lower = get_num_scalar(lower);
                let adjusted_lower_commitment =
                    self.commitment - self.commitment_statement.message_generator * sc_lower;
                self.proof
                    .proof
                    .verify_single(
                        &bulletproof_gens,
                        &pedersen_gen,
                        &mut transcript,
                        &adjusted_lower_commitment,
                        64,
                    )
                    .map_err(|_| Error::InvalidBulletproofRange)
            }
            (None, None) => {
                return Err(Error::InvalidPresentationData);
            }
        }
    }
}
