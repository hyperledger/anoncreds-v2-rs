use crate::error::Error;
use crate::presentation::{CommitmentBuilder, PresentationBuilder, PresentationProofs};
use crate::statement::RangeStatement;
use crate::utils::*;
use crate::CredxResult;
use blsful::bls12_381_plus::{group::Curve, Scalar};
use bulletproofs::RangeProof as RangeProofBulletproof;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub(crate) struct RangeBuilder<'a> {
    statement: &'a RangeStatement,
    commitment_builder: &'a CommitmentBuilder<'a>,
    adjusted_lower: Option<u64>,
    adjusted_upper: Option<u64>,
}

impl<'a> PresentationBuilder for RangeBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let pedersen_gen = bulletproofs::PedersenGens {
            B: self.commitment_builder.statement.message_generator,
            B_blinding: self.commitment_builder.statement.blinder_generator,
        };

        let mut transcript = Transcript::new(b"credx range proof");
        transcript.append_message(b"challenge", &challenge.to_bytes());

        let blinder = self.commitment_builder.b;

        match (self.adjusted_upper, self.adjusted_lower) {
            (Some(upper), Some(lower)) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 2);
                let (proof, commitments) = RangeProofBulletproof::prove_multiple(
                    &bulletproof_gens,
                    &pedersen_gen,
                    &mut transcript,
                    &[upper, lower],
                    &[blinder, blinder],
                    64,
                )
                .unwrap();

                debug_assert_eq!(
                    commitments[0],
                    self.commitment_builder.commitment
                        + self.commitment_builder.statement.message_generator
                            * Scalar::from(
                                u64::MAX - zero_center(*self.statement.upper.as_ref().unwrap())
                            )
                );
                debug_assert_eq!(
                    commitments[1],
                    self.commitment_builder.commitment
                        - self.commitment_builder.statement.message_generator
                            * Scalar::from(zero_center(*self.statement.lower.as_ref().unwrap()))
                );
                RangeProof {
                    id: self.statement.id.clone(),
                    proof,
                }
                .into()
            }
            (Some(upper), None) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 1);
                let (proof, commitment) = RangeProofBulletproof::prove_single(
                    &bulletproof_gens,
                    &pedersen_gen,
                    &mut transcript,
                    upper,
                    &blinder,
                    64,
                )
                .unwrap();
                debug_assert_eq!(
                    commitment,
                    self.commitment_builder.commitment
                        + self.commitment_builder.statement.message_generator
                            * Scalar::from(
                                u64::MAX - zero_center(*self.statement.upper.as_ref().unwrap())
                            )
                );
                RangeProof {
                    id: self.statement.id.clone(),
                    proof,
                }
                .into()
            }
            (None, Some(lower)) => {
                let bulletproof_gens = bulletproofs::BulletproofGens::new(64, 1);
                let (proof, commitment) = RangeProofBulletproof::prove_single(
                    &bulletproof_gens,
                    &pedersen_gen,
                    &mut transcript,
                    lower,
                    &blinder,
                    64,
                )
                .unwrap();
                debug_assert_eq!(
                    commitment,
                    self.commitment_builder.commitment
                        - self.commitment_builder.statement.message_generator
                            * Scalar::from(zero_center(*self.statement.lower.as_ref().unwrap()))
                );
                RangeProof {
                    id: self.statement.id.clone(),
                    proof,
                }
                .into()
            }
            (None, None) => {
                panic!("How did this happen?")
            }
        }
    }
}

impl<'a> RangeBuilder<'a> {
    pub fn commit(
        statement: &'a RangeStatement,
        commitment_builder: &'a CommitmentBuilder<'a>,
        message: isize,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        if statement.claim != commitment_builder.statement.claim
            && statement.signature_id != commitment_builder.statement.reference_id
        {
            // Not testing the same message from the same signature
            return Err(Error::InvalidPresentationData);
        }

        transcript.append_message(b"", statement.id.as_bytes());
        transcript.append_message(
            b"used commitment",
            &commitment_builder.commitment.to_affine().to_compressed(),
        );
        transcript.append_u64(b"range proof bits", 64);

        let blind = commitment_builder.statement.blinder_generator * commitment_builder.b;
        let mut l = None;
        let mut u = None;
        // negation zero centers in the positive range
        match (statement.lower, statement.upper) {
            (Some(lower), Some(upper)) => {
                let adjusted_lower = zero_center(message) - zero_center(lower);
                let max_upper = u64::MAX - zero_center(upper);
                let adjusted_upper = zero_center(message) + max_upper;
                l = Some(adjusted_lower);
                u = Some(adjusted_upper);
                let adjusted_upper_commitment = commitment_builder.statement.message_generator
                    * Scalar::from(adjusted_upper)
                    + blind;
                let adjusted_lower_commitment = commitment_builder.statement.message_generator
                    * Scalar::from(adjusted_lower)
                    + blind;
                transcript.append_message(b"range proof version", &[3]);
                transcript.append_message(
                    b"adjusted upper commitment",
                    &adjusted_upper_commitment.to_affine().to_compressed(),
                );
                transcript.append_message(
                    b"adjusted lower commitment",
                    &adjusted_lower_commitment.to_affine().to_compressed(),
                );
            }
            (None, Some(upper)) => {
                let max_upper = u64::MAX - zero_center(upper);
                let adjusted_upper = zero_center(message) + max_upper;
                u = Some(adjusted_upper);
                let adjusted_upper_commitment = commitment_builder.statement.message_generator
                    * Scalar::from(adjusted_upper)
                    + blind;
                transcript.append_message(b"range proof version", &[2]);
                transcript.append_message(
                    b"adjusted upper commitment",
                    &adjusted_upper_commitment.to_affine().to_compressed(),
                );
            }
            (Some(lower), None) => {
                let adjusted_lower = zero_center(message) - zero_center(lower);
                l = Some(adjusted_lower);
                let adjusted_lower_commitment = commitment_builder.statement.message_generator
                    * Scalar::from(adjusted_lower)
                    + blind;
                transcript.append_message(b"range proof version", &[1]);
                transcript.append_message(
                    b"adjusted lower commitment",
                    &adjusted_lower_commitment.to_affine().to_compressed(),
                );
            }
            (None, None) => {
                return Err(Error::InvalidPresentationData);
            }
        }
        Ok(Self {
            statement,
            commitment_builder,
            adjusted_lower: l,
            adjusted_upper: u,
        })
    }
}

/// A Range proof
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RangeProof {
    /// The statement identifier
    pub id: String,
    /// The range proof
    pub proof: RangeProofBulletproof,
}
