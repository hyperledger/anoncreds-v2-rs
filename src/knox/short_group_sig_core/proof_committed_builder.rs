use super::super::ecc_group::*;
use crate::CredxResult;
use blsful::inner_types::{
    ff::PrimeField,
    group::{Curve, GroupEncoding},
};
use core::fmt::Debug;
use merlin::Transcript;
use rand_core::RngCore;
use subtle::ConstantTimeEq;

/// A builder struct for creating a proof of knowledge
/// of messages in a vector commitment
/// each message has a blinding factor
pub struct ProofCommittedBuilder<B, C, S>
where
    B: Clone + Copy + Debug + Default + ConstantTimeEq + PartialEq + Eq + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
    S: PrimeField + ScalarOps<Scalar = S>,
{
    points: Vec<B>,
    scalars: Vec<S>,
    sum_of_products: fn(&[B], &[S]) -> B,
}

impl<B, C, S> Default for ProofCommittedBuilder<B, C, S>
where
    B: Clone + Copy + Debug + Default + ConstantTimeEq + PartialEq + Eq + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
    S: PrimeField + ScalarOps<Scalar = S>,
{
    fn default() -> Self {
        Self::new(|_, _| B::default())
    }
}

impl<B, C, S> ProofCommittedBuilder<B, C, S>
where
    B: Clone + Copy + Debug + Default + ConstantTimeEq + PartialEq + Eq + Curve<AffineRepr = C>,
    C: GroupEncoding + Debug,
    S: PrimeField + ScalarOps<Scalar = S>,
{
    /// Create a new builder
    pub fn new(sum_of_products: fn(&[B], &[S]) -> B) -> Self {
        Self {
            points: Vec::new(),
            scalars: Vec::new(),
            sum_of_products,
        }
    }

    /// Add a specified point and generate a random blinding factor
    pub fn commit_random(&mut self, point: B, rng: impl RngCore) {
        self.points.push(point);
        self.scalars.push(S::random(rng));
    }

    /// Commit a specified point with the specified scalar
    pub fn commit(&mut self, point: B, scalar: S) {
        self.points.push(point);
        self.scalars.push(scalar);
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    pub fn add_challenge_contribution(&self, label: &'static [u8], transcript: &mut Transcript) {
        let mut scalars = self.scalars.clone();
        let commitment = (self.sum_of_products)(self.points.as_ref(), scalars.as_mut());
        transcript.append_message(label, commitment.to_affine().to_bytes().as_ref());
    }

    /// Generate the Schnorr challenges given the specified secrets
    /// by computing p = r + c * s
    pub fn generate_proof(&self, challenge: S, secrets: &[S]) -> CredxResult<Vec<S>> {
        Ok(self
            .scalars
            .iter()
            .enumerate()
            .map(|(i, s)| *s + secrets[i] * challenge)
            .collect())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use blsful::inner_types::*;

    #[test]
    fn test_proof_committed_builder() {
        let mut pb = ProofCommittedBuilder::<G1Projective, G1Affine, Scalar>::new(
            G1Projective::sum_of_products,
        );

        let mut transcript = Transcript::new(b"test_proof_committed_builder");
        let challenge = Scalar::from(3);

        pb.commit(G1Projective::IDENTITY, Scalar::from(2));

        pb.add_challenge_contribution(b"test", &mut transcript);
        let proof = pb.generate_proof(challenge, &[Scalar::from(1337)]).unwrap();
        assert!(!proof.is_empty());
    }
}
