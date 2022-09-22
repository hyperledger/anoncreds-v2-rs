use super::SignatureProof;
use crate::presentation::{
    AccumulatorSetMembershipProof, CommitmentProof, EqualityProof, PresentationSchema,
};
use crate::CredxResult;
use yeti::knox::bls12_381_plus::Scalar;

/// The methods for proofs given in the presentation
pub trait PresentationProof {
    /// Get the statement identifier for this proof
    fn id(&self) -> String;
    /// Recreate the proof contributions for schnorr proofs
    fn get_proof_contribution(
        &self,
        challenge: Scalar,
        schema: &PresentationSchema,
        transcript: &mut merlin::Transcript,
    );
    /// Verify this proof if separate from schnorr
    fn verify(&self, schema: &PresentationSchema) -> CredxResult<()>;
}

/// The types of presentation proofs
#[derive(Clone, Debug)]
pub enum PresentationProofs {
    /// Signature proofs of knowledge
    Signature(SignatureProof),
    /// Accumulator set membership proof
    AccumulatorSetMembership(AccumulatorSetMembershipProof),
    /// Equality proof
    Equality(EqualityProof),
    /// Commitment proof
    Commitment(CommitmentProof),
    /// Verifiable Encryption proof
    VerifiableEncryption,
}

impl PresentationProofs {
    /// The statement identifier
    pub fn id(&self) -> String {
        match self {
            PresentationProofs::Signature(ss) => ss.id(),
            PresentationProofs::Equality(e) => e.id(),
            PresentationProofs::AccumulatorSetMembership(a) => a.id(),
            PresentationProofs::Commitment(c) => c.id(),
            PresentationProofs::VerifiableEncryption => todo!(),
        }
    }

    /// Get the proof contribution for the schnorr proof verification
    pub fn get_proof_contribution(
        &self,
        challenge: Scalar,
        schema: &PresentationSchema,
        transcript: &mut merlin::Transcript,
    ) {
        match self {
            PresentationProofs::Signature(ss) => {
                ss.get_proof_contribution(challenge, schema, transcript)
            }
            PresentationProofs::Equality(e) => {
                e.get_proof_contribution(challenge, schema, transcript)
            }
            PresentationProofs::AccumulatorSetMembership(a) => {
                a.get_proof_contribution(challenge, schema, transcript);
            }
            PresentationProofs::Commitment(c) => {
                c.get_proof_contribution(challenge, schema, transcript)
            }
            PresentationProofs::VerifiableEncryption => todo!(),
        }
    }

    /// Verify the individual proofs
    pub fn verify(&self, schema: &PresentationSchema) -> CredxResult<()> {
        match self {
            PresentationProofs::Signature(ss) => ss.verify(schema),
            PresentationProofs::Equality(e) => e.verify(schema),
            PresentationProofs::AccumulatorSetMembership(a) => a.verify(schema),
            PresentationProofs::Commitment(c) => c.verify(schema),
            PresentationProofs::VerifiableEncryption => todo!(),
        }
    }
}
