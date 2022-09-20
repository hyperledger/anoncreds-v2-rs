use super::SignatureProof;
use crate::presentation::PresentationSchema;
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
    Equality,
}

impl PresentationProofs {
    /// The statement identifier
    pub fn id(&self) -> String {
        match self {
            PresentationProofs::Signature(ss) => ss.id(),
            PresentationProofs::Equality => String::new(),
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
        }
    }

    /// Verify the individual proofs
    pub fn verify(&self, schema: &PresentationSchema) -> CredxResult<()> {
        match self {
            PresentationProofs::Signature(ss) => ss.verify(schema),
        }
    }
}
