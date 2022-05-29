mod ps;
mod r#type;

pub use ps::*;
pub use r#type::*;

use crate::presentation::{PresentationProof, PresentationSchema};
use yeti::knox::bls12_381_plus::Scalar;

/// Statement methods
pub trait Statement {
    /// The returned proof value
    type ProofValue: PresentationProof;

    /// Return this statement unique identifier
    fn id(&self) -> String;
    /// Commit the blinded values and the challenge contributions
    fn commit(&self, schema: &PresentationSchema, transcript: &mut merlin::Transcript);
    /// Finalize proofs
    fn gen_proof(&self, challenge: Scalar) -> Self::ProofValue;
}
