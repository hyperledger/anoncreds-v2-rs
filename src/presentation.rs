mod proof;
mod schema;
mod signature;

pub use proof::*;
pub use schema::*;
pub use signature::*;

use yeti::knox::bls12_381_plus::Scalar;

/// Implementers can build proofs for presentations
pub trait PresentationBuilder {
    /// The returned proof value
    type ProofValue: PresentationProof;

    /// Finalize proofs
    fn gen_proof(&self, challenge: Scalar) -> Self::ProofValue;
}
