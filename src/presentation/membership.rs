use crate::prelude::MembershipCredential;
use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::MembershipStatement;
use crate::CredxResult;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use crate::knox::accumulator::vb20::{
    Element, MembershipProof as Vb20MembershipProof, MembershipProofCommitting, ProofParams,
};
use signature_bls::bls12_381_plus::Scalar;
use crate::knox::short_group_sig_core::ProofMessage;

pub(crate) struct MembershipProofBuilder<'a> {
    id: &'a String,
    committing: MembershipProofCommitting,
}

impl<'a> PresentationBuilder for MembershipProofBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let proof = self.committing.gen_proof(Element(challenge));
        MembershipProof {
            id: self.id.clone(),
            proof,
        }
        .into()
    }
}

impl<'a> MembershipProofBuilder<'a> {
    /// Create a new accumulator set membership proof builder
    pub fn commit(
        statement: &'a MembershipStatement,
        credential: &MembershipCredential,
        message: ProofMessage<Scalar>,
        nonce: &[u8],
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let params = ProofParams::new(statement.verification_key, Some(nonce));
        let committing = MembershipProofCommitting::new(
            message,
            *credential,
            params,
            statement.verification_key,
        );
        params.add_to_transcript(transcript);
        committing.get_bytes_for_challenge(transcript);
        Ok(Self {
            id: &statement.id,
            committing,
        })
    }
}

/// A membership proof based on accumulators
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MembershipProof {
    /// The statement identifier
    pub id: String,
    /// The membership proof
    pub proof: Vb20MembershipProof,
}
