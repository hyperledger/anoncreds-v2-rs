use crate::credential::Credential;
use crate::knox::accumulator::vb20::{
    Element, MembershipProof, MembershipProofCommitting, ProofParams,
};
use crate::knox::short_group_sig_core::ProofMessage;
use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::RevocationStatement;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub(crate) struct RevocationProofBuilder<'a> {
    id: &'a String,
    committing: MembershipProofCommitting,
}

impl<'a> PresentationBuilder for RevocationProofBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let proof = self.committing.gen_proof(Element(challenge));
        RevocationProof {
            id: self.id.clone(),
            proof,
        }
        .into()
    }
}

impl<'a> RevocationProofBuilder<'a> {
    /// Create a new accumulator set membership proof builder
    pub fn commit(
        statement: &'a RevocationStatement,
        credential: &Credential,
        message: ProofMessage<Scalar>,
        nonce: &[u8],
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        let params = ProofParams::new(statement.verification_key, Some(nonce));
        let committing = MembershipProofCommitting::new(
            message,
            credential.revocation_handle,
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
pub struct RevocationProof {
    /// The statement identifier
    pub id: String,
    /// The membership proof
    pub proof: MembershipProof,
}
