use crate::credential::Credential;
use crate::presentation::{PresentationBuilder, PresentationProofs};
use crate::statement::AccumulatorSetMembershipStatement;
use crate::{error::Error, CredxResult};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use yeti::knox::accumulator::vb20::{
    Element, MembershipProof, MembershipProofCommitting, ProofParams,
};
use yeti::knox::bls12_381_plus::Scalar;
use yeti::knox::short_group_sig_core::ProofMessage;

pub(crate) struct AccumulatorSetMembershipProofBuilder<'a> {
    id: &'a String,
    committing: MembershipProofCommitting,
}

impl<'a> PresentationBuilder for AccumulatorSetMembershipProofBuilder<'a> {
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        let proof = self.committing.gen_proof(Element(challenge));
        AccumulatorSetMembershipProof {
            id: self.id.clone(),
            proof,
        }
        .into()
    }
}

impl<'a> AccumulatorSetMembershipProofBuilder<'a> {
    /// Create a new accumulator set membership proof builder
    pub fn commit(
        statement: &'a AccumulatorSetMembershipStatement,
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
pub struct AccumulatorSetMembershipProof {
    /// The statement identifier
    pub id: String,
    /// The membership proof
    pub proof: MembershipProof,
}

impl From<AccumulatorSetMembershipProof> for AccumulatorSetMembershipProofText {
    fn from(p: AccumulatorSetMembershipProof) -> Self {
        Self::from(&p)
    }
}

impl From<&AccumulatorSetMembershipProof> for AccumulatorSetMembershipProofText {
    fn from(p: &AccumulatorSetMembershipProof) -> Self {
        Self {
            id: p.id.clone(),
            proof: hex::encode(p.proof.to_bytes()),
        }
    }
}

/// A membership proof in a text friendly format
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccumulatorSetMembershipProofText {
    /// The statement identifier
    pub id: String,
    /// The membership proof
    pub proof: String,
}

impl TryFrom<AccumulatorSetMembershipProofText> for AccumulatorSetMembershipProof {
    type Error = Error;

    fn try_from(value: AccumulatorSetMembershipProofText) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&AccumulatorSetMembershipProofText> for AccumulatorSetMembershipProof {
    type Error = Error;

    fn try_from(value: &AccumulatorSetMembershipProofText) -> Result<Self, Self::Error> {
        let mut input = [0u8; MembershipProof::BYTES];
        let proof_bytes = hex::decode(&value.proof).map_err(|_| Error::DeserializationError)?;
        input.copy_from_slice(&proof_bytes);
        let proof = MembershipProof::from_bytes(&input).map_err(|_| Error::DeserializationError)?;
        Ok(Self {
            id: value.id.clone(),
            proof,
        })
    }
}
