use super::*;
use crate::knox::short_group_sig_core::short_group_traits::{
    ProofOfSignatureKnowledgeContribution, ShortGroupSignatureScheme,
};
use crate::knox::short_group_sig_core::ProofMessage;
use crate::statement::SignatureStatement;
use crate::{error::Error, utils::*, CredxResult};
use blsful::inner_types::Scalar;
use indexmap::IndexMap;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A builder for creating signature presentations
pub(crate) struct SignatureBuilder<'a, S: ShortGroupSignatureScheme> {
    /// The statement identifier
    id: &'a String,
    /// The messages that belong to this signature
    disclosed_messages: IndexMap<usize, Scalar>,
    /// The signature proof of knowledge builder
    pok_sig: S::ProofOfSignatureKnowledgeContribution,
}

impl<S: ShortGroupSignatureScheme> PresentationBuilder<S> for SignatureBuilder<'_, S> {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs<S> {
        // PS signature generate_proof can't fail, okay to unwrap
        SignatureProof {
            id: self.id.clone(),
            disclosed_messages: self.disclosed_messages,
            pok: self.pok_sig.generate_proof(challenge).unwrap(),
        }
        .into()
    }
}

impl<'a, S: ShortGroupSignatureScheme> SignatureBuilder<'a, S> {
    /// Create a new signature builder
    pub fn commit(
        statement: &'a SignatureStatement<S>,
        signature: &S::Signature,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        match S::ProofOfSignatureKnowledgeContribution::commit(
            signature,
            &statement.issuer.verifying_key,
            messages,
            rng,
        ) {
            Err(_) => Err(Error::InvalidSignatureProofData),
            Ok(poksig) => {
                let disclosed_messages = messages
                    .iter()
                    .enumerate()
                    .filter(|(_i, m)| matches!(m, ProofMessage::Revealed(_)))
                    .map(|(i, m)| (i, m.get_message()))
                    .collect::<IndexMap<usize, Scalar>>();

                poksig.add_proof_contribution(transcript);

                Ok(Self {
                    id: &statement.id,
                    disclosed_messages,
                    pok_sig: poksig,
                })
            }
        }
    }
}

/// A signature proof that can be presented
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureProof<S: ShortGroupSignatureScheme> {
    /// The statement identifier
    pub id: String,
    /// The disclosed message scalars
    #[serde(
        serialize_with = "serialize_indexmap",
        deserialize_with = "deserialize_indexmap"
    )]
    pub disclosed_messages: IndexMap<usize, Scalar>,
    /// The proof
    pub pok: S::ProofOfSignatureKnowledge,
}
