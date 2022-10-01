use super::*;
use crate::statement::SignatureStatement;
use crate::{error::Error, CredxResult};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yeti::knox::{
    bls12_381_plus::Scalar,
    ps::{PokSignature, PokSignatureProof, Signature as PsSignature},
    short_group_sig_core::ProofMessage,
};

/// A builder for creating signature presentations
pub(crate) struct SignatureBuilder<'a> {
    /// The statement identifier
    id: &'a String,
    /// The messages that belong to this signature
    disclosed_messages: BTreeMap<usize, Scalar>,
    /// The signature proof of knowledge builder
    pok_sig: PokSignature,
}

impl<'a> PresentationBuilder for SignatureBuilder<'a> {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        // PS signature generate_proof can't fail, okay to unwrap
        PresentationProofs::Signature(SignatureProof {
            id: self.id.clone(),
            disclosed_messages: self.disclosed_messages,
            pok: self.pok_sig.generate_proof(challenge).unwrap(),
        })
    }
}

impl<'a> SignatureBuilder<'a> {
    /// Create a new signature builder
    pub fn commit(
        statement: &'a SignatureStatement,
        signature: PsSignature,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
        transcript: &mut Transcript,
    ) -> CredxResult<Self> {
        match PokSignature::init(signature, &statement.issuer.verifying_key, messages, rng) {
            Err(_) => Err(Error::InvalidSignatureProofData),
            Ok(mut poksig) => {
                let disclosed_messages = messages
                    .iter()
                    .enumerate()
                    .filter(|(_i, m)| matches!(m, ProofMessage::Revealed(_)))
                    .map(|(i, m)| (i, m.get_message()))
                    .collect::<BTreeMap<usize, Scalar>>();

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
pub struct SignatureProof {
    /// The statement identifier
    pub id: String,
    /// The disclosed message scalars
    pub disclosed_messages: BTreeMap<usize, Scalar>,
    /// The proof
    pub pok: PokSignatureProof,
}

impl Into<PresentationProofs> for SignatureProof {
    fn into(self) -> PresentationProofs {
        PresentationProofs::Signature(self)
    }
}
