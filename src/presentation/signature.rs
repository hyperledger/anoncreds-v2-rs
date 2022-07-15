use super::*;
use crate::{error::Error, uint::Uint, CredxResult};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yeti::knox::{
    bls12_381_plus::Scalar,
    ps::{PokSignature, PokSignatureProof, Signature as PsSignature},
    short_group_sig_core::ProofMessage,
};

/// A builder for creating signature presentations
pub struct SignatureBuilder {
    /// The statement identifier
    id: String,
    /// The messages that belong to this signature
    disclosed_messages: BTreeMap<usize, Scalar>,
    /// The signature proof of knowledge builder
    pok_sig: PokSignature,
}

impl PresentationBuilder for SignatureBuilder {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        // PS signature generate_proof can't fail, okay to unwrap
        PresentationProofs::Signature(SignatureProof {
            id: self.id,
            disclosed_messages: self.disclosed_messages,
            pok: self.pok_sig.generate_proof(challenge).unwrap(),
        })
    }
}

impl SignatureBuilder {
    /// Create a new signature builder
    pub fn commit(
        statement: &crate::statement::SignatureStatement,
        signature: PsSignature,
        messages: &[ProofMessage<Scalar>],
        rng: impl RngCore + CryptoRng,
        transcript: &mut merlin::Transcript,
    ) -> CredxResult<Self> {
        match PokSignature::init(signature, &statement.issuer.verifying_key, messages, rng) {
            Err(_) => Err(Error::InvalidSignatureProofData),
            Ok(mut poksig) => {
                let disclosed_messages = messages
                    .iter()
                    .enumerate()
                    .filter(|(_i, m)|  matches!(m, ProofMessage::Revealed(_)))
                    .map(|(i, m)| (i, m.get_message()))
                    .collect::<BTreeMap<usize, Scalar>>();
                let idx_to_label: BTreeMap<usize, String> = statement
                    .issuer
                    .schema
                    .claim_indices
                    .iter()
                    .map(|(k, v)| (*v, k.clone()))
                    .collect();

                // Add the disclosed messages to the transcript
                transcript.append_message(
                    b"disclosed messages length",
                    &Uint::from(disclosed_messages.len()).bytes(),
                );
                for (i, m) in &disclosed_messages {
                    transcript.append_message(b"disclosed message index", &Uint::from(*i).bytes());
                    transcript
                        .append_message(b"disclosed message label", idx_to_label[i].as_bytes());
                    transcript.append_message(b"disclosed message value", &m.to_bytes());
                }
                poksig.add_proof_contribution(transcript);

                Ok(Self {
                    id: statement.id.clone(),
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

impl PresentationProof for SignatureProof {
    fn id(&self) -> String {
        self.id.clone()
    }

    /// Recreate the proof contributions for schnorr proofs
    fn get_proof_contribution(
        &self,
        _challenge: Scalar,
        _schema: &PresentationSchema,
        _transcript: &mut merlin::Transcript,
    ) {
        todo!();
    }

    /// Verify this proof if separate from schnorr
    fn verify(&self, _schema: &PresentationSchema) -> CredxResult<()> {
        Ok(())
    }
}
