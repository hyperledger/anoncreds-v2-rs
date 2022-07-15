use super::*;
use crate::{
    CredxResult,
    uint::Uint,
    error::Error,
    issuer::IssuerPublic,
};
use std::collections::BTreeMap;
use rand::{RngCore, CryptoRng};
use yeti::knox::{
    bls12_381_plus::Scalar,
    ps::{PokSignature, Signature as PsSignature},
    short_group_sig_core::ProofMessage,
};

/// A builder for creating signature presentations
pub struct SignatureBuilder {
    /// The statement identifier
    id: String,
    /// The messages that belong to this signature
    messages: Vec<ProofMessage<Scalar>>,
    /// The signature proof of knowledge builder
    poksig: PokSignature,
    /// The issuer information
    issuer: IssuerPublic,
}

impl PresentationBuilder for SignatureBuilder {
    /// The returned proof value
    type ProofValue = SignatureProof;

    /// Finalize proofs
    fn gen_proof(&self, challenge: Scalar) -> Self::ProofValue {
        SignatureProof {}
    }
}

impl SignatureBuilder {
    /// Create a new signature builder
    pub fn commit(statement: &crate::statement::SignatureStatement, signature: PsSignature, messages: &[ProofMessage<Scalar>], mut rng: impl RngCore + CryptoRng, transcript: &mut merlin::Transcript) -> CredxResult<Self> {
        match PokSignature::init(signature, &statement.issuer.verifying_key, messages, rng) {
            Err(_) => Err(Error::InvalidSignatureProofData),
            Ok(poksig) => {
                let disclosed_messages = messages.iter().enumerate()
                    .filter(|(_i, m)| {
                    match m {
                        ProofMessage::Revealed(_) => true,
                        _ => false,
                    }
                }).map(|(i, m)| (i, m.get_message())).collect::<BTreeMap<usize, Scalar>>();
                transcript.append_message(b"disclosed messages length", &Uint::from(disclosed_messages.len()).bytes());
                for (i, m) in &disclosed_messages {

                }

                Ok(Self {
                    id: statement.id.clone(),
                    messages: messages.to_vec(),
                    poksig,
                    issuer: statement.issuer.clone(),
                })
            }
        }
    }
}

/// A signature proof that can be presented
#[derive(Clone, Debug)]
pub struct SignatureProof {

}

impl PresentationProof for SignatureProof {
    /// Recreate the proof contributions for schnorr proofs
    fn get_proof_contribution(
        &self,
        schema: &PresentationSchema,
        transcript: &mut merlin::Transcript,
    ) {

    }

    /// Verify this proof if separate from schnorr
    fn verify(&self, schema: &PresentationSchema) -> CredxResult<()> {
        Ok(())
    }
}