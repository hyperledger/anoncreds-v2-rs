use crate::error::Error;
use crate::presentation::{PresentationProofs, PresentationSchema};
use crate::statement::{EqualityStatement, Statements};
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use merlin::Transcript;
use std::collections::BTreeMap;
use yeti::knox::bls12_381_plus::Scalar;

pub struct EqualityVerifier<'a, 'b, 'c> {
    pub statement: &'a EqualityStatement,
    pub schema: &'b PresentationSchema,
    pub proofs: &'c BTreeMap<String, PresentationProofs>,
}

impl<'a, 'b, 'c> ProofVerifier for EqualityVerifier<'a, 'b, 'c> {
    fn add_challenge_contribution(
        &self,
        _challenge: Scalar,
        _transcript: &mut Transcript,
    ) -> CredxResult<()> {
        Ok(())
    }

    fn verify(&self, _challenge: Scalar) -> CredxResult<()> {
        let mut messages = Vec::with_capacity(self.statement.ref_id_claim_index.len());
        for (id, claim_idx) in &self.statement.ref_id_claim_index {
            let proof = self.proofs.get(id).ok_or(Error::InvalidPresentationData)?;
            match proof {
                PresentationProofs::Signature(s) => {
                    match self
                        .schema
                        .statements
                        .get(&s.id)
                        .ok_or(Error::InvalidPresentationData)?
                    {
                        Statements::Signature(sig_st) => {
                            let disclosed_messages: Vec<(usize, Scalar)> = s
                                .disclosed_messages
                                .iter()
                                .map(|(idx, scalar)| (*idx, *scalar))
                                .collect();
                            let hidden_messages = s
                                .pok
                                .get_hidden_message_proofs(
                                    &sig_st.issuer.verifying_key,
                                    disclosed_messages.as_slice(),
                                )
                                .map_err(|_| Error::InvalidPresentationData)?;
                            let hidden_message = hidden_messages
                                .get(claim_idx)
                                .ok_or(Error::InvalidPresentationData)?;
                            messages.push(*hidden_message);
                        }
                        _ => return Err(Error::InvalidPresentationData),
                    };
                }
                _ => return Err(Error::InvalidPresentationData),
            }
        }
        let first = messages.get(0).ok_or(Error::InvalidPresentationData)?;
        for m in &messages[1..] {
            if first != m {
                return Err(Error::InvalidPresentationData);
            }
        }
        Ok(())
    }
}
