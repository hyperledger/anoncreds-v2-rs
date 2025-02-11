use crate::error::Error;
use crate::knox::short_group_sig_core::short_group_traits::{
    ProofOfSignatureKnowledge, ShortGroupSignatureScheme,
};
use crate::presentation::{PresentationProofs, PresentationSchema};
use crate::statement::{EqualityStatement, Statements};
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use indexmap::IndexMap;
use merlin::Transcript;

pub struct EqualityVerifier<'a, 'b, 'c, S: ShortGroupSignatureScheme> {
    pub statement: &'a EqualityStatement,
    pub schema: &'b PresentationSchema<S>,
    pub proofs: &'c IndexMap<String, PresentationProofs<S>>,
}

impl<S: ShortGroupSignatureScheme> ProofVerifier for EqualityVerifier<'_, '_, '_, S> {
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
        let first = messages.first().ok_or(Error::InvalidPresentationData)?;
        for m in &messages[1..] {
            if first != m {
                return Err(Error::InvalidPresentationData);
            }
        }
        Ok(())
    }
}
