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

#[derive(Debug)]
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
            let proof = self
                .proofs
                .get(id)
                .ok_or(Error::InvalidPresentationData(format!(
                    "no presentation proof exists with id '{}': equality_verifier: {:?}",
                    id, self
                )))?;
            match proof {
                PresentationProofs::Signature(s) => {
                    match self
                        .schema
                        .statements
                        .get(&s.id)
                        .ok_or(Error::InvalidPresentationData(format!("no statement with id '{}' is found in the presentation schema: equality_verifier: {:?}", s.id, self)))?
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
                                )?;
                            let hidden_message = hidden_messages
                                .get(claim_idx)
                                .ok_or(Error::InvalidPresentationData(format!("the referenced claim_idx '{}' from in the equality proof statement '{}' does not exist in the signature statement: equality_verifier: {:?}", claim_idx, id, self)))?;
                            messages.push(*hidden_message);
                        }
                        _ => return Err(Error::InvalidPresentationData(format!("tried to use a non-signature statement reference in an equality proof: equality_verifier: {:?}", self))),
                    };
                }
                _ => return Err(Error::InvalidPresentationData(format!("tried to use a non-signature proof in an equality proof using reference statement id '{}': equality_verifier: {:?}", id, self))),
            }
        }
        let first = messages
            .first()
            .ok_or(Error::InvalidPresentationData(format!(
                "must have at least one claim in an equality proof: equality_verifier: {:?}",
                self
            )))?;
        for (i, m) in messages.iter().enumerate().skip(1) {
            if first != m {
                return Err(Error::InvalidPresentationData(format!("not all of the claims in the equality proof are equal, the first claim at index 0 is {} and the current claim at index {} is {}: equality_verifier: {:?}", hex::encode(first.to_be_bytes()), i, hex::encode(m.to_be_bytes()), self)));
            }
        }
        Ok(())
    }
}
