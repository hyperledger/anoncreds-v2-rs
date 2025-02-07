use crate::knox::short_group_sig_core::short_group_traits::{
    ProofOfSignatureKnowledge, ShortGroupSignatureScheme,
};
use crate::presentation::SignatureProof;
use crate::statement::SignatureStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::inner_types::Scalar;
use merlin::Transcript;

pub struct SignatureVerifier<'a, 'b, S: ShortGroupSignatureScheme> {
    statement: &'a SignatureStatement<S>,
    signature_proof: &'b SignatureProof<S>,
    disclosed_messages: Vec<(usize, Scalar)>,
}

impl<'a, 'b, S: ShortGroupSignatureScheme> SignatureVerifier<'a, 'b, S> {
    pub fn new(
        statement: &'a SignatureStatement<S>,
        signature_proof: &'b SignatureProof<S>,
    ) -> Self {
        let disclosed_messages: Vec<(usize, Scalar)> = signature_proof
            .disclosed_messages
            .iter()
            .map(|(idx, sc)| (*idx, *sc))
            .collect();
        Self {
            statement,
            signature_proof,
            disclosed_messages,
        }
    }
}

impl<S: ShortGroupSignatureScheme> ProofVerifier for SignatureVerifier<'_, '_, S> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        self.signature_proof.pok.add_proof_contribution(
            &self.statement.issuer.verifying_key,
            &self.disclosed_messages,
            challenge,
            transcript,
        );
        Ok(())
    }

    fn verify(&self, challenge: Scalar) -> CredxResult<()> {
        self.signature_proof.pok.verify(
            &self.statement.issuer.verifying_key,
            &self.disclosed_messages,
            challenge,
        )
    }
}
