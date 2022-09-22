use crate::claim::ClaimData;
use crate::presentation::SignatureProof;
use crate::statement::SignatureStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use merlin::Transcript;
use std::collections::BTreeMap;
use yeti::knox::bls12_381_plus::Scalar;

#[derive(Clone, Debug)]
pub struct SignatureVerifier<'a, 'b, 'c> {
    pub statement: &'a SignatureStatement,
    pub signature_proof: &'b SignatureProof,
    pub disclosed_messages: &'c BTreeMap<String, ClaimData>,
}

impl<'a, 'b, 'c> ProofVerifier for SignatureVerifier<'a, 'b, 'c> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        let disclosed: Vec<(usize, Scalar)> = self
            .signature_proof
            .disclosed_messages
            .iter()
            .map(|(idx, sc)| (*idx, *sc))
            .collect();
        self.signature_proof.pok.add_challenge_contribution(
            &self.statement.issuer.verifying_key,
            &disclosed,
            challenge,
            transcript,
        );
        Ok(())
    }

    fn verify(&self, challenge: Scalar, transcript: &mut Transcript) -> CredxResult<()> {
        todo!()
    }
}
