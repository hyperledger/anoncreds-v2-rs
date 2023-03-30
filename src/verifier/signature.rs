use crate::error::Error;
use crate::presentation::SignatureProof;
use crate::statement::SignatureStatement;
use crate::verifier::ProofVerifier;
use crate::CredxResult;
use blsful::bls12_381_plus::Scalar;
use merlin::Transcript;

pub struct SignatureVerifier<'a, 'b> {
    statement: &'a SignatureStatement,
    signature_proof: &'b SignatureProof,
    disclosed_messages: Vec<(usize, Scalar)>,
}

impl<'a, 'b> SignatureVerifier<'a, 'b> {
    pub fn new(statement: &'a SignatureStatement, signature_proof: &'b SignatureProof) -> Self {
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

impl<'a, 'b> ProofVerifier for SignatureVerifier<'a, 'b> {
    fn add_challenge_contribution(
        &self,
        challenge: Scalar,
        transcript: &mut Transcript,
    ) -> CredxResult<()> {
        self.signature_proof.pok.add_challenge_contribution(
            &self.statement.issuer.verifying_key,
            &self.disclosed_messages,
            challenge,
            transcript,
        );
        Ok(())
    }

    fn verify(&self, _challenge: Scalar) -> CredxResult<()> {
        if self.signature_proof.pok.verify(
            &self.disclosed_messages,
            &self.statement.issuer.verifying_key,
        ) {
            Ok(())
        } else {
            Err(Error::InvalidSignatureProofData)
        }
    }
}
