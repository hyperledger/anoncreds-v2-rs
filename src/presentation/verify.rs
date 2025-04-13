use super::*;
use crate::knox::short_group_sig_core::short_group_traits::ProofOfSignatureKnowledge;
use std::collections::BTreeMap;

impl<S: ShortGroupSignatureScheme> Presentation<S> {
    /// Verify this presentation
    pub fn verify(&self, schema: &PresentationSchema<S>, nonce: &[u8]) -> CredxResult<()> {
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

        let (signature_statements, predicate_statements) = Self::split_statements(schema);

        let mut verifiers = Vec::<ProofVerifiers<S>>::with_capacity(schema.statements.len());
        for (id, sig_statement) in &signature_statements {
            match (sig_statement, self.proofs.get(*id)) {
                (Statements::Signature(ss), Some(PresentationProofs::Signature(proof))) => {
                    Self::add_disclosed_messages_challenge_contribution(
                        &ss.id,
                        &self.disclosed_messages[&ss.id],
                        &mut transcript,
                    );
                    let verifier = SignatureVerifier::new(ss, proof);
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (Statements::Signature(_), None) => {
                    return Err(Error::InvalidPresentationData(format!(
                        "expected a signature proof for statement '{}', but not proof was found",
                        id
                    )))
                }
                (_, _) => {}
            }
        }

        let mut ranges = Vec::new();
        for (id, pred_statement) in &predicate_statements {
            match (pred_statement, self.proofs.get(*id)) {
                (Statements::Revocation(aa), Some(PresentationProofs::Revocation(proof))) => {
                    let hidden_messages =
                        self.get_sig_hidden_message_proofs(schema, &aa.reference_id)?;
                    let message_proof = hidden_messages
                        .get(&aa.claim)
                        .ok_or(Error::InvalidPresentationData(format!("revocation statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", aa.id, aa.claim)))?;
                    let verifier = RevocationVerifier::new(aa, proof, nonce, *message_proof);
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (Statements::Membership(mm), Some(PresentationProofs::Membership(proof))) => {
                    let hidden_messages =
                        self.get_sig_hidden_message_proofs(schema, &mm.reference_id)?;
                    let message_proof = hidden_messages
                        .get(&mm.claim)
                        .ok_or(Error::InvalidPresentationData(format!("membership statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", mm.id, mm.claim)))?;
                    let verifier = MembershipVerifier::new(mm, proof, nonce, *message_proof);
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (Statements::Equality(statement), Some(PresentationProofs::Equality(_))) => {
                    let verifier = EqualityVerifier {
                        statement,
                        schema,
                        proofs: &self.proofs,
                    };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (
                    Statements::Commitment(statement),
                    Some(PresentationProofs::Commitment(proof)),
                ) => {
                    let hidden_messages =
                        self.get_sig_hidden_message_proofs(schema, &statement.reference_id)?;
                    let message_proof = hidden_messages
                        .get(&statement.claim)
                        .ok_or(Error::InvalidPresentationData(format!("commitment statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", statement.id, statement.claim)))?;
                    let verifier = CommitmentVerifier {
                        statement,
                        proof,
                        message_proof: *message_proof,
                    };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (
                    Statements::VerifiableEncryption(statement),
                    Some(PresentationProofs::VerifiableEncryption(proof)),
                ) => {
                    let hidden_messages =
                        self.get_sig_hidden_message_proofs(schema, &statement.reference_id)?;
                    let message_proof = hidden_messages
                        .get(&statement.claim)
                        .ok_or(Error::InvalidPresentationData(format!("verifiable encryption statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", statement.id, statement.claim)))?;
                    let verifier = VerifiableEncryptionVerifier {
                        statement,
                        proof,
                        message_proof: *message_proof,
                    };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (Statements::Range(statement), Some(PresentationProofs::Range(proof))) => {
                    let cstmt = predicate_statements
                        .get(&statement.reference_id)
                        .ok_or(Error::InvalidPresentationData(format!("range proof statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", statement.id, statement.claim)))?;
                    if let Statements::Commitment(commitment_statement) = cstmt {
                        let cproof = self
                            .proofs
                            .get(&statement.reference_id)
                            .ok_or(Error::InvalidPresentationData(format!("commitment statement with id '{}' does not have an associated commitment proof with id '{}'", commitment_statement.id, statement.reference_id)))?;
                        if let PresentationProofs::Commitment(commitment_proof) = cproof {
                            let verifier = RangeProofVerifier {
                                statement,
                                proof,
                                commitment_statement,
                                commitment: commitment_proof.commitment,
                            };
                            // Can't call add to transcript until all the others are complete
                            ranges.push(verifier);
                        } else {
                            return Err(Error::InvalidPresentationData(format!("range proof statement with id '{}' references a commitment proof that doesn't exist or was not included", statement.id)));
                        }
                    } else {
                        return Err(Error::InvalidPresentationData(format!("range proof statement with id '{}' references a commitment statement that doesn't exist or was not included", statement.id)));
                    }
                }
                (
                    Statements::VerifiableEncryptionDecryption(statement),
                    Some(PresentationProofs::VerifiableEncryptionDecryption(proof)),
                ) => {
                    let hidden_messages =
                        self.get_sig_hidden_message_proofs(schema, &statement.reference_id)?;
                    let message_proof = hidden_messages
                        .get(&statement.claim)
                        .ok_or(Error::InvalidPresentationData(format!("verifiable encryption decryption statement with id '{}' references a claim proof '{}' that doesn't exist or was not included", statement.id, statement.claim)))?;
                    let verifier = VerifiableEncryptionDecryptionVerifier {
                        statement,
                        proof,
                        message_proof: *message_proof,
                    };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (_, _) => {
                    return Err(Error::InvalidPresentationData(format!(
                        "an unknown predicate statement was found in the presentation: {:?}",
                        pred_statement
                    )))
                }
            }
        }
        for range in &ranges {
            range.add_challenge_contribution(self.challenge, &mut transcript)?;
        }

        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        if challenge != self.challenge {
            return Err(Error::InvalidPresentationData(format!("the presentation proof failed, the expected challenge '{}' does not match the computed challenge '{}'", hex::encode(challenge.to_be_bytes()), hex::encode(self.challenge.to_be_bytes()))));
        }

        for verifier in &verifiers {
            verifier.verify(self.challenge)?;
        }
        for verifier in &ranges {
            verifier.verify(self.challenge)?;
        }

        Ok(())
    }

    fn get_sig_hidden_message_proofs(
        &self,
        schema: &PresentationSchema<S>,
        reference_id: &String,
    ) -> CredxResult<BTreeMap<usize, Scalar>> {
        let sig_proof = self
            .proofs
            .get(reference_id)
            .ok_or(Error::InvalidPresentationData(format!("the presentation references a proof with id '{}', but not proof with that id exists or was not included", reference_id)))?;
        match sig_proof {
            PresentationProofs::Signature(s) => {
                match schema
                    .statements
                    .get(&s.id)
                    .ok_or(Error::InvalidPresentationData(format!("signature proof with id '{}' does not have an associated statement", s.id)))?
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
                        Ok(hidden_messages)
                    }
                    st => Err(Error::InvalidPresentationData(format!("signature proof of id '{}' associated statement is not a signature statement: associated statement: {:?}", s.id, st))),
                }
            }
            p => Err(Error::InvalidPresentationData(format!(
                "proof with id '{}' is not a signature proof: proof {:?}",
                reference_id, p
            ))),
        }
    }
}
