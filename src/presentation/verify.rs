use super::*;

impl Presentation {
    /// Verify this presentation
    pub fn verify(&self, schema: &PresentationSchema, nonce: &[u8]) -> CredxResult<()> {
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

        let (signature_statements, predicate_statements) = Self::split_statements(schema);

        let mut verifiers = Vec::<ProofVerifiers>::with_capacity(schema.statements.len());
        for (id, sig_statement) in &signature_statements {
            match (sig_statement, self.proofs.get(id)) {
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
                (Statements::Signature(_), None) => return Err(Error::InvalidPresentationData),
                (_, _) => {}
            }
        }

        let mut ranges = Vec::new();
        for (id, pred_statement) in &predicate_statements {
            match (pred_statement, self.proofs.get(id)) {
                (
                    Statements::AccumulatorSetMembership(aa),
                    Some(PresentationProofs::AccumulatorSetMembership(proof)),
                ) => {
                    let verifier = AccumulatorSetMembershipVerifier::new(aa, proof, nonce);
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
                    let verifier = CommitmentVerifier { statement, proof };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (
                    Statements::VerifiableEncryption(statement),
                    Some(PresentationProofs::VerifiableEncryption(proof)),
                ) => {
                    let verifier = VerifiableEncryptionVerifier { statement, proof };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(verifier.into());
                }
                (Statements::Range(statement), Some(PresentationProofs::Range(proof))) => {
                    let cstmt = predicate_statements
                        .get(&statement.reference_id)
                        .ok_or(Error::InvalidPresentationData)?;
                    if let Statements::Commitment(commitment_statement) = cstmt {
                        let cproof = self
                            .proofs
                            .get(&statement.reference_id)
                            .ok_or(Error::InvalidPresentationData)?;
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
                            return Err(Error::InvalidPresentationData);
                        }
                    } else {
                        return Err(Error::InvalidPresentationData);
                    }
                }
                (_, _) => return Err(Error::InvalidPresentationData),
            }
        }
        for range in &ranges {
            range.add_challenge_contribution(self.challenge, &mut transcript)?;
        }

        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        if challenge != self.challenge {
            return Err(Error::InvalidPresentationData);
        }

        for verifier in &verifiers {
            verifier.verify(self.challenge)?;
        }
        for verifier in &ranges {
            verifier.verify(self.challenge)?;
        }

        Ok(())
    }
}
