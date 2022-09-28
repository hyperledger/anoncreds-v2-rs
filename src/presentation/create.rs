use super::*;

impl Presentation {
    /// Create a new presentation composed of 1 to many proofs
    pub fn create(
        credentials: &BTreeMap<String, Credential>,
        schema: &PresentationSchema,
        nonce: &[u8],
    ) -> CredxResult<Self> {
        let mut rng = OsRng {};
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

        let (signature_statements, predicate_statements) = Self::split_statements(schema);

        if signature_statements.len() != credentials.len() {
            return Err(Error::InvalidPresentationData);
        }

        if signature_statements
            .iter()
            .any(|(k, _)| !credentials.contains_key(k))
        {
            return Err(Error::InvalidPresentationData);
        }

        let messages = Self::get_message_types(
            credentials,
            &signature_statements,
            &predicate_statements,
            &mut rng,
        )?;

        let mut builders = Vec::<PresentationBuilders>::with_capacity(schema.statements.len());
        let mut disclosed_messages = BTreeMap::new();

        for (id, sig_statement) in &signature_statements {
            if let Statements::Signature(ss) = sig_statement {
                let mut dm = BTreeMap::new();
                for (index, claim) in credentials[id].claims.iter().enumerate() {
                    if matches!(messages[id][index], ProofMessage::Revealed(_)) {
                        let (label, _) = ss
                            .issuer
                            .schema
                            .claim_indices
                            .iter()
                            .find(|(_, v)| **v == index)
                            .unwrap();
                        dm.insert(label.clone(), claim.clone());
                    }
                }
                Self::add_disclosed_messages_challenge_contribution(id, &dm, &mut transcript);
                let builder = SignatureBuilder::commit(
                    ss,
                    credentials[id].signature,
                    &messages[id],
                    &mut rng,
                    &mut transcript,
                )?;
                builders.push(builder.into());
                disclosed_messages.insert(id.clone(), dm);
            }
        }

        let mut id_to_builder = BTreeMap::new();
        let mut range_id = BTreeSet::new();
        for (id, pred_statement) in &predicate_statements {
            match pred_statement {
                Statements::Equality(e) => {
                    let builder = EqualityBuilder::commit(e, credentials)?;
                    id_to_builder.insert(id, builders.len());
                    builders.push(builder.into());
                }
                Statements::AccumulatorSetMembership(a) => {
                    let proof_message = messages[&a.reference_id][a.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData);
                    }
                    let credential = &credentials[&a.reference_id];
                    let builder = AccumulatorSetMembershipProofBuilder::commit(
                        a,
                        credential,
                        proof_message,
                        nonce,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Commitment(c) => {
                    let proof_message = messages[&c.reference_id][c.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData);
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(&mut rng).unwrap();
                    let builder =
                        CommitmentBuilder::commit(c, message, blinder, &mut rng, &mut transcript)?;
                    id_to_builder.insert(id, builders.len());
                    builders.push(builder.into());
                }
                Statements::VerifiableEncryption(v) => {
                    let proof_message = messages[&v.reference_id][v.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData);
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(&mut rng).unwrap();
                    let builder = VerifiableEncryptionBuilder::commit(
                        v,
                        message,
                        blinder,
                        &mut rng,
                        &mut transcript,
                    )?;
                    id_to_builder.insert(id, builders.len());
                    builders.push(builder.into());
                }
                Statements::Range(_) => {
                    // handle after these since they depend on commitment builders
                    range_id.insert(id);
                }
                Statements::Signature(_) => {}
            }
        }
        let mut range_builders = Vec::<PresentationBuilders>::with_capacity(range_id.len());
        for id in range_id {
            if let Statements::Range(r) = predicate_statements
                .get(id)
                .ok_or(Error::InvalidPresentationData)?
            {
                let sig = credentials
                    .get(&r.signature_id)
                    .ok_or(Error::InvalidPresentationData)?;
                if let PresentationBuilders::Commitment(commitment) = &builders[id_to_builder[id]] {
                    if let ClaimData::Number(n) = sig
                        .claims
                        .get(r.claim)
                        .ok_or(Error::InvalidPresentationData)?
                    {
                        let builder =
                            RangeBuilder::commit(r, commitment, n.value, &mut transcript)?;
                        range_builders.push(builder.into());
                    } else {
                        return Err(Error::InvalidPresentationData);
                    }
                } else {
                    return Err(Error::InvalidPresentationData);
                }
            }
        }
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        let mut proofs = BTreeMap::new();

        for builder in range_builders.into_iter() {
            let proof = builder.gen_proof(challenge);
            proofs.insert(proof.id().clone(), proof);
        }
        for builder in builders.into_iter() {
            let proof = builder.gen_proof(challenge);
            proofs.insert(proof.id().clone(), proof);
        }

        Ok(Self {
            proofs,
            challenge,
            disclosed_messages,
        })
    }
}