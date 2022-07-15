mod proof;
mod schema;
mod signature;

pub use proof::*;
pub use schema::*;
pub use signature::*;

use crate::{claim::ClaimData, credential::Credential, error::Error, CredxResult};
use group::ff::Field;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use crate::statement::{StatementType, Statements};
use yeti::knox::bls12_381_plus::Scalar;
use yeti::knox::short_group_sig_core::{HiddenMessage, ProofMessage};

/// Implementers can build proofs for presentations
pub trait PresentationBuilder {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs;
}

/// Defines the proofs for a verifier
#[derive(Clone, Debug)]
pub struct Presentation {
    /// The proofs
    pub proofs: BTreeMap<String, PresentationProofs>,
    /// The fiat-shamir hash
    pub challenge: Scalar,
    /// The disclosed messages
    pub disclosed_messages: BTreeMap<String, BTreeMap<String, ClaimData>>,
}

impl Presentation {
    /// Create a new presentation composed of 1 to many proofs
    pub fn create(
        credentials: &BTreeMap<String, Credential>,
        schema: &PresentationSchema,
        nonce: &[u8],
        mut rng: impl RngCore + CryptoRng,
        transcript: &mut merlin::Transcript,
    ) -> CredxResult<Self> {
        let mut signature_statements: BTreeMap<String, &Statements> = BTreeMap::new();
        let mut predicate_statements: BTreeMap<String, &Statements> = BTreeMap::new();

        for (id, statement) in &schema.statements {
            match statement.r#type() {
                StatementType::PS | StatementType::BBS => {
                    signature_statements.insert(id.clone(), statement)
                }
                _ => predicate_statements.insert(id.clone(), statement),
            };
        }

        if signature_statements.len() != credentials.len() {
            return Err(Error::InvalidPresentationData);
        }

        if signature_statements
            .iter()
            .any(|(k, _)| !credentials.contains_key(k))
        {
            return Err(Error::InvalidPresentationData);
        }

        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(transcript);

        let messages = Self::get_message_types(
            credentials,
            &signature_statements,
            &predicate_statements,
            &mut rng,
        )?;

        let mut builders = Vec::with_capacity(schema.statements.len());
        let mut id_to_builder: BTreeMap<String, usize> = BTreeMap::new();
        let mut current = 0;
        let mut disclosed_messages = BTreeMap::new();

        for (id, sig_statement) in &signature_statements {
            match sig_statement {
                Statements::Signature(ss) => {
                    let builder = SignatureBuilder::commit(
                        ss,
                        credentials[id].signature,
                        &messages[id],
                        &mut rng,
                        transcript,
                    )?;
                    builders.push(builder);
                    id_to_builder.insert(id.clone(), current);
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
                    disclosed_messages.insert(id.clone(), dm);
                }
            }
            current += 1;
        }

        for (_id, pred_statement) in &predicate_statements {
            match pred_statement {
                _ => return Err(Error::InvalidPresentationData),
            }
            current += 1;
        }
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        let mut proofs = BTreeMap::new();

        for builder in builders.into_iter() {
            let proof = builder.gen_proof(challenge);
            proofs.insert(proof.id(), proof);
        }

        Ok(Self {
            proofs,
            challenge,
            disclosed_messages,
        })
    }

    /// Map the claims to the respective types
    fn get_message_types(
        credentials: &BTreeMap<String, Credential>,
        signature_statements: &BTreeMap<String, &Statements>,
        predicate_statements: &BTreeMap<String, &Statements>,
        mut rng: impl RngCore + CryptoRng,
    ) -> CredxResult<BTreeMap<String, Vec<ProofMessage<Scalar>>>> {
        let mut shared_proof_msg_indices: BTreeMap<String, BTreeMap<usize, bool>> = BTreeMap::new();

        for (id, cred) in credentials {
            let mut indexer = BTreeMap::new();
            for i in 0..cred.claims.len() {
                indexer.insert(i, false);
            }
            shared_proof_msg_indices.insert(id.clone(), indexer);
        }

        let mut same_proof_messages = Vec::new();

        let mut proof_messages: BTreeMap<String, Vec<ProofMessage<Scalar>>> = BTreeMap::new();

        // If a claim is used in a statement, it is a shared message between the signature
        // and the statement. Equality statements are shared across signatures
        for statement in predicate_statements.values() {
            let reference_ids = statement.reference_ids();
            if reference_ids.len() > 1 {
                same_proof_messages.push((*statement).clone());
            }

            for ref_id in &reference_ids {
                match shared_proof_msg_indices.get_mut(ref_id) {
                    None => {
                        // Does this statement reference another statement instead of a signature
                        if !predicate_statements.contains_key(ref_id) {
                            // If not, then error
                            return Err(Error::InvalidPresentationData);
                        }
                        continue;
                    }
                    Some(indexer) => {
                        let claim_index = statement.get_claim_index(ref_id);
                        match indexer.get_mut(&claim_index) {
                            None => return Err(Error::InvalidPresentationData),
                            Some(v) => *v = true,
                        }
                    }
                }
            }
        }

        for (id, sig) in signature_statements {
            let signature = &credentials[id];
            let mut proof_claims = Vec::with_capacity(signature.claims.len());

            for (index, claim) in signature.claims.iter().enumerate() {
                let claim_value = claim.to_scalar();

                // If the claim is not disclosed and used in a statement,
                // it must use a shared blinder, otherwise its proof specific
                match sig {
                    Statements::Signature(ss) => {
                        let (claim_label, _) = ss
                            .issuer
                            .schema
                            .claim_indices
                            .iter()
                            .find(|(_, i)| index == **i)
                            .unwrap();
                        if ss.disclosed.contains(claim_label) {
                            proof_claims.push(ProofMessage::Revealed(claim_value));
                        } else if shared_proof_msg_indices[id][&index] {
                            let blinder = Scalar::random(&mut rng);
                            proof_claims.push(ProofMessage::Hidden(
                                HiddenMessage::ExternalBlinding(claim_value, blinder),
                            ));
                        } else {
                            proof_claims.push(ProofMessage::Hidden(
                                HiddenMessage::ProofSpecificBlinding(claim_value),
                            ));
                        }
                    }
                }
            }
            proof_messages.insert(id.clone(), proof_claims);
        }

        for statement in &same_proof_messages {
            let ref_ids = statement.reference_ids();
            let id1 = &ref_ids[0];
            for id2 in ref_ids.iter().skip(1) {
                let ix2 = statement.get_claim_index(id2);
                let ix1 = statement.get_claim_index(id1);
                let map1 = proof_messages.get(id1).unwrap().clone();
                let map2 = proof_messages.get_mut(id2).unwrap();
                map2[ix2] = map1[ix1];
            }
        }

        Ok(proof_messages)
    }
}
