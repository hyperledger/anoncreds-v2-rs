mod accumulator_set_membership;
mod commitment;
mod equality;
mod proof;
mod schema;
mod signature;
mod verifiable_encryption;

pub use accumulator_set_membership::*;
pub use commitment::*;
pub use equality::*;
pub use proof::*;
pub use schema::*;
pub use signature::*;
pub use verifiable_encryption::*;

use crate::verifier::{ProofVerifier, ProofVerifiers, SignatureVerifier};
use crate::{
    claim::ClaimData,
    credential::Credential,
    error::Error,
    statement::{StatementType, Statements},
    CredxResult,
};
use group::ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uint_zigzag::Uint;
use yeti::knox::bls12_381_plus::{G1Affine, G2Affine, Scalar};
use yeti::knox::short_group_sig_core::{HiddenMessage, ProofMessage};

/// Implementers can build proofs for presentations
pub trait PresentationBuilder {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs;
}

/// Encapsulates the builders for later conversion to proofs
enum PresentationBuilders<'a> {
    Signature(SignatureBuilder<'a>),
    AccumulatorSetMembership(AccumulatorSetMembershipProofBuilder<'a>),
    Equality(EqualityBuilder<'a>),
    Commitment(CommitmentBuilder<'a>),
    VerifiableEncryption(VerifiableEncryptionBuilder<'a>),
}

impl<'a> PresentationBuilders<'a> {
    /// Convert to proofs
    pub fn gen_proof(self, challenge: Scalar) -> PresentationProofs {
        match self {
            Self::Signature(s) => s.gen_proof(challenge),
            Self::Equality(e) => e.gen_proof(challenge),
            Self::Commitment(c) => c.gen_proof(challenge),
            Self::AccumulatorSetMembership(a) => a.gen_proof(challenge),
            Self::VerifiableEncryption(v) => v.gen_proof(challenge),
        }
    }
}

/// Defines the proofs for a verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    ) -> CredxResult<Self> {
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

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

        let messages = Self::get_message_types(
            credentials,
            &signature_statements,
            &predicate_statements,
            &mut rng,
        )?;

        let mut builders = Vec::with_capacity(schema.statements.len());
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
                builders.push(PresentationBuilders::Signature(builder));
                disclosed_messages.insert(id.clone(), dm);
            }
        }

        for (_, pred_statement) in &predicate_statements {
            match pred_statement {
                Statements::Equality(e) => {
                    let builder = EqualityBuilder::commit(e, credentials)?;
                    builders.push(PresentationBuilders::Equality(builder));
                }
                Statements::AccumulatorSetMembership(a) => {
                    let proof_message = messages[&a.id][a.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData);
                    }
                    let credential = &credentials[&a.reference_id];
                    let builder = AccumulatorSetMembershipProofBuilder::commit(
                        a,
                        &credential,
                        proof_message,
                        nonce,
                        &mut transcript,
                    )?;
                    builders.push(PresentationBuilders::AccumulatorSetMembership(builder));
                }
                Statements::Commitment(c) => {
                    let proof_message = messages[&c.id][c.claim];
                    if matches!(proof_message, ProofMessage::Revealed(_)) {
                        return Err(Error::InvalidClaimData);
                    }
                    let message = proof_message.get_message();
                    let blinder = proof_message.get_blinder(&mut rng).unwrap();
                    let builder =
                        CommitmentBuilder::commit(c, message, blinder, &mut rng, &mut transcript)?;
                    builders.push(PresentationBuilders::Commitment(builder));
                }
                Statements::VerifiableEncryption(v) => {
                    let proof_message = messages[&v.id][v.claim];
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
                    builders.push(PresentationBuilders::VerifiableEncryption(builder));
                }
                Statements::Signature(_) => {}
            }
        }
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(b"challenge bytes", &mut okm);
        let challenge = Scalar::from_bytes_wide(&okm);

        let mut proofs = BTreeMap::new();

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

    /// Verify this presentation
    pub fn verify(&self, schema: &PresentationSchema, nonce: &[u8]) -> CredxResult<()> {
        let mut transcript = Transcript::new(b"credx presentation");
        Self::add_curve_parameters_challenge_contribution(&mut transcript);
        transcript.append_message(b"nonce", nonce);
        schema.add_challenge_contribution(&mut transcript);

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

        let mut verifiers = Vec::with_capacity(schema.statements.len());
        for (id, sig_statement) in &signature_statements {
            match (sig_statement, self.proofs.get(id)) {
                (Statements::Signature(ss), Some(PresentationProofs::Signature(proof))) => {
                    Self::add_disclosed_messages_challenge_contribution(
                        &ss.id,
                        &self.disclosed_messages[&ss.id],
                        &mut transcript,
                    );
                    let verifier = SignatureVerifier {
                        statement: ss,
                        signature_proof: proof,
                        disclosed_messages: &self.disclosed_messages[&ss.id],
                    };
                    verifier.add_challenge_contribution(self.challenge, &mut transcript)?;
                    verifiers.push(ProofVerifiers::Signature(verifier));
                }
                (Statements::Signature(_), None) => return Err(Error::InvalidPresentationData),
                (_, _) => {}
            }
        }

        Ok(())
    }

    fn add_curve_parameters_challenge_contribution(transcript: &mut Transcript) {
        transcript.append_message(b"curve name", b"BLS12-381");
        transcript.append_message(
            b"curve G1 generator",
            G1Affine::generator().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"curve G2 generator",
            G2Affine::generator().to_compressed().as_slice(),
        );
        transcript.append_message(
            b"subgroup size",
            &[
                0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
                0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x01,
            ],
        );
        transcript.append_message(
            b"field modulus",
            &[
                0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b,
                0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0,
                0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe,
                0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
            ],
        );
    }

    fn add_disclosed_messages_challenge_contribution(
        id: &String,
        dm: &BTreeMap<String, ClaimData>,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"disclosed messages from statement ", id.as_bytes());
        transcript.append_message(b"disclosed messages length", &Uint::from(dm.len()).to_vec());
        let mut i = 0;
        for (label, claim) in dm {
            transcript.append_message(b"disclosed message label", label.as_bytes());
            transcript.append_message(b"disclosed message index", &Uint::from(i).to_vec());
            transcript.append_message(b"disclosed message value", &claim.to_bytes());
            transcript.append_message(b"disclosed message scalar", &claim.to_scalar().to_bytes());
            i += 1;
        }
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
                if let Statements::Signature(ss) = sig {
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
                        proof_claims.push(ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                            claim_value,
                            blinder,
                        )));
                    } else {
                        proof_claims.push(ProofMessage::Hidden(
                            HiddenMessage::ProofSpecificBlinding(claim_value),
                        ));
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
