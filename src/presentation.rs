mod accumulator_set_membership;
mod commitment;
mod create;
mod equality;
mod proof;
mod range;
mod schema;
mod signature;
mod verifiable_encryption;
mod verify;

pub use accumulator_set_membership::*;
pub use commitment::*;
pub use equality::*;
pub use proof::*;
pub use range::*;
pub use schema::*;
pub use signature::*;
pub use verifiable_encryption::*;

use crate::verifier::*;
use crate::{
    claim::ClaimData,
    credential::Credential,
    error::Error,
    statement::{StatementType, Statements},
    CredxResult,
};
use group::ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uint_zigzag::Uint;
use yeti::knox::bls12_381_plus::{G1Affine, G2Affine, Scalar};
use yeti::knox::short_group_sig_core::{HiddenMessage, ProofMessage};

/// Implementers can build proofs for presentations
pub trait PresentationBuilder {
    /// Finalize proofs
    fn gen_proof(self, challenge: Scalar) -> PresentationProofs;
}

/// Encapsulates the builders for later conversion to proofs
pub(crate) enum PresentationBuilders<'a> {
    Signature(SignatureBuilder<'a>),
    AccumulatorSetMembership(AccumulatorSetMembershipProofBuilder<'a>),
    Equality(EqualityBuilder<'a>),
    Commitment(CommitmentBuilder<'a>),
    VerifiableEncryption(VerifiableEncryptionBuilder<'a>),
    Range(RangeBuilder<'a>),
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
            Self::Range(r) => r.gen_proof(challenge),
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
    fn split_statements(
        schema: &PresentationSchema,
    ) -> (BTreeMap<String, &Statements>, BTreeMap<String, &Statements>) {
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
        (signature_statements, predicate_statements)
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
        for (i, (label, claim)) in dm.iter().enumerate() {
            transcript.append_message(b"disclosed message label", label.as_bytes());
            transcript.append_message(b"disclosed message index", &Uint::from(i).to_vec());
            transcript.append_message(b"disclosed message value", &claim.to_bytes());
            transcript.append_message(b"disclosed message scalar", &claim.to_scalar().to_bytes());
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
