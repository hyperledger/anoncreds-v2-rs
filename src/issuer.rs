use super::{credential::CredentialSchema, error::Error, revocation_registry::RevocationRegistry};
use crate::blind::{BlindCredential, BlindCredentialBundle, BlindCredentialRequest};
use crate::claim::{Claim, ClaimData, RevocationClaim};
use crate::credential::{Credential, CredentialBundle};
use crate::knox::{
    accumulator::vb20::{self, Accumulator, Element, MembershipWitness},
    ps, Knox,
};
use crate::{random_string, CredxResult};
use blsful::{inner_types::*, *};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// An issuer of a credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Issuer {
    /// The issuer's unique id
    pub id: String,
    /// The schema for this issuer
    pub schema: CredentialSchema,
    /// The credential signing key for this issuer
    pub signing_key: ps::SecretKey,
    /// The revocation update key for this issuer
    pub revocation_key: vb20::SecretKey,
    /// The verifiable decryption key for this issuer
    pub verifiable_decryption_key: SecretKey<Bls12381G2Impl>,
    /// The revocation registry for this issuer
    pub revocation_registry: RevocationRegistry,
}

/// The public data for an issuer
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerPublic {
    /// The issuer's unique id
    pub id: String,
    /// The schema for this issuer
    pub schema: CredentialSchema,
    /// The credential verifying key for this issuer
    pub verifying_key: ps::PublicKey,
    /// The revocation registry verifying key for this issuer
    pub revocation_verifying_key: vb20::PublicKey,
    /// The verifiable encryption key for this issuer
    pub verifiable_encryption_key: PublicKey<Bls12381G2Impl>,
    /// The revocation registry for this issuer
    pub revocation_registry: Accumulator,
}

impl From<&Issuer> for IssuerPublic {
    fn from(i: &Issuer) -> Self {
        i.get_public()
    }
}

impl From<&mut Issuer> for IssuerPublic {
    fn from(i: &mut Issuer) -> Self {
        i.get_public()
    }
}

impl Issuer {
    /// Create a new Issuer
    pub fn new(schema: &CredentialSchema) -> (IssuerPublic, Self) {
        let id = random_string(16, rand::thread_rng());
        let (verifying_key, signing_key) =
            ps::Issuer::new_keys(schema.claims.len(), rand::thread_rng()).unwrap();
        let (pubkkey, seckey) = Knox::new_bls381g1_keys(rand::thread_rng());
        let revocation_verifying_key = vb20::PublicKey(pubkkey.0);
        let revocation_key = vb20::SecretKey(seckey.0);
        let (verifiable_encryption_key, verifiable_decryption_key) =
            Knox::new_bls381g2_keys(rand::thread_rng());
        let revocation_registry = RevocationRegistry::new(rand::thread_rng());
        let issuer_public = IssuerPublic {
            id: id.clone(),
            schema: schema.clone(),
            verifying_key,
            revocation_verifying_key,
            verifiable_encryption_key,
            revocation_registry: revocation_registry.value,
        };
        debug!(
            "Credential Definition: {:}",
            serde_json::to_string_pretty(&issuer_public).unwrap()
        );
        let issuer = Issuer {
            id,
            schema: schema.clone(),
            signing_key,
            revocation_key,
            verifiable_decryption_key,
            revocation_registry,
        };
        (issuer_public, issuer)
    }

    /// Sign the claims into a credential
    pub fn sign_credential(&mut self, claims: &[ClaimData]) -> CredxResult<CredentialBundle> {
        // Check if claim data matches schema and validators
        if claims.len() != self.schema.claims.len() {
            return Err(Error::InvalidClaimData("claims.len != schema.claims.len"));
        }
        let mut revocation_element_index = None;
        let mut revocation_claim = None;
        for (i, (c, t)) in claims.iter().zip(&self.schema.claims).enumerate() {
            if !c.is_type(t.claim_type) {
                return Err(Error::InvalidClaimData("claim is not the correct type"));
            }
            match t.is_valid(c) {
                Some(b) => {
                    if !b {
                        return Err(Error::InvalidClaimData("claim is not valid"));
                    }
                }
                None => {
                    return Err(Error::InvalidClaimData(
                        "claim is not correct type to validate",
                    ))
                }
            };
            if let ClaimData::Revocation(rc) = c {
                if revocation_claim.is_some() {
                    return Err(Error::InvalidClaimData("multiple revocation claims found"));
                }
                revocation_element_index = Some(i);
                revocation_claim = Some(rc);
            }
        }
        let revocation_element_index = revocation_element_index.ok_or(Error::InvalidClaimData(
            "revocation element index not found",
        ))?;
        let revocation_claim =
            revocation_claim.ok_or(Error::InvalidClaimData("revocation claim not found"))?;

        // This data has already been revoked
        if !self
            .revocation_registry
            .active
            .contains(&revocation_claim.value)
            && self
                .revocation_registry
                .elements
                .contains(&revocation_claim.value)
        {
            return Err(Error::InvalidClaimData("This claim is already revoked"));
        }

        let attributes: Vec<Scalar> = claims.iter().map(|c| c.to_scalar()).collect();
        let revocation_id = Element(attributes[revocation_element_index]);
        let witness = MembershipWitness::new(
            revocation_id,
            self.revocation_registry.value,
            &self.revocation_key,
        );
        self.revocation_registry
            .active
            .insert(revocation_claim.value.clone());
        self.revocation_registry
            .elements
            .insert(revocation_claim.value.clone());
        let signature = ps::Signature::new(&self.signing_key, &attributes)
            .map_err(|_| Error::InvalidSigningOperation)?;
        let credential_bundle = CredentialBundle {
            issuer: IssuerPublic::from(self),
            credential: Credential {
                claims: claims.to_vec(),
                signature,
                revocation_handle: witness,
                revocation_index: revocation_element_index,
            },
        };
        debug!(
            "Signed Credential: {}",
            serde_json::to_string_pretty(&credential_bundle).unwrap()
        );
        Ok(credential_bundle)
    }

    /// Blind sign a credential where only a subset of the claims are known
    pub fn blind_sign_credential(
        &mut self,
        request: &BlindCredentialRequest,
        claims: &BTreeMap<String, ClaimData>,
    ) -> CredxResult<BlindCredentialBundle> {
        if request.blind_claim_labels.len() + claims.len() != self.schema.claims.len() {
            return Err(Error::InvalidClaimData(
                "blind_claims.len + known_claims.len != schema.claims.len",
            ));
        }

        let mut messages = Vec::with_capacity(claims.len());
        let mut revocation_label = None;
        let mut revocation_claim = None;
        for (label, c) in claims {
            let index = self
                .schema
                .claim_indices
                .get_index_of(label)
                .ok_or(Error::InvalidClaimData("claim not found in schema"))?;
            let t = &self.schema.claims[index];

            if !c.is_type(t.claim_type) {
                return Err(Error::InvalidClaimData("claim is not the correct type"));
            }
            match t.is_valid(c) {
                Some(b) => {
                    if !b {
                        return Err(Error::InvalidClaimData("claim is not valid"));
                    }
                }
                None => {
                    return Err(Error::InvalidClaimData(
                        "claim is not correct type to validate",
                    ))
                }
            };
            messages.push((
                self.schema
                    .claim_indices
                    .get_index_of(label)
                    .ok_or(Error::InvalidClaimData("claim does not exist in schema"))?,
                c.to_scalar(),
            ));
            if let ClaimData::Revocation(rc) = c {
                revocation_label = Some(label.clone());
                revocation_claim = Some(rc);
            }
        }
        let revocation_label =
            revocation_label.ok_or(Error::InvalidClaimData("revocation label not found"))?;
        let revocation_claim =
            revocation_claim.ok_or(Error::InvalidClaimData("revocation claim not found"))?;

        // This data has already been revoked
        if !self
            .revocation_registry
            .active
            .contains(&revocation_claim.value)
            && self
                .revocation_registry
                .elements
                .contains(&revocation_claim.value)
        {
            return Err(Error::InvalidClaimData("This claim is already revoked"));
        }

        let revocation_id = Element(revocation_claim.to_scalar());
        let witness = MembershipWitness::new(
            revocation_id,
            self.revocation_registry.value,
            &self.revocation_key,
        );
        self.revocation_registry
            .active
            .insert(revocation_claim.value.clone());
        self.revocation_registry
            .elements
            .insert(revocation_claim.value.clone());

        let signature = ps::Issuer::blind_sign(
            &request.blind_signature_context,
            &self.signing_key,
            &messages,
            request.nonce,
        )
        .map_err(|_| Error::InvalidSigningOperation)?;
        let blind_credential_bundle = BlindCredentialBundle {
            issuer: IssuerPublic::from(self),
            credential: BlindCredential {
                claims: claims.clone(),
                signature,
                revocation_handle: witness,
                revocation_label,
            },
        };
        debug!(
            "Blind Signed Credential: {}",
            serde_json::to_string_pretty(&blind_credential_bundle).unwrap()
        );
        Ok(blind_credential_bundle)
    }

    /// Update a revocation handle
    pub fn update_revocation_handle(
        &self,
        claim: RevocationClaim,
    ) -> CredxResult<MembershipWitness> {
        if !self.revocation_registry.active.contains(&claim.value) {
            return Err(Error::InvalidRevocationRegistryRevokeOperation);
        }

        Ok(MembershipWitness::new(
            Element(claim.to_scalar()),
            self.revocation_registry.value,
            &self.revocation_key,
        ))
    }

    /// Revoke a credential and update this issue's revocation registry
    /// A list of all revoked claims should be kept externally.
    pub fn revoke_credentials(&mut self, claims: &[RevocationClaim]) -> CredxResult<()> {
        let c: Vec<_> = claims.iter().map(|c| c.value.clone()).collect();
        self.revocation_registry.revoke(&self.revocation_key, &c)
    }

    fn get_public(&self) -> IssuerPublic {
        let verifying_key = ps::PublicKey::from(&self.signing_key);
        let revocation_verifying_key = vb20::PublicKey::from(&self.revocation_key);
        let verifiable_encryption_key =
            blsful::PublicKey::<Bls12381G2Impl>::from(&self.verifiable_decryption_key);
        IssuerPublic {
            id: self.id.clone(),
            schema: self.schema.clone(),
            verifying_key,
            revocation_verifying_key,
            verifiable_encryption_key,
            revocation_registry: self.revocation_registry.value,
        }
    }
}

impl IssuerPublic {
    /// Add data to transcript
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(b"issuer id", self.id.as_bytes());
        transcript.append_message(
            b"issuer verifying key",
            self.verifying_key.to_bytes().as_slice(),
        );
        transcript.append_message(
            b"issuer revocation verifying key",
            self.revocation_verifying_key.to_bytes().as_slice(),
        );
        transcript.append_message(
            b"issuer revocation registry",
            self.revocation_registry.0.to_bytes().as_ref(),
        );
        transcript.append_message(
            b"issuer verifiable encryption key",
            self.verifiable_encryption_key.0.to_bytes().as_ref(),
        );
        self.schema.add_challenge_contribution(transcript);
    }
}
