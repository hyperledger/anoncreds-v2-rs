use super::{credential::CredentialSchema, error::Error, revocation_registry::RevocationRegistry};
use crate::claim::ClaimData;
use crate::credential::{Credential, CredentialBundle};
use crate::{random_string, CredxResult};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use yeti::knox::bls12_381_plus::Scalar;
use yeti::knox::{accumulator::vb20, bls, ps, Knox};

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
    pub verifiable_decryption_key: bls::SecretKey,
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
    pub verifiable_encryption_key: bls::PublicKeyVt,
    /// The revocation registry for this issuer
    pub revocation_registry: vb20::Accumulator,
}

impl From<&Issuer> for IssuerPublic {
    fn from(i: &Issuer) -> Self {
        let verifying_key = ps::PublicKey::from(&i.signing_key);
        let revocation_verifying_key = vb20::PublicKey::from(&i.revocation_key);
        let verifiable_encryption_key = bls::PublicKeyVt::from(&i.verifiable_decryption_key);
        Self {
            id: i.id.clone(),
            schema: i.schema.clone(),
            verifying_key,
            revocation_verifying_key,
            verifiable_encryption_key,
            revocation_registry: i.revocation_registry.value,
        }
    }
}

impl Issuer {
    /// Create a new Issuer
    pub fn new(schema: &CredentialSchema, max_issuance: NonZeroUsize) -> (IssuerPublic, Self) {
        let id = random_string(16, rand::thread_rng());
        let (verifying_key, signing_key) =
            ps::Issuer::new_keys(schema.claims.len(), rand::thread_rng()).unwrap();
        let (pubkkey, seckey) = Knox::new_bls381g2_keys(rand::thread_rng());
        let revocation_verifying_key = vb20::PublicKey(pubkkey.0);
        let revocation_key = vb20::SecretKey(seckey.0);
        let (verifiable_encryption_key, verifiable_decryption_key) =
            Knox::new_bls381g1_keys(rand::thread_rng());
        let revocation_registry = RevocationRegistry::new(&revocation_key, max_issuance);
        (
            IssuerPublic {
                id: id.clone(),
                schema: schema.clone(),
                verifying_key,
                revocation_verifying_key,
                verifiable_encryption_key,
                revocation_registry: revocation_registry.value,
            },
            Issuer {
                id,
                schema: schema.clone(),
                signing_key,
                revocation_key,
                verifiable_decryption_key,
                revocation_registry,
            },
        )
    }

    /// Sign the claims into a credential
    pub fn sign_credential(
        &self,
        revocation_element_index: usize,
        claims: &[ClaimData],
    ) -> CredxResult<CredentialBundle> {
        let attributes: Vec<Scalar> = claims.iter().map(|c| c.to_scalar()).collect();
        let revocation_id = vb20::Element(attributes[revocation_element_index]);
        let elements: Vec<vb20::Element> = self
            .revocation_registry
            .elements
            .iter()
            .map(|e| vb20::Element::hash(e.as_bytes()))
            .collect();
        let index = elements
            .iter()
            .position(|e| e.0 == revocation_id.0)
            .ok_or(Error::InvalidRevocationRegistryRevokeOperation)?;
        let witness = vb20::MembershipWitness::new(
            index,
            elements.as_slice(),
            self.revocation_registry.value,
            &self.revocation_key,
        )
        .ok_or(Error::InvalidRevocationRegistryRevokeOperation)?;
        let signature = ps::Signature::new(&self.signing_key, &attributes)
            .map_err(|_| Error::InvalidSigningOperation)?;
        Ok(CredentialBundle {
            issuer: IssuerPublic::from(self),
            credential: Credential {
                claims: claims.to_vec(),
                signature,
                revocation_handle: witness,
                revocation_index: revocation_element_index,
            },
        })
    }
}
