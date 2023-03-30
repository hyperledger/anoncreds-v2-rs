use super::*;
use crate::{
    claim::ClaimData, credential::CredentialBundle, error::Error, issuer::IssuerPublic, CredxResult,
};

use crate::credential::Credential;
use blsful::bls12_381_plus::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A blind credential bundle returned by the issuer from a blind signing operation
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredentialBundle {
    /// The issuer information that gave this credential
    pub issuer: IssuerPublic,
    /// The blind credential
    pub credential: BlindCredential,
}

impl BlindCredentialBundle {
    /// Create a unblinded credential
    pub fn to_unblinded(
        mut self,
        blind_claims: &BTreeMap<String, ClaimData>,
        blinder: Scalar,
    ) -> CredxResult<CredentialBundle> {
        for label in blind_claims.keys() {
            if !self.issuer.schema.blind_claims.contains(label) {
                return Err(Error::InvalidClaimData("claim is not blindable"));
            }
            if self.credential.claims.contains_key(label) {
                return Err(Error::InvalidClaimData("duplicate claim detected"));
            }
        }
        self.credential.claims.append(&mut blind_claims.clone());
        let mut ordering = vec![String::new(); self.credential.claims.len()];

        for label in self.credential.claims.keys() {
            ordering[self
                .issuer
                .schema
                .claim_indices
                .get_index_of(label)
                .unwrap()] = label.clone();
        }
        let mut claims = Vec::with_capacity(self.issuer.schema.claims.len());
        for label in &ordering {
            claims.push(
                self.credential
                    .claims
                    .remove(label)
                    .ok_or(Error::InvalidClaimData("claim missing"))?,
            );
        }
        let revocation_index = self
            .issuer
            .schema
            .claim_indices
            .get_index_of(&self.credential.revocation_label)
            .ok_or(Error::InvalidClaimData(
                "revocation label not found in claims",
            ))?;
        Ok(CredentialBundle {
            issuer: self.issuer,
            credential: Credential {
                claims,
                signature: self.credential.signature.to_unblinded(blinder),
                revocation_handle: self.credential.revocation_handle,
                revocation_index,
            },
        })
    }
}
