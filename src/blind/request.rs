use crate::knox::short_group_sig_core::short_group_traits::{
    BlindSignatureContext as _, ShortGroupSignatureScheme,
};
use crate::{
    claim::ClaimData,
    error::Error,
    issuer::{Issuer, IssuerPublic},
    CredxResult,
};
use blsful::inner_types::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A blind credential signing request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredentialRequest<S: ShortGroupSignatureScheme> {
    /// The blind signing context
    pub blind_signature_context: S::BlindSignatureContext,
    /// The blind claim labels
    pub blind_claim_labels: Vec<String>,
    /// The nonce for this context
    pub nonce: Scalar,
}

impl<S: ShortGroupSignatureScheme> BlindCredentialRequest<S> {
    /// Create a new request
    pub fn new(
        issuer: &IssuerPublic<S>,
        claims: &BTreeMap<String, ClaimData>,
    ) -> CredxResult<(Self, Scalar)> {
        let nonce = Scalar::random(rand::thread_rng());
        let mut messages = Vec::with_capacity(claims.len());
        for (label, claim) in claims {
            if !issuer.schema.blind_claims.contains(label) {
                return Err(Error::InvalidClaimData("claim is not blindable"));
            }
            messages.push((
                issuer
                    .schema
                    .claim_indices
                    .get_index_of(label)
                    .ok_or(Error::InvalidClaimData("claim does not exist in schema"))?,
                claim.to_scalar(),
            ));
        }
        let (ctx, blinder) = S::new_blind_signature_context(
            &messages,
            &issuer.verifying_key,
            nonce,
            rand::thread_rng(),
        )
        .map_err(|_| Error::InvalidClaimData("unable to create blind signature context"))?;
        Ok((
            Self {
                blind_signature_context: ctx,
                blind_claim_labels: claims.keys().cloned().collect(),
                nonce,
            },
            blinder,
        ))
    }

    /// Verify the signing request is well-formed
    pub fn verify(&self, issuer: &Issuer<S>) -> CredxResult<()> {
        let mut known_messages =
            Vec::with_capacity(issuer.schema.claims.len() - self.blind_claim_labels.len());
        for label in &self.blind_claim_labels {
            if !issuer.schema.blind_claims.contains(label) {
                return Err(Error::InvalidClaimData("claim is not blindable"));
            }
            known_messages.push(
                issuer
                    .schema
                    .claim_indices
                    .get_index_of(label)
                    .ok_or(Error::InvalidClaimData("claim does not exist in schema"))?,
            );
        }
        let res = self
            .blind_signature_context
            .verify(&known_messages, &issuer.signing_key, self.nonce)
            .map_err(|_| Error::InvalidSigningOperation)?;
        if !res {
            return Err(Error::InvalidSigningOperation);
        }
        Ok(())
    }
}
