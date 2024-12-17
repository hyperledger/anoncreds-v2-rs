use crate::knox::accumulator::vb20::MembershipWitness;
use crate::knox::short_group_sig_core::short_group_traits::{
    BlindSignature, ShortGroupSignatureScheme,
};
use crate::{
    claim::ClaimData, credential::Credential, error::Error, issuer::IssuerPublic, CredxResult,
};
use blsful::inner_types::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A blind credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredential<S: ShortGroupSignatureScheme> {
    /// The known claims signed by the issuer
    pub claims: BTreeMap<String, ClaimData>,
    /// The blind signature
    pub signature: S::BlindSignature,
    /// The revocation handle
    pub revocation_handle: MembershipWitness,
    /// The claim that is used for revocation
    pub revocation_label: String,
}

impl<S: ShortGroupSignatureScheme> BlindCredential<S> {
    /// Convert this blind credential into a regular credential
    pub fn to_credential(
        mut self,
        issuer: &IssuerPublic<S>,
        blinder: Scalar,
        hidden_claims: &BTreeMap<String, ClaimData>,
    ) -> CredxResult<Credential<S>> {
        if issuer.schema.claims.len() != self.claims.len() + hidden_claims.len() {
            return Err(Error::InvalidClaimData(
                "hidden + known claims != schema claims",
            ));
        }
        let mut combined_claims = hidden_claims.clone();
        combined_claims.append(&mut self.claims);
        let signature = self.signature.to_unblinded(blinder);

        let revocation_index = issuer
            .schema
            .claim_indices
            .get_index_of(&self.revocation_label)
            .ok_or(Error::InvalidClaimData("revocation index not found"))?;

        let mut claims = Vec::with_capacity(issuer.schema.claims.len());
        for claim in &issuer.schema.claims {
            match combined_claims.remove(&claim.label) {
                None => return Err(Error::InvalidClaimData("claim not found list")),
                Some(claim) => claims.push(claim),
            }
        }

        Ok(Credential {
            claims,
            signature,
            revocation_handle: self.revocation_handle,
            revocation_index,
        })
    }
}
