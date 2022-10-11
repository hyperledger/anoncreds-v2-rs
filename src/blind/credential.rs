use crate::utils::g1_from_hex_str;
use crate::{
    claim::ClaimData, credential::Credential, error::Error, issuer::IssuerPublic, CredxResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yeti::knox::{
    accumulator::vb20::MembershipWitness, bls12_381_plus::Scalar, ps::BlindSignature,
};

/// A blind credential
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredential {
    /// The known claims signed by the issuer
    pub claims: BTreeMap<String, ClaimData>,
    /// The blind signature
    pub signature: BlindSignature,
    /// The revocation handle
    pub revocation_handle: MembershipWitness,
    /// The claim that is used for revocation
    pub revocation_label: String,
}

impl BlindCredential {
    /// Convert this blind credential into a regular credential
    pub fn to_credential(
        mut self,
        issuer: &IssuerPublic,
        blinder: Scalar,
        hidden_claims: &BTreeMap<String, ClaimData>,
    ) -> CredxResult<Credential> {
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

impl From<&BlindCredential> for BlindCredentialText {
    fn from(credential: &BlindCredential) -> Self {
        let claims = credential
            .claims
            .iter()
            .map(|(label, data)| (label.clone(), data.to_text()))
            .collect();
        Self {
            claims,
            signature: hex::encode(&credential.signature.to_bytes()),
            revocation_handle: hex::encode(&credential.revocation_handle.to_bytes()),
            revocation_label: credential.revocation_label.clone(),
        }
    }
}

impl From<BlindCredential> for BlindCredentialText {
    fn from(credential: BlindCredential) -> Self {
        Self::from(&credential)
    }
}

/// A blind credential in a text friendly format
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlindCredentialText {
    /// The signed claims
    pub claims: BTreeMap<String, String>,
    /// The signature
    pub signature: String,
    /// The revocation handle
    pub revocation_handle: String,
    /// The revocation label
    pub revocation_label: String,
}

impl TryFrom<&BlindCredentialText> for BlindCredential {
    type Error = Error;

    fn try_from(credential: &BlindCredentialText) -> Result<Self, Self::Error> {
        let mut claims = BTreeMap::new();
        for (label, s) in &credential.claims {
            claims.insert(label.clone(), ClaimData::from_text(s)?);
        }

        let sig_bytes = hex::decode(&credential.signature).map_err(|_| {
            Error::InvalidClaimData("unable to decode credential signature from hex string")
        })?;
        let sig_buf = <[u8; 128]>::try_from(sig_bytes.as_slice())
            .map_err(|_| Error::InvalidClaimData("unable to read credential signature bytes"))?;
        let sig = BlindSignature::from_bytes(&sig_buf);
        if sig.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidClaimData(
                "unable to deserialize credential blind signature",
            ));
        }
        Ok(Self {
            claims,
            signature: sig.unwrap(),
            revocation_handle: MembershipWitness(g1_from_hex_str(
                &credential.revocation_handle,
                Error::InvalidClaimData("unable to deserialize revocation handle"),
            )?),
            revocation_label: credential.revocation_label.clone(),
        })
    }
}
