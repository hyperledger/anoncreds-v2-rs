use super::{credential::CredentialSchema, error::Error, revocation_registry::RevocationRegistry};
use crate::blind::{BlindCredential, BlindCredentialBundle, BlindCredentialRequest};
use crate::claim::{Claim, ClaimData, RevocationClaim};
use crate::credential::{Credential, CredentialBundle};
use crate::{random_string, utils::*, CredxResult};
use group::Curve;
use indexmap::{indexmap, IndexMap};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use yeti::knox::bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use yeti::knox::{
    accumulator::vb20::{self, Accumulator, Element, MembershipWitness},
    bls, ps, Knox,
};

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
    pub revocation_registry: Accumulator,
}

/// The public data for an issuer in a json friendly struct
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerPublicText {
    /// The issuer's unique id
    pub id: String,
    /// The schema for this issuer
    pub schema: CredentialSchema,
    /// The credential verifying key for this issuer
    #[serde(
        serialize_with = "serialize_indexmap",
        deserialize_with = "deserialize_indexmap"
    )]
    pub verifying_key: IndexMap<String, String>,
    /// The revocation registry verifying key for this issuer
    pub revocation_verifying_key: String,
    /// The verifiable encryption key for this issuer
    pub verifiable_encryption_key: String,
    /// The revocation registry for this issuer
    pub revocation_registry: String,
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
        let (pubkkey, seckey) = Knox::new_bls381g2_keys(rand::thread_rng());
        let revocation_verifying_key = vb20::PublicKey(pubkkey.0);
        let revocation_key = vb20::SecretKey(seckey.0);
        let (verifiable_encryption_key, verifiable_decryption_key) =
            Knox::new_bls381g1_keys(rand::thread_rng());
        let revocation_registry = RevocationRegistry::new(rand::thread_rng());
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

    /// Blind sign a credential where only a subset of the claims are known
    pub fn blind_sign_credential(
        &mut self,
        request: &BlindCredentialRequest,
        claims: &BTreeMap<String, ClaimData>,
    ) -> CredxResult<BlindCredentialBundle> {
        // request.verify(self)?;

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

        Ok(BlindCredentialBundle {
            issuer: IssuerPublic::from(self),
            credential: BlindCredential {
                claims: claims.clone(),
                signature,
                revocation_handle: witness,
                revocation_label,
            },
        })
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
        let verifiable_encryption_key = bls::PublicKeyVt::from(&self.verifiable_decryption_key);
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

impl From<&IssuerPublic> for IssuerPublicText {
    fn from(ip: &IssuerPublic) -> Self {
        IssuerPublicText {
            id: ip.id.clone(),
            schema: ip.schema.clone(),
            verifying_key: indexmap! {
                "w".to_string() => hex::encode(ip.verifying_key.w.to_affine().to_compressed()),
                "x".to_string() => hex::encode(ip.verifying_key.x.to_affine().to_compressed()),
                "y".to_string() => serde_json::to_string(&ip.verifying_key.y.iter().map(|y| hex::encode(y.to_affine().to_compressed())).collect::<Vec<String>>()).unwrap(),
                "y_blinds".to_string() => serde_json::to_string(&ip.verifying_key.y_blinds.iter().map(|y| hex::encode(y.to_affine().to_compressed())).collect::<Vec<String>>()).unwrap(),
            },
            revocation_verifying_key: hex::encode(ip.revocation_verifying_key.to_bytes()),
            verifiable_encryption_key: hex::encode(ip.verifiable_encryption_key.to_bytes()),
            revocation_registry: hex::encode(ip.revocation_registry.to_bytes()),
        }
    }
}

impl TryFrom<&IssuerPublicText> for IssuerPublic {
    type Error = Error;

    fn try_from(ipj: &IssuerPublicText) -> Result<Self, Self::Error> {
        let get_point = |key: &str| -> CredxResult<G2Projective> {
            if let Some(value) = ipj.verifying_key.get(key) {
                let tv = hex::decode(value).map_err(|_| Error::InvalidPublicKey)?;
                let arr =
                    <[u8; 96]>::try_from(tv.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
                let pt = G2Affine::from_compressed(&arr).map(G2Projective::from);
                if pt.is_none().unwrap_u8() == 1 {
                    return Err(Error::InvalidPublicKey);
                }
                Ok(pt.unwrap())
            } else {
                Err(Error::InvalidPublicKey)
            }
        };
        let w = get_point("w")?;
        let x = get_point("x")?;
        let mut y = Vec::new();
        if let Some(ys) = ipj.verifying_key.get("y") {
            let yy: Vec<String> = serde_json::from_str(ys).map_err(|_| Error::InvalidPublicKey)?;
            for yi in &yy {
                let bytes = hex::decode(yi).map_err(|_| Error::InvalidPublicKey)?;
                let arr =
                    <[u8; 96]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
                let pt = G2Affine::from_compressed(&arr).map(G2Projective::from);
                if pt.is_none().unwrap_u8() == 1 {
                    return Err(Error::InvalidPublicKey);
                }
                y.push(pt.unwrap());
            }
        } else {
            return Err(Error::InvalidPublicKey);
        }
        let mut y_blinds = Vec::new();
        if let Some(ys) = ipj.verifying_key.get("y_blinds") {
            let yy: Vec<String> = serde_json::from_str(ys).map_err(|_| Error::InvalidPublicKey)?;
            for yi in &yy {
                let bytes = hex::decode(yi).map_err(|_| Error::InvalidPublicKey)?;
                let arr =
                    <[u8; 48]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
                let pt = G1Affine::from_compressed(&arr).map(G1Projective::from);
                if pt.is_none().unwrap_u8() == 1 {
                    return Err(Error::InvalidPublicKey);
                }
                y_blinds.push(pt.unwrap());
            }
        } else {
            return Err(Error::InvalidPublicKey);
        }

        let bytes =
            hex::decode(&ipj.revocation_verifying_key).map_err(|_| Error::InvalidPublicKey)?;
        let arr = <[u8; 96]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
        let revocation_verifying_key =
            vb20::PublicKey::try_from(&arr).map_err(|_| Error::InvalidPublicKey)?;
        let bytes =
            hex::decode(&ipj.verifiable_encryption_key).map_err(|_| Error::InvalidPublicKey)?;
        let arr = <[u8; 48]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
        let pt = bls::PublicKeyVt::from_bytes(&arr);
        if pt.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidPublicKey);
        }
        let verifiable_encryption_key = pt.unwrap();
        let bytes = hex::decode(&ipj.revocation_registry).map_err(|_| Error::InvalidPublicKey)?;
        let arr = <[u8; 48]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidPublicKey)?;
        let pt = G1Affine::from_compressed(&arr).map(G1Projective::from);
        if pt.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidPublicKey);
        }
        let revocation_registry = vb20::Accumulator::from(pt.unwrap());

        Ok(IssuerPublic {
            id: ipj.id.clone(),
            schema: ipj.schema.clone(),
            verifying_key: ps::PublicKey { w, x, y, y_blinds },

            revocation_verifying_key,
            verifiable_encryption_key,
            revocation_registry,
        })
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
            self.revocation_registry.to_bytes().as_slice(),
        );
        transcript.append_message(
            b"issuer verifiable encryption key",
            self.verifiable_encryption_key.to_bytes().as_slice(),
        );
        self.schema.add_challenge_contribution(transcript);
    }
}
