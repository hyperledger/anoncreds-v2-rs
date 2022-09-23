use super::{credential::CredentialSchema, error::Error, revocation_registry::RevocationRegistry};
use crate::claim::ClaimData;
use crate::credential::{Credential, CredentialBundle};
use crate::{random_string, CredxResult};
use group::Curve;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use yeti::knox::bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
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

/// The public data for an issuer in a json friendly struct
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuerPublicText {
    /// The issuer's unique id
    pub id: String,
    /// The schema for this issuer
    pub schema: CredentialSchema,
    /// The credential verifying key for this issuer
    pub verifying_key: BTreeMap<String, String>,
    /// The revocation registry verifying key for this issuer
    pub revocation_verifying_key: String,
    /// The verifiable encryption key for this issuer
    pub verifiable_encryption_key: String,
    /// The revocation registry for this issuer
    pub revocation_registry: String,
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
        // Check if claim data matches schema and validators
        if claims.len() != self.schema.claims.len() {
            return Err(Error::InvalidClaimData);
        }
        for (c, t) in claims.iter().zip(&self.schema.claims) {
            if !c.is_type(t.claim_type) {
                return Err(Error::InvalidClaimData);
            }
            match t.is_valid(c) {
                Some(b) => {
                    if !b {
                        return Err(Error::InvalidClaimData);
                    }
                }
                None => return Err(Error::InvalidClaimData),
            };
        }

        let attributes: Vec<Scalar> = claims.iter().map(|c| c.to_scalar()).collect();
        let revocation_id = vb20::Element(attributes[revocation_element_index]);
        let witness = vb20::MembershipWitness::new(
            revocation_id,
            self.revocation_registry.value,
            &self.revocation_key,
        );
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

impl From<&IssuerPublic> for IssuerPublicText {
    fn from(ip: &IssuerPublic) -> Self {
        IssuerPublicText {
            id: ip.id.clone(),
            schema: ip.schema.clone(),
            verifying_key: btreemap! {
                "w".to_string() => hex::encode(&ip.verifying_key.w.to_affine().to_compressed()),
                "x".to_string() => hex::encode(&ip.verifying_key.x.to_affine().to_compressed()),
                "y".to_string() => serde_json::to_string(&ip.verifying_key.y.iter().map(|y| hex::encode(y.to_affine().to_compressed())).collect::<Vec<String>>()).unwrap(),
                "y_blinds".to_string() => serde_json::to_string(&ip.verifying_key.y_blinds.iter().map(|y| hex::encode(y.to_affine().to_compressed())).collect::<Vec<String>>()).unwrap(),
            },
            revocation_verifying_key: hex::encode(&ip.revocation_verifying_key.to_bytes()),
            verifiable_encryption_key: hex::encode(&ip.verifiable_encryption_key.to_bytes()),
            revocation_registry: hex::encode(&ip.revocation_registry.to_bytes()),
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
