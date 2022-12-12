use crate::claim::*;
use crate::error::Error;
use crate::{random_string, utils::*, CredxResult};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use uint_zigzag::Uint;

/// A credential schema
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialSchema {
    /// The unique identifier for this schema
    pub id: String,
    /// Friendly label
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub label: Option<String>,
    /// A longer description
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// The list of claims allowed to be blindly signed
    #[serde(
        serialize_with = "serialize_indexset",
        deserialize_with = "deserialize_indexset"
    )]
    pub blind_claims: IndexSet<String>,
    /// The claim labels to indices
    #[serde(
        serialize_with = "serialize_indexset",
        deserialize_with = "deserialize_indexset"
    )]
    pub claim_indices: IndexSet<String>,
    /// The claims that can be signed
    pub claims: Vec<ClaimSchema>,
}

impl CredentialSchema {
    /// Create a new credential schema
    pub fn new(
        label: Option<&str>,
        description: Option<&str>,
        blind_claims: &[&str],
        claims: &[ClaimSchema],
    ) -> CredxResult<Self> {
        let claims = claims.to_vec();
        if claims.is_empty() {
            return Err(Error::InvalidClaimData(
                "cannot create a schema with an empty claims list",
            ));
        }

        let id = random_string(16, rand::thread_rng());
        let mut claim_indices = IndexSet::new();
        for claim in &claims {
            if !claim_indices.insert(claim.label.to_string()) {
                return Err(Error::InvalidClaimData("duplicate claim detected"));
            }
        }
        for blind_claim in blind_claims {
            if !claim_indices.contains(&blind_claim.to_string()) {
                return Err(Error::InvalidClaimData(
                    "blind claim not found in claims list",
                ));
            }
        }
        let blind_claims = blind_claims.iter().map(|b| b.to_string()).collect();
        Ok(Self {
            id,
            blind_claims,
            claims,
            claim_indices,
            label: label.map(|l| l.to_string()),
            description: description.map(|d| d.to_string()),
        })
    }
    /// Add data to the transcript
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        let label = self
            .label
            .as_ref()
            .map(|l| l.as_bytes())
            .unwrap_or_default();
        let description = self
            .description
            .as_ref()
            .map(|d| d.as_bytes())
            .unwrap_or_default();
        transcript.append_message(b"schema id length", &Uint::from(self.id.len()).to_vec());
        transcript.append_message(b"schema id", self.id.as_bytes());
        transcript.append_message(b"schema label length", &Uint::from(label.len()).to_vec());
        transcript.append_message(b"schema label", label);
        transcript.append_message(
            b"schema description length",
            &Uint::from(description.len()).to_vec(),
        );
        transcript.append_message(b"schema description", description);
        transcript.append_message(
            b"blind claims length",
            &Uint::from(self.blind_claims.len()).to_vec(),
        );
        for b in &self.blind_claims {
            transcript.append_message(b"blind claim", b.as_bytes());
        }
        transcript.append_message(
            b"claim indices length",
            &Uint::from(self.claim_indices.len()).to_vec(),
        );
        for (index, label) in self.claim_indices.iter().enumerate() {
            transcript.append_message(
                b"claim indices label length",
                &Uint::from(label.len()).to_vec(),
            );
            transcript.append_message(b"claim indices label", label.as_bytes());
            transcript.append_message(b"claim indices index", &Uint::from(index).to_vec());
        }
        transcript.append_message(b"claims length", &Uint::from(self.claims.len()).to_vec());
    }
}

/// A claim schema
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimSchema {
    /// The claim type
    pub claim_type: ClaimType,
    /// The claim label
    pub label: String,
    /// Can the claim be represented as printable characters
    pub print_friendly: bool,
    /// The claim data validators
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validators: Vec<ClaimValidator>,
}

impl ClaimSchema {
    /// [`Some(true)`] if the claim is the right type and meets the validator requirements
    /// [`Some(false)`] if the claim is the right type but doesn't meet the requirements
    /// [`None`] if the claim is the incorrect type
    pub fn is_valid(&self, claim: &ClaimData) -> Option<bool> {
        let mut result = true;
        for v in &self.validators {
            match v.is_valid(claim) {
                Some(b) => result &= b,
                None => return None,
            }
        }
        Some(result)
    }

    /// Add data to the transcript
    pub fn add_challenge_contribution(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(b"claim label", self.label.as_bytes());
        transcript.append_message(b"claim type", &[self.claim_type as u8]);
        transcript.append_message(b"claim print friendly", &[u8::from(self.print_friendly)]);
        transcript.append_message(
            b"claim validators length",
            &Uint::from(self.validators.len()).to_vec(),
        );
        for (index, validator) in self.validators.iter().enumerate() {
            transcript.append_message(b"claim validator index", &Uint::from(index).to_vec());
            validator.add_challenge_contribution(transcript);
        }
    }
}

#[test]
fn test_serialize() {
    let string = r#"{"id":"63e8b522-3ef6-4c45-92f1-47cad2449523","label":"FinclusiveKYCSchema","description":"","blind_claims":[],"claim_indices":["credential_id","first_name","last_name","address1","address2","city","state","postal_cost","iso_country_code","date_of_birth","phone_number","phone_number_type","email_address","tax_id_number","document_id","document_url","document_identification_number","document_type","document_file_name","document_content","document_iso_country_code"],"claims":[{"claim_type":"Revocation","label":"credential_id","print_friendly":false},{"claim_type":"Hashed","label":"first_name","print_friendly":true,"validators":[{"Length":{"max":64}}]},{"claim_type":"Hashed","label":"last_name","print_friendly":true,"validators":[{"Length":{"max":64}}]},{"claim_type":"Hashed","label":"address1","print_friendly":true},{"claim_type":"Hashed","label":"address2","print_friendly":true},{"claim_type":"Hashed","label":"city","print_friendly":true},{"claim_type":"Hashed","label":"state","print_friendly":true},{"claim_type":"Hashed","label":"postal_code","print_friendly":true},{"claim_type":"Hashed","label":"iso_country_code","print_friendly":true},{"claim_type":"Number","label":"date_of_birth","print_friendly":true,"validators":[{"Range":{"min":0,"max":65000}}]},{"claim_type":"Hashed","label":"phone_number","print_friendly":true,"validators":[{"Regex":"\\d{10,15}"}]},{"claim_type":"Number","label":"phone_number_type","print_friendly":true},{"claim_type":"Hashed","label":"email_address","print_friendly":true},{"claim_type":"Hashed","label":"tax_id_number","print_friendly":true},{"claim_type":"Hashed","label":"document_id","print_friendly":true},{"claim_type":"Hashed","label":"document_url","print_friendly":true},{"claim_type":"Hashed","label":"document_identification_number","print_friendly":true},{"claim_type":"Hashed","label":"document_type","print_friendly":true},{"claim_type":"Hashed","label":"document_file_name","print_friendly":true},{"claim_type":"Hashed","label":"document_content","print_friendly":false},{"claim_type":"Number","label":"document_iso_country_code","print_friendly":true}]}"#;
    let res = serde_json::from_str::<CredentialSchema>(string);
    assert!(res.is_ok(), "{}", res.unwrap_err());
    let schema = res.unwrap();
    assert_eq!("63e8b522-3ef6-4c45-92f1-47cad2449523", schema.id);
    let res = serde_cbor::to_vec(&schema);
    assert!(res.is_ok());
    let bytes = res.unwrap();
    let res = serde_cbor::from_slice::<CredentialSchema>(&bytes);
    assert!(res.is_ok());
    let schema = res.unwrap();
    assert_eq!("63e8b522-3ef6-4c45-92f1-47cad2449523", schema.id);

    // let res = serde_bare::to_vec(&schema);
    // assert!(res.is_ok());
    // let bytes = res.unwrap();
    // let res = serde_bare::from_slice::<CredentialSchema>(&bytes);
    // assert!(res.is_ok(), "{:?}", res);
    // let schema = res.unwrap();
    // assert_eq!("63e8b522-3ef6-4c45-92f1-47cad2449523", schema.id);
}
