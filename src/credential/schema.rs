use crate::claim::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A credential schema
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialSchema {
    /// The unique identifier for this schema
    pub id: String,
    /// Friendly label
    pub label: String,
    /// A longer description
    pub description: String,
    /// The list of claims allowed to be blindly signed
    pub blind_claims: Vec<String>,
    /// The claim labels to indices
    pub claim_indices: BTreeMap<String, usize>,
    /// The claims that can be signed
    pub claims: Vec<ClaimSchema>,
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
}

#[test]
fn test_serialize() {
    let string = r#"{"id":"63e8b522-3ef6-4c45-92f1-47cad2449523","label":"Finclusive KYC Schema","description":"","blind_claims":[],"claim_indices":{"address1":3,"address2":4,"city":5,"credential_id":0,"date_of_birth":9,"document_content":19,"document_file_name":18,"document_id":14,"document_identification_number":16,"document_iso_country_code":20,"document_type":17,"document_url":15,"email_address":12,"first_name":1,"iso_country_code":8,"last_name":2,"phone_number":10,"phone_number_type":11,"postal_cost":7,"state":6,"tax_id_number":13},"claims":[{"claim_type":4,"label":"credential_id","print_friendly":false},{"claim_type":1,"label":"first_name","print_friendly":true,"validators":[{"Length":{"max":64}}]},{"claim_type":1,"label":"last_name","print_friendly":true,"validators":[{"Length":{"max":64}}]},{"claim_type":1,"label":"address1","print_friendly":true},{"claim_type":1,"label":"address2","print_friendly":true},{"claim_type":1,"label":"city","print_friendly":true},{"claim_type":1,"label":"state","print_friendly":true},{"claim_type":1,"label":"postal_code","print_friendly":true},{"claim_type":1,"label":"iso_country_code","print_friendly":true},{"claim_type":2,"label":"date_of_birth","print_friendly":true,"validators":[{"Range":{"min":0,"max":65000}}]},{"claim_type":1,"label":"phone_number","print_friendly":true,"validators":[{"Regex":"\\d{10,15}"}]},{"claim_type":2,"label":"phone_number_type","print_friendly":true},{"claim_type":1,"label":"email_address","print_friendly":true},{"claim_type":1,"label":"tax_id_number","print_friendly":true},{"claim_type":1,"label":"document_id","print_friendly":true},{"claim_type":1,"label":"document_url","print_friendly":true},{"claim_type":1,"label":"document_identification_number","print_friendly":true},{"claim_type":1,"label":"document_type","print_friendly":true},{"claim_type":1,"label":"document_file_name","print_friendly":true},{"claim_type":1,"label":"document_content","print_friendly":false},{"claim_type":2,"label":"document_iso_country_code","print_friendly":true}]}"#;
    let res = serde_json::from_str::<CredentialSchema>(string);
    assert!(res.is_ok());
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
