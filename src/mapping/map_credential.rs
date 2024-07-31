use crate::claim::{ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim};
use crate::credential::{ClaimSchema, CredentialBundle, CredentialSchema};
use crate::issuer::Issuer;
use crate::CredxResult;
use base64::Engine;
use chrono::Utc;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

fn create_credential() -> CredxResult<CredentialBundle> {
    const LABEL: &str = "Test Schema";
    const DESCRIPTION: &str = "This is a test presentation schema";
    const CRED_ID: &str = "91742856-6eda-45fb-a709-d22ebb5ec8a5";
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "identifier".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: Some(3),
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "address".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Length {
                min: None,
                max: Some(u8::MAX as usize),
            }],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![ClaimValidator::Range {
                min: Some(0),
                max: Some(u16::MAX as isize),
            }],
        },
    ];
    let cred_schema = CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)?;
    let (_issuer_public, mut issuer) = Issuer::new(&cred_schema);

    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;
    Ok(credential)
}

#[allow(dead_code)]
fn base64_encode(val: &[u8]) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(val)
}

#[allow(dead_code)]
fn base64_decode(val: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let padlen = 4 - val.len() % 4;
    let padded = if padlen > 2 {
        val.to_string()
    } else {
        format!("{}{}", val, "=".repeat(padlen))
    };
    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(padded)
}

fn encode_identifier(id: &str) -> String {
    format!("did:key:{}", id.replace(' ', "%20"))
}

fn decode_identifier(id: &str) -> String {
    id.replace("%20", " ")
        .trim_start_matches("did:key:")
        .to_string()
}

fn retrieve_cred_def_input_anoncreds(creds: &Value) -> Result<Value, String> {
    let issuer = creds
        .get("issuer")
        .and_then(Value::as_object)
        .ok_or_else(|| "Missing or invalid 'issuer' field".to_string())?;
    let issuer_id = issuer
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing or invalid 'issuer.id' field".to_string())?;
    let schema_id = issuer
        .get("schema")
        .and_then(|s| s.get("id").and_then(Value::as_str))
        .ok_or_else(|| "Missing or invalid 'issuer.schema.id' field".to_string())?;

    let cred_def = issuer_id;

    Ok(json!({
        "id": encode_identifier(issuer_id), // should be url in the future
        "schema": encode_identifier(schema_id),
        "cred_def": encode_identifier(cred_def),
    }))
}

fn encode_to_w3c_proof(creds: &Value) -> Result<String, Box<dyn std::error::Error>> {
    let anoncreds = &creds["credential"];
    let tmp_signature = Value::Object({
        let mut map = Map::new();
        map.insert("signature".to_string(), anoncreds["signature"].clone());
        map
    });
    let tmp_revocation = Value::Object({
        let mut map = Map::new();
        map.insert(
            "revocation_handle".to_string(),
            anoncreds["revocation_handle"].clone(),
        );
        map.insert(
            "revocation_index".to_string(),
            anoncreds["revocation_index"].clone(),
        );
        map
    });
    let parts = [tmp_signature, tmp_revocation];
    let mut buf = Vec::new();
    parts.serialize(&mut Serializer::new(&mut buf))?; // msgpack
    Ok("u".to_owned() + &base64_encode(&buf))
}

fn decode_to_anoncreds_proof(proof: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let decoded = base64_decode(&proof[1..])?;
    let mut de = Deserializer::new(&decoded[..]);
    let obj = Deserialize::deserialize(&mut de)?;
    Ok(obj)
}

fn map_label_to_claim_value(
    data: &Value,
) -> Result<Map<String, Value>, Box<dyn std::error::Error>> {
    let schema_claims = data["issuer"]["schema"]["claims"]
        .as_array()
        .ok_or("Expected array")?;
    let credential_claims = data["credential"]["claims"]
        .as_array()
        .ok_or("Expected array")?;

    let mut attr = Map::new();
    for (idx, schema_claim) in schema_claims.iter().enumerate() {
        let label = if schema_claim["claim_type"] == "Revocation" {
            "revocation_identifier".to_string()
        } else {
            schema_claim["label"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };

        let claim_value_dict = &credential_claims[idx];
        let claim_type = claim_value_dict
            .as_object()
            .ok_or("Expected object")?
            .keys()
            .next()
            .unwrap()
            .clone();
        let claim_value = &claim_value_dict[&claim_type]["value"];
        attr.insert(label, claim_value.clone());
    }
    Ok(attr)
}

fn to_w3c(cred_json: &Value) -> serde_json::Result<Value> {
    let issuer = retrieve_cred_def_input_anoncreds(cred_json);
    let signature = encode_to_w3c_proof(cred_json);
    let attrs = map_label_to_claim_value(cred_json);
    let mut vocab_map = Map::new();
    vocab_map.insert(
        "@vocab".to_string(),
        Value::String("https://www.w3.org/ns/credentials/issuer-dependent#".to_string()),
    );
    let contexts = vec![
        Value::String("https://www.w3.org/2018/credentials/v1".to_string()),
        Value::String("https://w3id.org/security/data-integrity/v2".to_string()),
        Value::Object(vocab_map), // Now correctly using serde_json::Map
    ];

    let issuance_date = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let proof = json!({
        "type": "DataIntegrityProof",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/credential-definition",
        "proofValue": signature.unwrap()
    });

    let w3c_cred = json!({
        "@context": contexts,
        "type": ["VerifiableCredential"],
        "issuer": issuer.unwrap(),
        "credentialSubject": attrs.unwrap(),
        "proof": proof,
        "issuanceDate": issuance_date
    });

    Ok(w3c_cred)
}

fn to_anoncreds(cred_json: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let issuer_id = decode_identifier(
        cred_json["issuer"]["id"]
            .as_str()
            .ok_or("Missing issuer ID")?,
    );
    let schema_id = decode_identifier(
        cred_json["issuer"]["schema"]
            .as_str()
            .ok_or("Missing schema ID")?,
    );
    let attrs = cred_json["credentialSubject"]
        .as_object()
        .ok_or("Missing attributes")?;
    let signature_parts = decode_to_anoncreds_proof(
        cred_json["proof"]["proofValue"]
            .as_str()
            .ok_or("Missing proof value")?,
    )?;
    let signature_map = signature_parts
        .first()
        .and_then(Value::as_object)
        .ok_or("Expected a map-like structure")?;
    let mut values = Vec::new();
    for (key, attr_value) in attrs {
        let value_entry = match attr_value {
            Value::String(s) => {
                if key != "revocation_identifier" {
                    json!({"Hashed": {"value": s, "print_friendly": true}})
                } else {
                    json!({"Hashed": {"value": s}})
                }
            }
            Value::Number(n) if n.is_f64() || n.is_i64() => json!({"Number": {"value": n}}),
            _ => continue, // Skip values that are neither String nor Number
        };
        values.push(value_entry);
    }

    let ret = json!({
        "issuer": {
            "id": issuer_id,
            "schema": schema_id,
            "cred_def": issuer_id,
        },
        "credential": {
            "claims": values,
            "signature": signature_map.get("signature").cloned().unwrap_or_default(),
            "revocation_handle": signature_map.get("revocation_handle").cloned().unwrap_or_default(),
            "revocation_index": signature_map.get("revocation_index").cloned().unwrap_or_default(),
        }
    });

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;

    #[test]
    fn test_create_credential() {
        let credential_result = create_credential();
        assert!(credential_result.is_ok());
    }

    #[test]
    fn test_extract_cred_def() {
        let credential_result = create_credential();
        assert!(credential_result.is_ok());
        let credential = credential_result.unwrap();
        let cred_string = serde_json::to_string_pretty(&credential).unwrap();
        let cred_json: Value = serde_json::from_str(&cred_string).unwrap();
        let issuer = retrieve_cred_def_input_anoncreds(&cred_json);
        // println!("issuer = {:?}", issuer);
        assert!(issuer.is_ok());
    }

    #[ignore]
    #[test]
    fn test_decode_to_anoncreds() {
        let encoded_string: &str = "ukoGpc2lnbmF0dXJlg6ZtX3RpY2vZQDEwNTZlMjU3ODJlZDE0ZGJjNTY0YTE5ZjM2ZTMzOTc5OTMxYzBmYTQ0ZWU4OWQzNDk1YjVhNWE4OTI5MTE5Njmnc2lnbWFfMdlgYjUyZDcyNGM4ZTdhYjJiYzExYzRmMzYzYmRkMTJkMjUzNTNlNjNhODA0Nzc5MWFmZjE2MTViYWU5ZGVmZmY5NzM4MmM0OGU4MGE4YjBhOGM4YmIyNjk1NmVhZGM4NmVkp3NpZ21hXzLZYGEzMDYxN2M1ODY0ZWM3NjU1ZDM5ZjNkNzc1MTYzY2JjYTliNDFmNmFkOGZiYzJmNTE4NzUwNzA5YTUxZGRjMzQ0NDEyYjYwYTE2MWJjMjc1MjViZTg0ODRjNGZhNjI2M4KxcmV2b2NhdGlvbl9oYW5kbGXZYDhhY2Q5OWJmMTgxYTMzNTFmZWQ0ZjBhMGNmNmFmNDE2YjhiMDM1OGRkMDg4MGViOTkyODU1NDZlYTAzNmM0ZDZjMjViNjExNzJhMjA2NWI1ZDIyY2JiYjI3YTljMmRlObByZXZvY2F0aW9uX2luZGV4AA";
        let decoded = decode_to_anoncreds_proof(&encoded_string);
        // println!("Decoded data: {:?}", decoded);
        assert!(decoded.is_ok(), "Decoding failed");
    }

    #[test]
    fn test_encode_to_w3c() {
        let credential_result = create_credential();
        assert!(credential_result.is_ok());
        let credential = credential_result.unwrap();
        let cred_string = serde_json::to_string_pretty(&credential).unwrap();
        let cred_json: Value = serde_json::from_str(&cred_string).unwrap();
        let encoded_string = encode_to_w3c_proof(&cred_json).unwrap();
        // println!("Encoded data: {}", encoded_string);
        assert!(encoded_string.len() > 0);
    }

    #[test]
    fn test_map_label_to_claim_value() {
        let credential_result = create_credential();
        assert!(credential_result.is_ok());
        let credential = credential_result.unwrap();
        let cred_string = serde_json::to_string_pretty(&credential).unwrap();
        let cred_json: Value = serde_json::from_str(&cred_string).unwrap();
        let attrs = map_label_to_claim_value(&cred_json);
        // println!("Attributes: {:?}", attrs);
        assert!(attrs.is_ok());
    }

    #[test]
    fn test_to_w3c() {
        let credential_result = create_credential();
        assert!(credential_result.is_ok());
        let credential = credential_result.unwrap();
        let cred_string = serde_json::to_string_pretty(&credential).unwrap();
        let cred_json: Value = serde_json::from_str(&cred_string).unwrap();
        let w3c_cred = to_w3c(&cred_json);
        // match serde_json::to_string_pretty(&w3c_cred.unwrap()) {
        //     Ok(pretty_json) => println!("{}", pretty_json),
        //     Err(e) => println!("Error serializing JSON: {}", e),
        // }
        let mut file = File::create("./samples/credentials/w3c_credential.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&w3c_cred.unwrap())
                .unwrap()
                .as_bytes(),
        )
        .expect("Failed to write to file");
        // assert!(w3c_cred.is_ok());
    }

    #[ignore]
    #[test]
    fn test_to_anoncreds() {
        let mut file = std::fs::File::open("./samples/credentials/w3c_credential.json")
            .expect("Failed to open file");
        let mut content = String::new();
        file.read_to_string(&mut content)
            .expect("Failed to read file content");

        let w3c_cred = serde_json::from_str(&content).expect("Failed to parse JSON");
        let anoncreds_cred = to_anoncreds(&w3c_cred);
        assert!(anoncreds_cred.is_ok());
        // let anoncreds_cred = to_anoncreds(&w3c_cred).expect("Failed to convert to anoncreds");
        // let mut file = std::fs::File::create("./samples/credentials/anoncreds_credential.json").expect("Failed to create file");
        // file.write_all(serde_json::to_string_pretty(&anoncreds_cred).expect("Failed to serialize").as_bytes()).expect("Failed to write to file");
    }
}
