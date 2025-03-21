use crate::claim::{ClaimType, ClaimValidator, HashedClaim, NumberClaim, RevocationClaim};
use crate::credential::{ClaimSchema, CredentialSchema};
use crate::issuer::Issuer;
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{
    MembershipClaim, MembershipCredential, MembershipRegistry, MembershipSigningKey,
    MembershipStatement, MembershipVerificationKey,
};
use crate::presentation::{Presentation, PresentationSchema};
use crate::statement::{
    CommitmentStatement, RangeStatement, RevocationStatement, SignatureStatement,
    VerifiableEncryptionStatement,
};
use crate::{random_string, CredxResult};
use base64::Engine;
use blsful::inner_types::*;
use chrono::Utc;
use indexmap::indexmap;
use maplit::btreeset;
use rand::thread_rng;
use rand_core::RngCore;
use rmp_serde::{encode::write, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value, Map, Value};
use std::collections::HashMap;
use std::error::Error;

fn base64_encode(val: &[u8]) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(val)
}

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

fn encode_proofs<T: Serialize>(context: &str, proofs: &T) -> Result<String, Box<dyn Error>> {
    let mut buf = Vec::new();
    write(&mut buf, &(context, proofs))?;
    Ok("u".to_string() + &base64_encode(&buf))
}

fn decode_proofs<T: for<'de> Deserialize<'de>>(proofs: &str) -> Result<T, Box<dyn Error>> {
    let decoded = base64_decode(&proofs[1..])?;
    let mut de = Deserializer::new(&decoded[..]);
    let obj: T = Deserialize::deserialize(&mut de)?;
    Ok(obj)
}

fn create_presentation<S: ShortGroupSignatureScheme>(
) -> CredxResult<(Presentation<S>, PresentationSchema<S>, [u8; 16])> {
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
    let (issuer_public, mut issuer) = Issuer::new(&cred_schema);

    let credential = issuer.sign_credential(&[
        RevocationClaim::from(CRED_ID).into(),
        HashedClaim::from("John Doe").into(),
        HashedClaim::from("P Sherman 42 Wallaby Way Sydney").into(),
        NumberClaim::from(30303).into(),
    ])?;

    let dummy_sk = MembershipSigningKey::new(None);
    let dummy_vk = MembershipVerificationKey::from(&dummy_sk);
    let dummy_registry = MembershipRegistry::random(thread_rng());
    let dummy_membership_credential = MembershipCredential::new(
        MembershipClaim::from(&credential.credential.claims[2]).0,
        dummy_registry,
        &dummy_sk,
    );

    let sig_st = SignatureStatement {
        disclosed: btreeset! {"name".to_string()},
        id: random_string(16, thread_rng()),
        issuer: issuer_public.clone(),
    };
    let acc_st = RevocationStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: issuer_public.revocation_registry,
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let comm_st = CommitmentStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        message_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        blinder_generator: G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        ),
        claim: 3,
    };
    let verenc_st = VerifiableEncryptionStatement {
        message_generator: G1Projective::GENERATOR,
        encryption_key: issuer_public.verifiable_encryption_key,
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        claim: 0,
        allow_message_decryption: false,
    };
    let range_st = RangeStatement {
        id: random_string(16, thread_rng()),
        reference_id: comm_st.id.clone(),
        signature_id: sig_st.id.clone(),
        claim: 3,
        lower: Some(0),
        upper: Some(44829),
    };
    let mem_st = MembershipStatement {
        id: random_string(16, thread_rng()),
        reference_id: sig_st.id.clone(),
        accumulator: dummy_registry,
        verification_key: dummy_vk,
        claim: 2,
    };

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);

    let credentials = indexmap! { sig_st.id.clone() => credential.credential.into(), mem_st.id.clone() => dummy_membership_credential.into() };
    let presentation_schema = PresentationSchema::new(&[
        sig_st.into(),
        acc_st.into(),
        comm_st.into(),
        verenc_st.into(),
        range_st.into(),
        mem_st.into(),
    ]);

    let presentation = Presentation::create(&credentials, &presentation_schema, &nonce)?;
    Ok((presentation, presentation_schema, nonce))
    // presentation.verify(&presentation_schema, &nonce)?;
}

fn extract_related_statements(statements: &Value) -> Value {
    let mut sig_to_related = HashMap::new();
    let mut sig_def = HashMap::new();

    if let Value::Object(statements) = statements {
        // Identify all "Signature" statements
        for (st_id, st_data) in statements {
            if let Value::Object(st_data) = st_data {
                if let Some(sig) = st_data.get("Signature").and_then(|sig| sig.as_object()) {
                    if let (Some(issuer), Some(schema)) = (
                        sig.get("issuer").and_then(|i| i.as_object()),
                        sig.get("issuer")
                            .and_then(|i| i.as_object())
                            .and_then(|issuer| {
                                issuer.get("schema").and_then(|schema| schema.as_object())
                            }),
                    ) {
                        if let (Some(issuer_id), Some(schema_id)) =
                            (issuer.get("id"), schema.get("id"))
                        {
                            sig_to_related.insert(st_id.clone(), vec![st_id.clone()]);
                            sig_def.insert(
                                st_id.clone(),
                                json!({
                                    "issuer": {
                                        "id": issuer_id,
                                        "schema": schema_id,
                                    }
                                }),
                            );
                        }
                    }
                }
            }
        }

        // Relate other statements to these "Signature" statements
        for (st_id, st_data) in statements {
            if let Value::Object(st_data) = st_data {
                for key in [
                    "Revocation",
                    "VerifiableEncryption",
                    "Membership",
                    "Commitment",
                    "Range",
                ] {
                    if let Some(ref_id) = st_data
                        .get(key)
                        .and_then(|data| {
                            if key == "Range" {
                                data.get("signature_id")
                            } else {
                                data.get("reference_id")
                            }
                        })
                        .and_then(|v| v.as_str())
                    {
                        if let Some(related) = sig_to_related.get_mut(ref_id) {
                            related.push(st_id.clone());
                        }
                    }
                }
            }
        }
    }

    let sig_to_related_json: Value = sig_to_related
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();
    let sig_def_json: Value = sig_def.into_iter().collect();

    json!({
        "sig_to_related": sig_to_related_json,
        "sig_def": sig_def_json,
    })
}

pub fn extract_credential(request: &Value, proof: &Value) -> Vec<Value> {
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

    let mut ret = Vec::new();
    let presentation_requests = &request; // Required to obtain statement schema
    let presentation_proofs = proof["proofs"].as_object().unwrap();
    let disclosed_messages = &proof["disclosed_messages"];

    let extraction_result = extract_related_statements(&presentation_requests["statements"]);
    let related_statements = extraction_result["sig_to_related"].as_object().unwrap();
    let sig_def = extraction_result["sig_def"].as_object().unwrap();
    for (sig_id, rel_sts) in related_statements.iter() {
        let issuer_info = &sig_def[sig_id];

        let mut cred_subject: HashMap<String, HashMap<String, String>> = HashMap::new();

        if let Value::Array(disclosed_messages) = disclosed_messages {
            for message in disclosed_messages {
                if let Some(sig_id_str) = message.get(0).and_then(Value::as_str) {
                    if sig_id_str == sig_id {
                        if let Some(message_detail) = message
                            .get(1)
                            .and_then(Value::as_array)
                            .and_then(|arr| arr.first())
                        {
                            let field_name = message_detail
                                .get(0)
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            if let Some(hash_val) = message_detail
                                .get(1)
                                .and_then(|m| m.get("Hashed"))
                                .and_then(|v| v.get("value"))
                            {
                                cred_subject.insert(
                                    field_name.to_string(),
                                    HashMap::from([(
                                        "value".to_string(),
                                        hash_val.as_str().unwrap_or_default().to_string(),
                                    )]),
                                );
                            } else if let Some(num_val) = message_detail
                                .get(1)
                                .and_then(|m| m.get("Number"))
                                .and_then(|v| v.get("value"))
                            {
                                cred_subject.insert(
                                    field_name.to_string(),
                                    HashMap::from([(
                                        "value".to_string(),
                                        num_val.as_str().unwrap_or_default().to_string(),
                                    )]),
                                );
                            }
                        }
                    }
                }
            }
        }

        let mut proofs = HashMap::new();
        let mut claims_schema = Value::Null;

        if let Some(rel_sts_array) = rel_sts.as_array() {
            for i in rel_sts_array {
                let proof_key = i.as_str().unwrap_or_default();
                if let Some(proof) = presentation_proofs.get(proof_key) {
                    proofs.insert(proof_key.to_string(), proof.clone());

                    if let Some((st_type, _)) = proof.as_object().and_then(|obj| obj.iter().next())
                    {
                        if st_type == "Signature" {
                            cred_subject.insert(
                                "Signature".to_string(),
                                HashMap::from([("Signed".to_string(), "YES".to_string())]),
                            );
                            claims_schema = json!(
                                request["statements"][proof_key]["Signature"]["issuer"]["schema"]
                                    ["claims"]
                            );
                        } else if let Some(statement) = request
                            .get("statements")
                            .and_then(|sts| sts.as_object())
                            .and_then(|obj| obj.get(proof_key))
                        {
                            let mut key = &Value::Null;
                            let claim_idx = &statement[st_type]["claim"];
                            let claim_int: usize = claim_idx.to_string().parse().unwrap();
                            if &claims_schema[claim_int]["claim_type"] == "Revocation" {
                                key = &claims_schema[claim_int]["claim_type"];
                            } else {
                                key = &claims_schema[claim_int]["label"];
                            }

                            if st_type == "Revocation" {
                                match cred_subject
                                    .entry(key.as_str().unwrap_or_default().to_string())
                                {
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        let mut map = HashMap::new();
                                        map.insert("Revoked".to_string(), "NO".to_string());
                                        e.insert(map);
                                    }
                                    std::collections::hash_map::Entry::Occupied(mut e) => {
                                        e.get_mut().insert("Revoked".to_string(), "NO".to_string());
                                    }
                                }
                            } else {
                                match cred_subject
                                    .entry(key.as_str().unwrap_or_default().to_string())
                                {
                                    std::collections::hash_map::Entry::Vacant(e) => {
                                        let mut map = HashMap::new();
                                        map.insert(st_type.to_string(), "YES".to_string());
                                        e.insert(map);
                                    }
                                    std::collections::hash_map::Entry::Occupied(mut e) => {
                                        e.get_mut().insert(st_type.to_string(), "YES".to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let cred_proof_value = encode_proofs("2", &proofs);
        let cred = json!({
            "@context": contexts, // Assume CONTEXTS is available in this scope
            "type": ["VerifiableCredential", "AnonCredsPresentation"],
            "issuer": {
                "id": encode_identifier(issuer_info["issuer"]["id"].as_str().unwrap()),
                "schema": encode_identifier(issuer_info["issuer"]["schema"].as_str().unwrap()),
            },
            "issuanceDate": Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "credentialSubject": cred_subject,
            "proof": {
                "type": "AnonCredsPresentationProof2022",
                "proofValue": cred_proof_value.unwrap()
            },
        });

        ret.push(cred);
    }

    ret
}

fn to_w3c_presentation(request: &Value, proof: &Value) -> Value {
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

    let credentials = extract_credential(request, proof);
    let schema_id = request["id"].as_str().unwrap_or_default();
    let challenge = proof["challenge"].clone(); // Adjust based on actual structure and type

    json!({
        "@context": contexts,
        "type": ["VerifiablePresentation"],
        "schema": encode_identifier(schema_id),
        "verifiableCredential": credentials,
        "proof": {
            "cryptosuite": "anoncreds-2024",
            "type": "DataIntegrityProof",
            "proofPurpose": "authentication",
            "verificationMethod": "did:key:z6MkwXG2WjeQnNxSoynSGYU8V9j3QzP3JSqhdmkHc6SaVWoT/credential-definition",
            "proofValue": encode_proofs("3", &challenge).unwrap()
        }
    })
}

pub fn map_to_w3c_presentation<S: ShortGroupSignatureScheme>(
    presentation: &Presentation<S>,
    presentation_schema: &PresentationSchema<S>,
    nonce: &[u8; 16],
) -> Value {
    presentation
        .verify(presentation_schema, nonce)
        .expect("Verification should not fail");
    to_w3c_presentation(
        &to_value(presentation_schema).unwrap(),
        &to_value(presentation).unwrap(),
    )
}

fn decode_credential_from_w3c(
    w3c_presentation: &Value,
) -> CredxResult<(Map<String, Value>, Map<String, Value>)> {
    let credential = &w3c_presentation["verifiableCredential"];
    let credential_list = credential.as_array().unwrap();
    let mut disclosed_msg = Map::new();
    let mut combined_proofs = Map::new();

    for c in credential_list {
        let credential_proof = &c["proof"]["proofValue"];
        let decode_proof: (String, HashMap<String, Value>) =
            decode_proofs(credential_proof.as_str().unwrap()).unwrap();
        combined_proofs.extend(decode_proof.1.clone());

        let mut signature_id = String::new();
        for (key, value) in decode_proof.1 {
            if let Some(inner_map) = value.as_object() {
                if inner_map.contains_key("Signature") {
                    signature_id = key.clone();
                    break;
                }
            }
        }

        let credential_subject = &c["credentialSubject"];
        let credential_subject_map = credential_subject.as_object().unwrap();

        let mut msg = HashMap::new();
        for (k, v) in credential_subject_map {
            if let Some(inner_map) = v.as_object() {
                if let Some(Value::String(inner_value)) = inner_map.get("value") {
                    msg.insert(k.clone(), inner_value.clone());
                }
            }
        }
        disclosed_msg.insert(signature_id, to_value(&msg).unwrap());
    }
    Ok((disclosed_msg, combined_proofs))
}

fn transform_disclosed_msg(input: &Map<String, Value>) -> Value {
    input
        .iter()
        .map(|(key, value_map)| {
            json!([
                key,
                value_map.as_object().map_or_else(Vec::new, |vm| {
                    vm.iter()
                        .map(|(inner_key, inner_value)| {
                            json!([
                                inner_key,
                                {
                                    "Hashed": {
                                        "value": inner_value,
                                        "print_friendly": true
                                    }
                                }
                            ])
                        })
                        .collect::<Vec<_>>()
                })
            ])
        })
        .collect::<Vec<_>>()
        .into()
}

pub fn to_anon_creds_presentation(w3c_presentation: &Value) -> Value {
    let challenge_proof = &w3c_presentation["proof"]["proofValue"];
    let challenge: (String, String) = decode_proofs(challenge_proof.as_str().unwrap()).unwrap();
    // let presentation_schema_id = decode_identifier(&w3c_presentation["schema"].as_str().unwrap());
    let (disclosed_msg, proofs) = decode_credential_from_w3c(w3c_presentation).unwrap();
    json!({
        "proofs": proofs,
        "challenge":challenge.1,
        "disclosed_msg": transform_disclosed_msg(&disclosed_msg),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knox::ps::PsScheme;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_create_presentation() {
        // returns a list of presentation + presentation request
        let presentation = create_presentation::<PsScheme>().unwrap();
        let mut file = File::create("./samples/presentations/anoncreds_presentation_list.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&presentation)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");
    }

    #[test]
    fn test_encode_decode_presentation() {
        let context = "1";
        let proofs: Vec<&str> = vec!["proof1", "proof2"];
        let encoded = encode_proofs(context, &proofs).expect("Failed to encode");
        println!("Encoded: {}", encoded);
        // let test = "ukqEyhtkgMGEyOWRlZDM0NWRmOTJlYWFiMGI3YTY5OGFlMDIzOTCBqVNpZ25hdHVyZYOyZGlzY2xvc2VkX21lc3NhZ2VzgaEx2UAzNWU0YmQ0MzAzYTgwZjFjZTY1ZGFhY2FkY2M2ZDQ3ZTgwNDFiNjBmM2VhODEwYWFlMmRjYmFjYTIzZDExYThiomlk2SAwYTI5ZGVkMzQ1ZGY5MmVhYWIwYjdhNjk4YWUwMjM5MKNwb2uEqmNvbW1pdG1lbnTZwDk5NGVlMjQyMzEyN2E0ZDMwNWFlMTFhNzQ5ODczNDQ1NjkyMTI4NDY3NGVmMmNkNDBkMTkzZGVjNjU1MjM0ZWExMDRlZDJkM2EyMTUzZGQwODEzOTJiMzQ5YzZmOTQ2ZDAzNTgzNjhjZjdkODBjNTQ2YzFkYTY3N2NlMDliMjM0ZmI4YTMxZmNlYjNhOGRhNTI4YjQyMjFiNjgzMGRjYjlmOWQyZjkxNTNhMjhmZDY2MjNjZTFjZmU3NDhiZmQ5NKVwcm9vZpXZQDI4NGY3NzdhMDNiNDYyYjJkYmUxNmFlOTk0YjE2ODM2ZmY4M2E3OTIyNDc2ZWY1YmQ0Mzg1MmQwZGMzYWE5MDnZQDAyNTMzNDZjNTQ4Njg3NmQ0MmM4YjFlOWY3Y2UzYTQxZjNkOWE2YzA2YjM1ZjZiMjkyOTZhZDVmODhhZmYxYzLZQDUwNjU5YWQ0YzVmZGIwYjE1NjEzNTJhZWQ3ZTYyZTA4ZDU0NGZjODhmZWQxNjAzNDdhZjBkZTYxOWY2MWZhZDHZQDM0Y2Q0MTE5YTYwYTY0NTMxZWIyOGU3MTU1MjkzYWE5ZjllYzVlNDFlYWU2M2E4ODU3MDY2M2JkN2Q5N2I1ODLZQDA3MGFlMDVmNWI2YTMzMzBhYTI5YWMyNDI2MDNiODU4OTEyZjZmOWU5YTlkYmI5MzMzNDZmNTc2N2ZjMDZiOGanc2lnbWFfMdlgYWM4ZjFhOGJkMTVmN2QzMzlhODQwNzZkOTYzODQyMWU0NmFjYjA0NThkMDZhMzBhNTk1OGI3NDlhNTJmM2VmYTM3YWY5M2MwNDJkNWY4ODMwNWM5MmM2ZDU5ZmI5NmZip3NpZ21hXzLZYGI4NTBmNmQ2MWZkODI4YmU3ODc4YWJiY2ZjMDE1MjJmZjQ4YTgxZDZjZjg1MzljMjMyODViNjkzZDg1OGU5NDhkOTVlZjFhMzUyYWE4MmEwNTcxMzdmODhlNzJkYzNlNdkgNDY0OTRiMTZlZWU4NDUzMDJkYjAyYzM5ZTUwYTA4OWOBqk1lbWJlcnNoaXCComlk2SA0NjQ5NGIxNmVlZTg0NTMwMmRiMDJjMzllNTBhMDg5Y6Vwcm9vZoijZV9j2WBiNTIxOGNkY2Y4ODFhZTIyYzM3MTMwYTMyZTFhOTcxY2VmZWU2ZThkMzY5Y2ZkODg3OWZiNTc5MzNmNTQwNmQ0NzhiZmI3YjgxNzVhMTZkZDgwMDZhNGExMzYzNWNlMTerc19kZWx0YV9yaG_ZQDBiNjA0MmUyM2NjYmM1Mjk2M2U1ZjgzMWExMDdhYTMzNGM3NzhmYjg4ZDkzMTcyOGZlM2JiNzhkNTVjZGU1NzCtc19kZWx0YV9zaWdtYdlANjllZjM5MmMwMTAwYTE1MGVlOTQzZDRiZThjZjFjZmE5YWFiZThhZGY5YjQwNTc2YjZiZDI3Y2E3NzdiMDE1N6VzX3Job9lAM2ExODgwNzYxY2RiMzVjNjZjNWI0YTg3YTMxYWQ4ZTE2MmQyNzc5MGY3MWM2ZDlkZjJmMGUxNmUwNjY1YmNlZadzX3NpZ21h2UAxYTUwODJhODA0NTdlNDA1ODIwMTFlNmQ1MDgzODJhNjc2YWYzZTg4NTRjMDQ4OTEyMWUwMDc5NGY2ZGMyZTg0o3NfedlAMzRjZDQxMTlhNjBhNjQ1MzFlYjI4ZTcxNTUyOTNhYTlmOWVjNWU0MWVhZTYzYTg4NTcwNjYzYmQ3ZDk3YjU4MqV0X3Job9lgOGI5OTY1ZmU3ZDQ1ZDQyMDdkMzFmZDZlYWMzMjU2NWY3ZjY5NGViYmViNzY3NDE4NDY3OTQxMDQ4NTZiYzQzZDYyYTRkNzM0YjhjNTdmNGI1MjViM2QyMzhjMTAyOGQ1p3Rfc2lnbWHZYDgwOWU2NzM0MTJlZjlmMzg5MGIxYTk3NjkzNTgzZDVkMDY0MjNkNmJjNWE3MTAzMmI4YWFjNWI5NzFhZWY1OGM4MmFkY2EyNWNjZTExYjFjNTEwNjg0M2YzYzE0YWU4MdkgNDc1ZjUwYmQ3NGY4MjFmYWJkZWRjNzk2NGQ2MDk1OGSBqlJldm9jYXRpb26Comlk2SA0NzVmNTBiZDc0ZjgyMWZhYmRlZGM3OTY0ZDYwOTU4ZKVwcm9vZoijZV9j2WA5MzQ1YzQxYWZmMjhjMjY0OWY5ODE4Nzc2MmFhZjM4ZjI4N2RiYzQ3MDZhN2MwODdiNTZhNDNjMjM2Y2ZlNTI5YjY2NTFhYjc3MTljM2I5ZDgwZGU3M2RlMzExMDBhMTGrc19kZWx0YV9yaG_ZQDA0MTVkZjIzODFlY2EzNWI3NDIzYzYxNmNkN2JhYWRkNWU4ZTVlMjliMTc1YzJmNzJmNDAyMjkzNjA2MDlhNDetc19kZWx0YV9zaWdtYdlAMDhjNjk2NDEwYjQxYWM4Yzg3NGY2YjBmNDJkN2NmM2RhMTgxMmEyNmNhOTlmYWYwM2YyMTg1ODU1MTY2NjI5MaVzX3Job9lANjU1Y2IwYWJmM2I0OWYxZTM0NzE0MThlYzc5ZjkzMGFlYzE1NjkwZDE1YjI3NDMzMWU1NTdmZjA0NDhjOGJkOKdzX3NpZ21h2UAyY2EyZGI5MWNkYWRkMTJjOTg3NWNiNDk0NjUyMDhjOGZlZTRmZDIwY2Q0M2NiNGU2OWQ2OGJhN2U5ZTFiZTFho3NfedlANTA2NTlhZDRjNWZkYjBiMTU2MTM1MmFlZDdlNjJlMDhkNTQ0ZmM4OGZlZDE2MDM0N2FmMGRlNjE5ZjYxZmFkMaV0X3Job9lgYjc1ZmY3MTlhYjI4MzQ0MDAxODk0ZGQ1NTcyOTJhYzZlNjc5ZmUxODFjYTBjZjgzYjFkMDdkNGI0NjMxNWMxNTA1MmZjMWE1ODUwMjc0ZDgwNjA3NjBiM2Q3ZmYxNTE0p3Rfc2lnbWHZYGFlYTIwMzZhY2M5YzQ3M2RlYWIxOGIzN2IwYTUxN2VlNzY2ZWEzYWMzNmUzYmVhMjAyN2ExYTUwZGRiYjkxODM5OTc3OTExNzEyYzFhNTcyZmMzYzNkYTliOGRhNzlmMdkgNGViNDBkZGFmMTU0MjU3MGZkOWI0NmNmMWJhZjQ1MmGBtFZlcmlmaWFibGVFbmNyeXB0aW9uha1ibGluZGVyX3Byb29m2UAyNzc2YjM2NzgxMmM3MDVhODNiNDI1MTMxYmE0N2IzYTA5MjQwNWVkYmJhYjRlMTAxZjdiZDQ0YTRhMjE3ZDYxomMx2WA4YjA5ZTFiNWY3MjBjMzYwMzQ2OWQ5OGY1MDFhZTI4NDkzYTZhY2ExZTdjMTMwNmYyMmYzMzcwODYwODhkZDNmODVkNzBjMTY2MzBhNTdkNDFjMTA5YTQ4YjY1YTQ0ODWiYzLZYDg4ZDQwNzE2YzRhZDEwZTk4YjhmNjI5MzE3NTlhYzY2MmRmZDZjYmFkYmExZDkwZTQwZDdiMmFmYjZkMjYyOTRiNzA0NjJjMjE2NTViNjFiM2M0YTBkNzg0MDgxYjRiMKJpZNkgNGViNDBkZGFmMTU0MjU3MGZkOWI0NmNmMWJhZjQ1MmGtbWVzc2FnZV9wcm9vZtlANTA2NTlhZDRjNWZkYjBiMTU2MTM1MmFlZDdlNjJlMDhkNTQ0ZmM4OGZlZDE2MDM0N2FmMGRlNjE5ZjYxZmFkMdkgNjAyZGM0NGRiOTk3MGFiOTY4MWYyNWIxZGVjZjhlMmOBqkNvbW1pdG1lbnSErWJsaW5kZXJfcHJvb2bZQDY3OGQ5YjYzYjVmYjkyMjdhMzQ3NzM0OWUyZDhmMjE1ZmExYzc3MDRkN2UwMzU4OTFlNGM0NDI5NTE3YWQ3M2GqY29tbWl0bWVudNlgYWZhZmE5MTdkZTA2ZWVhY2JmODNmNWNiM2E3YzNlN2UwMjUzM2Q3YWY1YmRjZWE5MDE4ZDFjZjJkYjI3YmViNzQzOWYyMzMyNTFmMWUxOGNiZDY2NTFkMmFlMTliYzdiomlk2SA2MDJkYzQ0ZGI5OTcwYWI5NjgxZjI1YjFkZWNmOGUyY61tZXNzYWdlX3Byb29m2UAwNzBhZTA1ZjViNmEzMzMwYWEyOWFjMjQyNjAzYjg1ODkxMmY2ZjllOWE5ZGJiOTMzMzQ2ZjU3NjdmYzA2Yjhm2SAyZTBhN2MyYjY4YTA4OGJhYWJiNGFjZjUyODQ4OTI4N4GlUmFuZ2WComlk2SAyZTBhN2MyYjY4YTA4OGJhYWJiNGFjZjUyODQ4OTI4N6Vwcm9vZtwEAMypzJxKzIvM7WtdzPptfEVqP8zFzOLM037MzyYIzJh3UQRxCsyRzJoxzKESzOc5zJ3MkicxAFcBzNPMnMzaWzJtzNFrzKdPzMxsGsyXzLFdzNrMzsyLCmcvB8zpzIAncMzwzLM9dFvMnmXM_FzM2CbMi8zLK0tiXhdYZMz-zJZlzJpazMpaGMzczKhPF8zxB39PTsy0zJBOey8gzKMBzKgOzPjMzmnM3VlgQcyIzJdtJAnM2yLMqibMmx5QcE3M0syQzNjMuh7Mxjs2UMyxbsymeczIcycqzMowzNfMgMyuzK7M-sz3zIF8zIVuzJjM-2RzPGvMjczjVgXMgMzAWMz8CMz6zJbM9iNWzIw8S1XM7FvMrlMGcszXQczQzNjMiW1HR00AVMymPDgjzN9GF3VTzOchYcyQGMzCzITMrcyFAz7M0cz_zP8sO3IGTMyXYszkzPLM7MygRsyazIHM0MyczMnM4sy4zITMlSQ2ScyVNAB5LcyizLMuGsyOdMznQcyGzMbMtMyCC3U-zNt3aczwXHnMqkXM2CjM0QfMosy6KTxEzMPMpCIXdjPM0D7M033MhczfXsz5EszCMcyEIcyxV8zQzKN2zI9UAhTMw1VqbF9gdMztzKQgMzXMvczAzNvMrszmzL_MqnDMw8yjNRpLzKfMwszqZMzczLPM2cypN3bMqMzPbMy6KljM_X0KRUXM6k_MjMztfCnM33Q4zJpbzOxazM0QzMU2zLUiGg3MoX_M61U7zN4yzN_M-G7MlnjMtMy6zIzM68yTzJnMmXfMow_M9w7MwcyHzM4aCcyczJRqThUJckrMqjUQSE1qzKI8EMzIa8yrcszQzNzMtcz4EyNPdczEcmnM1E3MysykKmjMw3U7zOwAzLfMx8yjVsznPsyWKj7Mt37M4sy1fiTMuszEzIJ2esysbE3MxcyyzMHM_8ydD8yTd8zjHcyQHiHMsMzSzPwfzKo-zP7M5AlRNV0hzI50zJ7M_szCScygaMyHzPTMs8zozI49fXnMiVJpzN_M58zSUBQBNRbM11zMuwfMjgHM4MzWzOZDXsyhzKpezK9LeUjMqszuJcy7T8zKzMPMxxDMjMyRWHTMsMyYzJTMoczSQn9ezPtfbmpQzKzMknLMqsziC8yTzK3MmszkzKUfzObMjyXM8MyYzPDMs03Mt3rM80g6aTJtWsy7BiJyzJPMrEYLzK7M08yBzK_Mp8ywzI8FfSnMvAN2zJxGzJpmzPnMxszPCcz8zJfMwnlLzNLMiMyHzMxPayvMoGFLEcybzNokREoOQ0xrzMlWzLpXzLNWzNx3L8zUzJxVzMjMiszqQmDMpgbMzXY6zLA8zOM8zNZqzIHMtcznSzYvB8z7JMzOJMyxcMzDO3LM6MzrzPPM-yDMgVPMlczZzL9hBAN1QCnMlT0gasz6zLnM-FjMscz3zMVlzPzM1MzczIcPzIXMk8yeIFrMgMz_aknMnczlzNnMgszMzOjM1FXM2GkWdg7M3nTM5symzKPM9lDM00gWR8zYNcy2KCXMzMzHzNPMqMzWUcyLzKZIOsyyzLpCF8yNzLfM8MzKzMHM2DHMqX7MgiwxzPbM3czhzIA4zKvMjsyQzPzMsDfMxhQgzMzM0MzozI7M3syGzKrM-8yhfVNGzORJDRjMix7MsMzNAczBzLLMo3rMjsy-YszGBhl_zMgJDMyTzNHMrsznJMzdzOMzAMzUOcycUi7Mn8zNzMTMqczKXDDM2Ul6zPfMzczzKszyzKDM18yBNRDMk3DMysydSsy4zKhyzNXMgsyLOsypzJ3MkszpRsyWzIHM_QzMgzI8WhQ_aA80f0UdBC7MoyjM1ynM2iTMgMy-zOkSzK3MtVIBEMzdzPVCzIZeHAXM43YhTngxHMzWHGEwIMyFcFBCHcyuZMzyzIFZNQdWzIvMzCXMyszyzP0FzNvMgMyHAcyYeRlZzJ1TzIUqzJoEzM7M_My-OcySzIXMzCZZVCPMrcyMWy_MxMyFfGMUEcy8zNvM3czEOA44zLjMpWYkzN9yzJIrzNnM4w".to_string();
        let decoded: (String, Value) = decode_proofs(&encoded).expect("Failed to decode");
        println!("Decoded context: {}, proofs: {:?}", decoded.0, decoded.1);
    }

    #[test]
    fn test_extract_related_statements() {
        let input = json!({
            "48f57e057e1d8a0dd0053c9a0fb0aa40": {
                "Signature": {
                    "issuer": {
                        "id": "d1bc208a7d0695e8cf2f3a3fe3e1f620",
                        "schema": {
                            "id": "89c31714307f6522379ad99b473ee364"
                        }
                    }
                }
            },
            "60e6ec5f20fcc7677f0aa13f190776d9": {
                "Range": {
                    "reference_id": "48f57",
                    "signature_id": "48f57e057e1d8a0dd0053c9a0fb0aa40",
                }
            }
        });
        let result = extract_related_statements(&input);
        let expected_sig_to_related = json!({
            "48f57e057e1d8a0dd0053c9a0fb0aa40": ["48f57e057e1d8a0dd0053c9a0fb0aa40", "60e6ec5f20fcc7677f0aa13f190776d9"]
        });
        assert_eq!(result["sig_to_related"], expected_sig_to_related);
    }

    #[test]
    fn test_extract_credential() {
        let tmp_list = create_presentation::<PsScheme>().unwrap();

        let presentation_proof = tmp_list.0.clone();
        let presentation_request = tmp_list.1.clone();

        let result = extract_credential(
            &to_value(&presentation_request).unwrap(),
            &to_value(&presentation_proof).unwrap(),
        );
        assert!(!result.is_empty(), "The result should not be empty.");
    }

    #[test]
    fn test_transform_input() {
        let mut map: Map<String, Value> = Map::new();
        map.insert("asdasdasd12312412".into(), json!({"number": 123435}));

        let expected_output = json!([
            [
                "asdasdasd12312412",
                [
                    [
                        "number",
                        {
                            "Hashed": {
                                "value": 123435,
                                "print_friendly": true
                            }
                        }
                    ]
                ]
            ]
        ]);

        let actual_output = transform_disclosed_msg(&map);
        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn test_to_w3c_presentation() {
        // let mut file = File::open("./samples/presentations/anoncreds_presentation_sample.json")
        //     .expect("Failed to open the sample file");
        // let mut content = String::new();
        // file.read_to_string(&mut content)
        //     .expect("Failed to read the sample file");
        // let presentation: Value =
        //     serde_json::from_str(&content).expect("Failed to parse the JSON content");

        let tmp_list = create_presentation::<PsScheme>().unwrap();
        let mut file = File::create("./samples/presentations/anoncreds_presentation_list.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&tmp_list)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");

        let presentation_proof = tmp_list.0.clone();
        let presentation_request = tmp_list.1.clone();
        let nonce: [u8; 16] = tmp_list.2.clone();
        presentation_proof
            .verify(&presentation_request, &nonce)
            .expect("Verification should not fail");

        let result = to_w3c_presentation(
            &to_value(&presentation_request).unwrap(),
            &to_value(&presentation_proof).unwrap(),
        );

        match serde_json::to_string_pretty(&result) {
            Ok(pretty_json_str) => println!("{}", pretty_json_str),
            Err(e) => println!("Error serializing JSON: {}", e),
        }
    }

    #[test]
    fn test_map_to_w3c_presentation() {
        let tmp_list = create_presentation::<PsScheme>().unwrap();
        let presentation_proof = tmp_list.0.clone();
        let presentation_request = tmp_list.1.clone();
        let nonce: [u8; 16] = tmp_list.2.clone();

        let w3c_presentation =
            map_to_w3c_presentation(&presentation_proof, &presentation_request, &nonce);
        let mut file = File::create("./samples/presentations/w3c_presentation.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&w3c_presentation)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");
    }

    #[ignore]
    #[test]
    fn test_to_anoncreds_presentation() {
        let tmp_list = create_presentation::<PsScheme>().unwrap();
        let presentation_proof = tmp_list.0.clone();
        let presentation_request = tmp_list.1.clone();
        let nonce: [u8; 16] = tmp_list.2.clone();

        let mut file = File::create("./samples/presentations/anoncreds_presentation_list.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&tmp_list)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");

        let w3c_presentation =
            map_to_w3c_presentation(&presentation_proof, &presentation_request, &nonce);
        let mut file = File::create("./samples/presentations/w3c_presentation.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&w3c_presentation)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");

        let result = to_anon_creds_presentation(&w3c_presentation);
        // match serde_json::to_string_pretty(&result) {
        //     Ok(pretty_json_str) => println!("{}", pretty_json_str),
        //     Err(e) => println!("Error serializing JSON: {}", e),
        // }
        let mut file = File::create("./samples/presentations/anoncreds_output.json")
            .expect("Failed to create file");
        file.write_all(
            serde_json::to_string_pretty(&result)
                .expect("Failed to serialize")
                .as_bytes(),
        )
        .expect("Failed to write to file");
    }
}
