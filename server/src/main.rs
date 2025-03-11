#![allow(non_snake_case)]

// based on okapi/examples/custom_schema

// ------------------------------------------------------------------------------
use credx::vcp::interfaces::types::*;
// ------------------------------------------------------------------------------
use rocket::{get,post};
use rocket::data::{ByteUnit, Limits};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use rocket_okapi::settings::UrlObject;
use rocket_okapi::{openapi, openapi_get_routes};
use rocket_okapi::rapidoc::*;
use rocket_okapi::swagger_ui::*;
// ------------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// ------------------------------------------------------------------------------

mod misc;
use misc::*;
mod query_param_guards;
use query_param_guards::*;

/// # Create the secret and public data used to sign and verify credentials.
///
/// Returns SignerData.
// #[openapi(tag = "Signer")]
#[openapi()]
#[post("/vcp/createSignerData?<rng_and_zkp..>", data = "<dat>")]
fn createSignerData(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
    dat         : Json<Vec<ClaimType>>,
) -> Result<Json<SignerData>, (Status, Json<Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "createSignerData")?;
    let op          = api.create_signer_data;
    op(seed, &dat).map_or_else(
        |e| vcpErr(e, "createSignerData"),
        |v| Ok(Json(v)))
}

/// # Create an accumulator and its associated secret/public data.
///
/// Returns CreateAccumulatorResponse.
// #[openapi(tag = "Accumulator Manager")]
#[openapi()]
#[post("/vcp/createAccumulatorData?<rng_and_zkp..>")]
fn createAccumulatorData(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
) -> Result<Json<CreateAccumulatorResponse>, (Status, Json<Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "createAccumulatorData")?;
    let op          = api.create_accumulator_data;
    op(seed).map_or_else(
        |e| vcpErr(e, "createAccumulatorData"),
        |v| Ok(Json(v)))
}

/// Sign the given values using the secret data, setup data and claim types (i.e., schema) in the given SignerData.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
struct SignRequest {

    /// The values to be signed.
    values     : Vec<DataValue>,

    /// See SignerData.
    signerData : SignerData,
}

/// # Create a signature from the given values and SignerData.
///
/// Returns Signature.
// #[openapi(tag = "Signer")]
#[openapi()]
#[post("/vcp/sign?<rng_and_zkp..>", data = "<dat>")]
fn sign(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
    dat         : crate::DataResult<'_, SignRequest>,
) -> Result<Json<Signature>, (Status, Json<misc::Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "sign")?;
    let dat         = dat.map_or_else(
        |e| err(format!("{:?}", e), "sign"),
        |v| Ok(v.into_inner()))?;
    let op = api.sign;
    op(seed, &dat.values, &dat.signerData).map_or_else(
        |e| vcpErr(e, "sign"),
        |v| Ok(Json(v)))
}

/// # Create an accumulator element from the given text.
///
/// Returns AccumulatorElement.
// #[openapi(tag = "Accumulator Manager")]
#[openapi()]
#[post("/vcp/createAccumulatorElement?<zkp..>", data = "<text>")]
fn createAccumulatorElement(
    zkp  : ZkpLibQueryParam,
    text : crate::DataResult<'_, String>,
) -> Result<Json<AccumulatorElement>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "createAccumulatorElement")?;
    let dat = text.map_or_else(
        |e| err(format!("{:?}", e), "createAccumulatorElement"),
        |v| Ok(v.into_inner()))?;
    let op  = api.create_accumulator_element;
    op(dat).map_or_else(
        |e| vcpErr(e, "createAccumulatorElement"),
        |v| Ok(Json(v)))
}

/// Elements (if any) to be added to, and elements (if any) to be removed from an accumulator.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
struct AccumulatorAddRemoveRequest {

    /// See Accumulator Data.
    accumulatorData : AccumulatorData,

    /// See Accumulator.
    accumulator     : Accumulator,

    /// Elements to be added. This is a map associating each element to be added with an (ephemeral) ID that can be used by the requester (e.g., Signer/Issuer) to determine who should receive the returned witness.
    additions       : HashMap<HolderID, AccumulatorElement>,

    /// Elements to be removed.
    removals        : Vec<AccumulatorElement>
}

/// # Add and/or remove elements from an accumulator.
///
/// Returns AccumulatorAddRemoveResponse.
// #[openapi(tag = "Accumulator Manager")]
#[openapi()]
#[post("/vcp/accumulatorAddRemove?<zkp..>", data = "<dat>")]
fn accumulatorAddRemove(
    zkp : ZkpLibQueryParam,
    dat : crate::DataResult<'_, AccumulatorAddRemoveRequest>,
) -> Result<Json<AccumulatorAddRemoveResponse>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "accumulatorAddRemove")?;
    let dat = dat.map_or_else(
        |e| err(format!("{:?}", e), "accumulatorAddRemove"),
        |v| Ok(v.into_inner()))?;
    let op  = api.accumulator_add_remove;
    op(&dat.accumulatorData, &dat.accumulator, &dat.additions, &dat.removals).map_or_else(
        |e| vcpErr(e, "accumulatorAddRemove"),
        |v| Ok(Json(v)))
}

/// Used to update an existing witness after additions and/or removals from an accumulator.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
struct UpdateAccumulatorWitnessRequest {

    /// The existing witness before the update.
    witness           : AccumulatorMembershipWitness,

    /// The element used to create the existing witness.
    element           : AccumulatorElement,

    /// Data returned from accumulatorAddRemove.
    witnessUpdateInfo : AccumulatorWitnessUpdateInfo
}

/// # Update an accumulator witness.
///
/// Returns AccumulatorMembershipWitness.
// #[openapi(tag = "Accumulator Manager")]
#[openapi()]
#[post("/vcp/updateAccumulatorWitness?<zkp..>", data = "<dat>")]
fn updateAccumulatorWitness(
    zkp : ZkpLibQueryParam,
    dat : crate::DataResult<'_, UpdateAccumulatorWitnessRequest>,
) -> Result<Json<AccumulatorMembershipWitness>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "updateAccumulatorWitness")?;
    let dat = dat.map_or_else(
        |e| err(format!("{:?}", e), "updateAccumulatorWitness"),
        |v| Ok(v.into_inner()))?;
    let op  = api.update_accumulator_witness;
    op(&dat.witness, &dat.element, &dat.witnessUpdateInfo).map_or_else(
        |e| vcpErr(e, "updateAccumulatorWitness"),
        |v| Ok(Json(v)))
}

/// # Create accumulator membership proving key.
///
/// Returns MembershipProvingKey.
// #[openapi(tag = "Accumulator Manager")]
#[openapi()]
#[post("/vcp/createMembershipProvingKey?<rng_and_zkp..>")]
fn createMembershipProvingKey(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
) -> Result<Json<MembershipProvingKey>, (Status, Json<Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "createMembershipProvingKey")?;
    let op          = api.create_membership_proving_key;
    op(seed).map_or_else(
        |e| vcpErr(e, "createMembershipProvingKey"),
        |v| Ok(Json(v)))
}

/// # Create range proof proving key.
///
/// Returns RangeProofProvingKey.
// #[openapi(tag = "Verifier")]
#[openapi()]
#[post("/vcp/createRangeProofProvingKey?<rng_and_zkp..>")]
fn createRangeProofProvingKey(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
) -> Result<Json<RangeProofProvingKey>, (Status, Json<Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "createRangeProofProvingKey")?;
    let op          = api.create_range_proof_proving_key;
    op(seed).map_or_else(
        |e| vcpErr(e, "createRangeProofProvingKey"),
        |v| Ok(Json(v)))
}

/// # Get the maximum value supported in range proofs for the specific zkpLib.
///
/// Returns the maximum value.
// #[openapi(tag = "Verifier")]
#[openapi()]
#[get("/vcp/getRangeProofMaxValue?<zkp..>")]
fn getRangeProofMaxValue(
    zkp : ZkpLibQueryParam,
) -> Result<Json<u64>, (Status, Json<Error>)> {
    let api = getApiFromQP(zkp, "getRangeProofMaxValue")?;
    let op  = api.get_range_proof_max_value;
    Ok(Json(op()))
}

/// # Create authority data.  Used in verifiable encryption.
///
/// Returns AuthorityData.
// #[openapi(tag = "Authority")]
#[openapi()]
#[post("/vcp/createAuthorityData?<rng_and_zkp..>")]
fn createAuthorityData(
    rng_and_zkp : RngSeedAndZkpLibQueryParams,
) -> Result<Json<AuthorityData>, (Status, Json<Error>)> {
    let (seed, api) = getSeedAndApi(rng_and_zkp, "createAuthorityData")?;
    let op          = api.create_authority_data;
    op(seed).map_or_else(
        |e| vcpErr(e, "createAuthorityData"),
        |v| Ok(Json(v)))
}

/// Information used for creating a proof.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
struct CreateProofRequest {

    /// Proof requirements as specified by the Verifier.
    proofReqs          : HashMap<CredentialLabel, CredentialReqs>,

    /// A map of parameter names to values (e.g., public keys).
    sharedParams       : HashMap<SharedParamKey, SharedParamValue>,

    /// A map of credential labels to SignatureAndRelatedData.
    sigsAndRelatedData : HashMap<CredentialLabel, SignatureAndRelatedData>,

    //looseOrStrict      : Option<ProofMode>,

    /// Arbitrary text.
    nonce              : String, // API.Nonce
}

/// # Create a proof with respect to proof requirements from a Verifier.
///
/// Returns WarningsAndDataForVerifier.
// #[openapi(tag = "Holder")]
#[openapi()]
#[post("/vcp/createProof?<zkp..>", data = "<dat>")]
fn createProof(
    zkp : ZkpLibQueryParam,
    dat : crate::DataResult<'_, CreateProofRequest>,
) -> Result<Json<WarningsAndDataForVerifier>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "createProof")?;
    let dat = dat.map_or_else(
        |e| err(format!("{:?}", e), "createProof"),
        |v| Ok(v.into_inner()))?;
    let op  = api.create_proof;
    op(&dat.proofReqs, &dat.sharedParams, &dat.sigsAndRelatedData,
       ProofMode::Strict, Some(dat.nonce)).map_or_else(
        |e| vcpErr(e, "createProof"),
        |v| Ok(Json(v)))
}

/// Information (including the proof) to verify a proof.
#[derive(Serialize, Eq, PartialEq, Deserialize, Clone, Debug, JsonSchema)]
struct VerifyProofRequest {

    /// Agreed proof requirements.
    proofReqs       : HashMap<CredentialLabel, CredentialReqs>,

    /// A map from parameter labels to associated parameter values.
    sharedParams    : HashMap<SharedParamKey, SharedParamValue>,

    /// See DataForVerifier.
    dataForVerifier : DataForVerifier,

    /// A map from credential label to a map of credential attributed index to DecryptRequest.
    decryptRequests : HashMap<CredentialLabel,
                              HashMap<CredAttrIndex,
                                      HashMap<SharedParamKey, DecryptRequest>>>,
    //looseOrStrict      : Option<ProofMode>,

    /// Arbitrary text.
    nonce           : String, // API.Nonce
}

/// # Verify a proof with respect to proof requirments.
///
/// Returns WarningsAndDecryptResponses.
// #[openapi(tag = "Verifier")]
#[openapi()]
#[post("/vcp/verifyProof?<zkp..>", data = "<dat>")]
fn verifyProof(
    zkp : ZkpLibQueryParam,
    dat : crate::DataResult<'_, VerifyProofRequest>,
) -> Result<Json<WarningsAndDecryptResponses>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "verifyProof")?;
    let dat = dat.map_or_else(
        |e| err(format!("{:?}", e), "verifyProof"),
        |v| Ok(v.into_inner()))?;
    let op  = api.verify_proof;
    op(&dat.proofReqs, &dat.sharedParams, &dat.dataForVerifier, &dat.decryptRequests,
       ProofMode::Strict, Some(dat.nonce)).map_or_else(
        |e| vcpErr(e, "verifyProof"),
        |v| Ok(Json(v)))
}

/// Verify that each decrypted value is correct.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
struct VerifyDecryptionRequest {

    /// Agreed proof requirements.
    proofReqs        : HashMap<CredentialLabel, CredentialReqs>,

    /// A map from parameter labels to associated parameter values.
    sharedParams     : HashMap<SharedParamKey, SharedParamValue>,

    /// See Proof.
    proof            : Proof,

    /// Map from Authority label to decryption key.
    decryptionKeys   : HashMap<SharedParamKey, AuthorityDecryptionKey>,

    /// Map from credential label to credential attribute index to DecryptResponse.
    decryptResponses : HashMap<CredentialLabel,
                               HashMap<CredAttrIndex,
                                       HashMap<SharedParamKey, DecryptResponse>>>,
    //looseOrStrict      : Option<ProofMode>,

    /// Arbitrary text.
    nonce            : String, // API.Nonce
}

/// # Verify a decryption.
///
/// Returns list of Warnings.
// #[openapi(tag = "Authority")]
#[openapi()]
#[post("/vcp/verifyDecryption?<zkp..>", data = "<dat>")]
fn verifyDecryption(
    zkp : ZkpLibQueryParam,
    dat : crate::DataResult<'_, VerifyDecryptionRequest>,
) -> Result<Json<Vec<Warning>>, (Status, Json<misc::Error>)> {
    let api = getApiFromQP(zkp, "verifyDecryption")?;
    let dat = dat.map_or_else(
        |e| err(format!("{:?}", e), "verifyDecryption"),
        |v| Ok(v.into_inner()))?;
    let op  = api.verify_decryption;
    op(&dat.proofReqs, &dat.sharedParams, &dat.proof,&dat.decryptionKeys, &dat.decryptResponses,
       ProofMode::Strict, Some(dat.nonce)).map_or_else(
        |e| vcpErr(e, "verifyDecryption"),
        |v| Ok(Json(v)))
}

// ------------------------------------------------------------------------------

const PORT               : usize = 8080;
const OPENAPI_JSON_ROUTE : &str  = "../openapi.json";

#[rocket::main]
async fn main() {
    let one_gib: ByteUnit = "1GiB".parse().unwrap();
    let launch_result     = rocket::build()
        .configure(rocket::Config::figment()
                   .merge(("address", "0.0.0.0"))
                   .merge(("port"   , PORT))
                   .merge(("limits" , Limits::new().limit("json", one_gib))))
        .mount(
            "/",
            openapi_get_routes![
                createSignerData,
                createAccumulatorData,
                sign,
                createAccumulatorElement,
                accumulatorAddRemove,
                updateAccumulatorWitness,
                createMembershipProvingKey,
                createRangeProofProvingKey,
                getRangeProofMaxValue,
                createAuthorityData,
                createProof,
                verifyProof,
                verifyDecryption,
            ],
        )
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                url: OPENAPI_JSON_ROUTE.to_owned(),
                ..Default::default()
            }),
        )
        .mount(
            "/rapidoc/",
            make_rapidoc(&RapiDocConfig {
                general: GeneralConfig {
                    spec_urls: vec![UrlObject::new("General", OPENAPI_JSON_ROUTE)],
                    ..Default::default()
                },
                hide_show: HideShowConfig {
                    allow_spec_url_load: false,
                    allow_spec_file_load: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .launch()
        .await;
    match launch_result {
        Ok(_)    => println!("VCP server shut down gracefully."),
        Err(err) => println!("VCP server had an error: {}", err),
    };
}
