// ------------------------------------------------------------------------------
use core::fmt;
use serde::*;
use std::collections::BTreeMap;
use std::collections::HashMap;
// ------------------------------------------------------------------------------

macro_rules! impl_Debug_for_OpaqueMaterial_wrapper {
    ($ty: ident) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($ty))
                // Sometimes, this shrink_to(16) results in showing just ().  Weird.
                // shrink_to does not seem to make sense -- it shrinks capacity, not the string itself:
                // https://doc.rust-lang.org/std/string/struct.String.html#method.shrink_to
//                    .field(&format!("{:?}...", self.0).shrink_to(16))
                    .field(&format!("{:?}...", self.0))
                    .finish()
            }
        }
    };
}

// ------------------------------------------------------------------------------
// signer data

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignerData {
    #[serde(rename = "signerPublicData")]
    pub signer_public_data: Box<SignerPublicData>,
    #[serde(rename = "signerSecretData")]
    pub signer_secret_data: SignerSecretData,
}

impl SignerData {
    pub fn new(signer_public_data: SignerPublicData,
               signer_secret_data: SignerSecretData) -> SignerData {
        SignerData { signer_public_data: Box::new(signer_public_data), signer_secret_data }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignerPublicData {
    #[serde(rename = "signerPublicSetupData")]
    pub signer_public_setup_data: SignerPublicSetupData,
    #[serde(rename = "signerPublicSchema")]
    pub signer_public_schema: Vec<ClaimType>,
}

impl SignerPublicData {
    pub fn new(signer_public_setup_data: SignerPublicSetupData,
               signer_public_schema: Vec<ClaimType>) -> SignerPublicData {
        SignerPublicData { signer_public_schema, signer_public_setup_data }
    }
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignerPublicSetupData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { SignerPublicSetupData }

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignerSecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { SignerSecretData }

// ------------------------------------------------------------------------------
// values to sign and how to encode them

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ClaimType {
    #[serde(rename = "CTText")]
    CTText,
    #[serde(rename = "CTEncryptableText")]
    CTEncryptableText,
    #[serde(rename = "CTInt")]
    CTInt,
    #[serde(rename = "CTAccumulatorMember")]
    CTAccumulatorMember,
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClaimType::CTText              => write!(f, "CTText"),
            ClaimType::CTEncryptableText   => write!(f, "CTEncryptableText"),
            ClaimType::CTInt               => write!(f, "CTInt"),
            ClaimType::CTAccumulatorMember => write!(f, "CTAccumulatorMember"),
        }
    }
}

impl Default for ClaimType {
    fn default() -> ClaimType {
        Self::CTText
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(content = "contents", tag = "tag")]
pub enum DataValue {
    DVInt(u64),
    DVText(String),
}

impl fmt::Display for DataValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DataValue::DVInt(v) => write!(f, "DVInt({v})"),
            DataValue::DVText(s) => write!(f, "DVText({s})"),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Signature }

// ------------------------------------------------------------------------------
// proof requirements

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialReqs {
    #[serde(rename = "signerLabel")]
    pub signer_label: SharedParamKey,
    #[serde(rename = "disclosed")]
    pub disclosed: Disclosed,
    #[serde(rename = "inAccum")]
    pub in_accum: InAccum,
    #[serde(rename = "notInAccum")]
    pub not_in_accum: NotInAccum,
    #[serde(rename = "inRange")]
    pub in_range: InRange,
    #[serde(rename = "encryptedFor")]
    pub encrypted_for: EncryptedFor,
    #[serde(rename = "equalTo")]
    pub equal_to: EqualTo,
}

impl CredentialReqs {
    pub fn new(signer_label: SharedParamKey,  disclosed: Disclosed, in_accum: InAccum,
               not_in_accum: NotInAccum, in_range: InRange,
               encrypted_for: EncryptedFor, equal_to: EqualTo,) -> CredentialReqs {
        CredentialReqs {signer_label, disclosed, in_accum, not_in_accum, in_range, encrypted_for, equal_to }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Disclosed(pub Vec<RawIndex>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InAccum(pub Vec<InAccumInfo>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotInAccum(pub Vec<IndexAndLabel>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InRange(pub Vec<InRangeInfo>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedFor(pub Vec<IndexAndLabel>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EqualTo(pub Vec<EqInfo>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexAndLabel {
    #[serde(rename = "index")]
    pub index: RawIndex,
    #[serde(rename = "label")]
    pub label: SharedParamKey,
}

impl IndexAndLabel {
    pub fn new(index: RawIndex, label: SharedParamKey) -> IndexAndLabel {
        IndexAndLabel { index, label }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EqInfo {
    #[serde(rename = "fromIndex")]
    pub from_index: RawIndex,
    #[serde(rename = "toLabel")]
    pub to_label: CredentialLabel,
    #[serde(rename = "toIndex")]
    pub to_index: RawIndex,
}

impl EqInfo {
    /// Information specifying equalities between values in different credentials.
    pub fn new(from_index: RawIndex, to_label: CredentialLabel, to_index: RawIndex, ) -> EqInfo {
        EqInfo { from_index, to_label, to_index }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InRangeInfo {
    #[serde(rename = "index")]
    pub index: RawIndex,
    #[serde(rename = "minLabel")]
    pub min_label: SharedParamKey,
    #[serde(rename = "maxLabel")]
    pub max_label: SharedParamKey,
    #[serde(rename = "provingKeyLabel")]
    pub proving_key_label: SharedParamKey,
}

impl InRangeInfo {
    pub fn new(index: RawIndex, min_label: SharedParamKey,
               max_label: SharedParamKey, proving_key_label: SharedParamKey) -> InRangeInfo {
        InRangeInfo { index, max_label, min_label, proving_key_label }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InAccumInfo {
    #[serde(rename = "index")]
    pub index: RawIndex,
    #[serde(rename = "publicDataLabel")]
    pub public_data_label: SharedParamKey,
    #[serde(rename = "memPrvLabel")]
    pub mem_prv_label: SharedParamKey,
    #[serde(rename = "accumulatorLabel")]
    pub accumulator_label: SharedParamKey,
    /// Holder needs this to find appropriate witness
    #[serde(rename = "accumulatorSeqNo")]
    pub accumulator_seq_no_label: SharedParamKey,
}

impl InAccumInfo {
    pub fn new(index: RawIndex, public_data_label: SharedParamKey,
               mem_prv_label: SharedParamKey, accumulator_label: SharedParamKey,
               accumulator_seq_no_label: SharedParamKey) -> InAccumInfo {
        InAccumInfo { index, public_data_label, mem_prv_label, accumulator_label, accumulator_seq_no_label }
    }
}

// ------------------------------------------------------------------------------
// accumulators

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Accumulator(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Accumulator }

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MembershipProvingKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { MembershipProvingKey }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorData {
    #[serde(rename = "accumulatorPublicData")]
    pub public_data: AccumulatorPublicData,
    #[serde(rename = "accumulatorSecretData")]
    pub secret_data: AccumulatorSecretData,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccumulatorPublicData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorPublicData }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorSecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorSecretData }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorMembershipWitness(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorMembershipWitness }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorElement(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorElement }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AccumWitnessUpdateInfo(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumWitnessUpdateInfo }

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HolderID(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { HolderID }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateAccumulatorResponse  {
    pub new_accum_data  : AccumulatorData,
    pub new_accum_value : Accumulator,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccumulatorAddRemoveResponse {
    pub witness_update_info: AccumWitnessUpdateInfo,
    pub wits_for_new: HashMap<HolderID, AccumulatorMembershipWitness>,
    pub updated_accum_data: AccumulatorData,
    pub updated_accum_value: Accumulator,
}

// ------------------------------------------------------------------------------
// range proof data

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RangeProofProvingKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { RangeProofProvingKey }

// ------------------------------------------------------------------------------
// verifiable encryption data

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct AuthorityPublicData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthorityPublicData }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthoritySecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthoritySecretData }

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorityDecryptionKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthorityDecryptionKey }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityData {
    #[serde(rename = "public")]
    pub public: AuthorityPublicData,
    #[serde(rename = "secret")]
    pub secret: AuthoritySecretData,
    #[serde(rename = "decryptionKey")]
    pub decryption_key: AuthorityDecryptionKey,
}

impl AuthorityData {
    pub fn new(public: AuthorityPublicData, secret: AuthoritySecretData,
               decryption_key: AuthorityDecryptionKey) -> AuthorityData {
        AuthorityData { public, secret, decryption_key }
    }
}

// ------------------------------------------------------------------------------
// Proof

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Proof(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Proof }

pub type AccumulatorBatchSeqNo = u64;

pub type AllAccumulatorWitnesses = HashMap<CredAttrIndex,BTreeMap<AccumulatorBatchSeqNo,AccumulatorMembershipWitness>>;

pub type AccumulatorWitnesses = HashMap<CredAttrIndex, AccumulatorMembershipWitness>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureAndRelatedData {
    #[serde(rename = "signature")]
    pub signature: Signature,
    #[serde(rename = "values")]
    pub values: Vec<DataValue>,
    #[serde(rename = "credAuxData")]
    pub accum_wits: AccumulatorWitnesses,
}

impl SignatureAndRelatedData {
    pub fn new(signature: Signature, values: Vec<DataValue>,
               accum_wits: AccumulatorWitnesses) -> SignatureAndRelatedData {
        SignatureAndRelatedData { signature, values, accum_wits }
    }
}

// ------------------------------------------------------------------------------
// decryption

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecryptRequest {
    #[serde(rename = "authSecret")]
    pub auth_secret: AuthoritySecretData,
    #[serde(rename = "authDecryptionKey")]
    pub auth_decryption_key: AuthorityDecryptionKey,
}

impl DecryptRequest {
    pub fn new(auth_secret: AuthoritySecretData,
               auth_decryption_key: AuthorityDecryptionKey) -> DecryptRequest {
        DecryptRequest { auth_secret, auth_decryption_key }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecryptResponse {
    #[serde(rename = "value")]
    pub value: String,
    #[serde(rename = "proof")]
    pub proof: Proof
}

impl DecryptResponse {
    pub fn new(value: String, proof: Proof) -> DecryptResponse {
        DecryptResponse { value, proof }
    }
}

// ------------------------------------------------------------------------------
// types passed between roles

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(content = "contents", tag = "tag")]
pub enum SharedParamValue {
    SPVOne(DataValue),
    SPVList(Vec<DataValue>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredAttrIndexAndDataValue {
    #[serde(rename = "index")]
    pub index: CredAttrIndex,
    #[serde(rename = "value")]
    pub value: Box<DataValue>,   // TO DISCUSS: why Box?
}

impl CredAttrIndexAndDataValue {
    pub fn new(index: CredAttrIndex, value: DataValue) -> CredAttrIndexAndDataValue {
        CredAttrIndexAndDataValue { index, value: Box::new(value) }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataForVerifier {
    #[serde(rename = "revealedIdxsAndVals")]
    pub revealed_idxs_and_vals: HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
    #[serde(rename = "proof")]
    pub proof: Proof,
}

impl DataForVerifier {
    pub fn new(
        revealed_idxs_and_vals: HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
        proof: Proof
    ) -> DataForVerifier {
        DataForVerifier { revealed_idxs_and_vals, proof }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WarningsAndDataForVerifier {
    #[serde(rename = "warnings")]
    pub warnings: Vec<Warning>,
    #[serde(rename = "result")]
    pub result: DataForVerifier
}

impl WarningsAndDataForVerifier {
    pub fn new(warnings: Vec<Warning>, result: DataForVerifier) -> WarningsAndDataForVerifier {
        WarningsAndDataForVerifier { warnings, result }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WarningsAndDecryptResponses {
    #[serde(rename = "statementWarnings")]
    pub statement_warnings: Vec<Warning>,
    #[serde(rename = "decryptResponses")]
    pub decrypt_responses: HashMap<CredentialLabel,
                                   HashMap<CredAttrIndex,
                                           HashMap<AuthorityLabel, DecryptResponse>>>,
}

impl WarningsAndDecryptResponses {
    pub fn new(statement_warnings: Vec<Warning>,
               decrypt_responses: HashMap<CredentialLabel,
                                          HashMap<CredAttrIndex,
                                                  HashMap<AuthorityLabel, DecryptResponse>>>,
    ) -> WarningsAndDecryptResponses {
        WarningsAndDecryptResponses { statement_warnings, decrypt_responses }
    }
}

// ------------------------------------------------------------------------------

pub type CredentialLabel = String;
// Used to identify the ShearedParamKey for the AuthorityPublicData
pub type AuthorityLabel  = String;
pub type CredAttrIndex   = u64;
pub type Natural         = u64;
pub type Nonce           = String;
pub type OpaqueMaterial  = String;
pub type RawIndex        = u64;
pub type SharedParamKey  = String;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(content = "contents", tag = "tag")]
pub enum Warning {
    UnsupportedFeature(String),
    RevealPrivacyWarning(CredentialLabel, CredAttrIndex, String)
}
