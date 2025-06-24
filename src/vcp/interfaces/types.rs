// ------------------------------------------------------------------------------
use schemars::JsonSchema;
// ------------------------------------------------------------------------------
use core::fmt;
use serde::*;
use std::collections::BTreeMap;
use std::collections::HashMap;
// ------------------------------------------------------------------------------

#[macro_export]
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

/// Contains a Signer's secret and public data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
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

/// A Signer's public keys and setup data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SignerPublicData {

    #[serde(rename = "signerPublicSetupData")]
    pub signer_public_setup_data: SignerPublicSetupData,

    #[serde(rename = "signerPublicSchema")]
    pub signer_public_schema: Vec<ClaimType>,

    #[serde(rename = "signerBlindedAttrIdxs")]
    pub signer_blinded_attr_idxs: Vec<CredAttrIndex>,
}

impl SignerPublicData {
    pub fn new(signer_public_setup_data: SignerPublicSetupData,
               signer_public_schema: Vec<ClaimType>,
               signer_blinded_attr_idxs: Vec<CredAttrIndex>) -> SignerPublicData {
        SignerPublicData { signer_public_schema, signer_public_setup_data, signer_blinded_attr_idxs}
    }
}

/// Data resulting from a Signer's setup.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SignerPublicSetupData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { SignerPublicSetupData }

/// A Signer's secret keys.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct SignerSecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { SignerSecretData }

// ------------------------------------------------------------------------------
// values to sign and how to encode them

/// How values are handled (e.g., accumulator member, encryptable text, text, int).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ClaimType {
    #[serde(rename = "CTText")]
    CTText,
    #[serde(rename = "CTEncryptableText")]
    CTEncryptableText,
    #[serde(rename = "CTInt")]
    CTInt,
    #[serde(rename = "CTAccumulatorMember")]
    CTAccumulatorMember,
    #[serde(rename = "CTTextOrInt")]
    CTTextOrInt,
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClaimType::CTText              => write!(f, "CTText"),
            ClaimType::CTEncryptableText   => write!(f, "CTEncryptableText"),
            ClaimType::CTInt               => write!(f, "CTInt"),
            ClaimType::CTAccumulatorMember => write!(f, "CTAccumulatorMember"),
            ClaimType::CTTextOrInt         => write!(f, "CTTextOrInt"),
        }
    }
}

impl Default for ClaimType {
    fn default() -> ClaimType {
        Self::CTText
    }
}

/// An int or text value.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, JsonSchema)]
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

/// A signature, based on the 'values', etc., given in a SignRequest.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Signature(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Signature }

impl Eq for Signature {}

/// A blinded signature, based on the 'values', etc., given in a TODO -- what's this?
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlindSignature(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { BlindSignature }

/// Info sent by requester to Signer to create blind signature
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BlindInfoForSigner(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { BlindInfoForSigner }

/// Data retained by requester to unblind blind signature
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InfoForUnblinding(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { InfoForUnblinding }

#[derive(Clone, Eq, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BlindSigningInfo {
    #[serde(rename = "blindInfoForSigner")]
    pub blind_info_for_signer: BlindInfoForSigner,

    #[serde(rename = "blindedAttributes")]
    pub blinded_attributes: Vec<CredAttrIndexAndDataValue>,

    #[serde(rename = "infoForUnblinding")]
    pub info_for_unblinding: InfoForUnblinding,
}

// ------------------------------------------------------------------------------
// proof requirements

/// Proof requirements for a specific credential.
#[derive(Clone, Eq, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CredentialReqs {

    /// A key into SharedParams to obtain the Signer's public data.
    #[serde(rename = "signerLabel")]
    pub signer_label: SharedParamKey,

    /// Specifies which attributes are to be selectively disclosed.
    #[serde(rename = "disclosed")]
    pub disclosed: Disclosed,

    /// Specifies which attributes are to be proved PRESENT in a specified accumulator.
    #[serde(rename = "inAccum")]
    pub in_accum: InAccum,

    /// Specifies which attributes are to be proved ABSENT from a specified accumulator.
    #[serde(rename = "notInAccum")]
    pub not_in_accum: NotInAccum,

    /// Specifies which attributes are to be proved to be within a specified range.
    #[serde(rename = "inRange")]
    pub in_range: InRange,

    /// Specifies which attributes are to be encrypted for a specified Authority.
    #[serde(rename = "encryptedFor")]
    pub encrypted_for: EncryptedFor,

    /// Specifies which attributes in this credential are to be proved equal to other specified attributes (usually in other credentials).
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

/// A list of indices for attributes that are to be disclosed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Disclosed(pub Vec<RawIndex>);

/// A list of 'InAccumInfo', each indicating an attribute to be proved present in an accumulator and SharedParam keys for relevant parameters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InAccum(pub Vec<InAccumInfo>);

// TODO: remove?
/// Requirements for attributes to be proved ABSENT from an accumulator.  Out of date, not currently supported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NotInAccum(pub Vec<IndexAndLabel>);

/// A list of 'InRangeInfo', each indicating an attribute to be proved to be within a range and SharedParam keys for relevant parameters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InRange(pub Vec<InRangeInfo>);

/// A list of index-label pairs, each of which specifies an attribute to be encrypted and SharedParam key to obtain the Authority's public information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EncryptedFor(pub Vec<IndexAndLabel>);

/// A list of 'EqInfo', each of which specifies an attribute to be proved equal to another specified attribute.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EqualTo(pub Vec<EqInfo>);

/// An index-label pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IndexAndLabel {

    /// An index specifying an attribute.
    #[serde(rename = "index")]
    pub index: RawIndex,

    /// A key into SharedParams.
    #[serde(rename = "label")]
    pub label: SharedParamKey,
}

impl IndexAndLabel {
    pub fn new(index: RawIndex, label: SharedParamKey) -> IndexAndLabel {
        IndexAndLabel { index, label }
    }
}

/// Information specifying equalities between values in different credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EqInfo {

    /// The index of the attribute in this credential that must be proved equal to another attribute (usually in another credential).
    #[serde(rename = "fromIndex")]
    pub from_index: RawIndex,

    /// The label of a credential containing the attribute that is to be proved equal to the attribute specified by fromIndex.
    #[serde(rename = "toLabel")]
    pub to_label: CredentialLabel,

    /// The index of the attribute in the credential specified by toLabel that is to be proved equal to the attribute specified by fromIndex.
    #[serde(rename = "toIndex")]
    pub to_index: RawIndex,
}

impl EqInfo {
    pub fn new(from_index: RawIndex, to_label: CredentialLabel, to_index: RawIndex, ) -> EqInfo {
        EqInfo { from_index, to_label, to_index }
    }
}

/// Information for range proof requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InRangeInfo {

    /// Specifies the index of the attribute to be proved to be within a specified range.
    #[serde(rename = "index")]
    pub index: RawIndex,

    /// A key into SharedParams used to obtain the minimum value in the specified range.
    #[serde(rename = "minLabel")]
    pub min_label: SharedParamKey,

    /// A key into SharedParams used to obtain the maximum value in the specified range.
    #[serde(rename = "maxLabel")]
    pub max_label: SharedParamKey,

    /// A key into SharedParams used to obtain the proving key to be used for the required range proof.
    #[serde(rename = "rangeProvingKeyLabel")]
    pub range_proving_key_label: SharedParamKey,
}

impl InRangeInfo {
    pub fn new(index: RawIndex, min_label: SharedParamKey,
               max_label: SharedParamKey, range_proving_key_label: SharedParamKey) -> InRangeInfo {
        InRangeInfo { index, max_label, min_label, range_proving_key_label }
    }
}

/// Used to prove accumulator membership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InAccumInfo {

    /// Indicates which attribute is to be proved present in an accumulator.
    #[serde(rename = "index")]
    pub index: RawIndex,

    /// A key into SharedParams to obtain an accumulator's public keys.
    #[serde(rename = "accumulatorPublicDataLabel")]
    pub accumulator_public_data_label: SharedParamKey,

    /// A key into SharedParams to obtain a MembershipProvingKey.
    #[serde(rename = "membershipProvingKeyLabel")]
    pub membership_proving_key_label: SharedParamKey,

    /// A key into SharedParams to obtain an Accumulator value.
    #[serde(rename = "accumulatorLabel")]
    pub accumulator_label: SharedParamKey,

    /// A key into SharedParams to obtain a sequence number. A holder needs this to find the appropriate witness.
    #[serde(rename = "accumulatorSeqNumLabel")]
    pub accumulator_seq_num_label: SharedParamKey,
}

impl InAccumInfo {
    pub fn new(index: RawIndex, accumulator_public_data_label: SharedParamKey,
               membership_proving_key_label: SharedParamKey, accumulator_label: SharedParamKey,
               accumulator_seq_num_label: SharedParamKey) -> InAccumInfo {
        InAccumInfo { index, accumulator_public_data_label, membership_proving_key_label, accumulator_label, accumulator_seq_num_label }
    }
}

// ------------------------------------------------------------------------------
// accumulators

/// The value of an accumulator.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Accumulator(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Accumulator }

/// Key to use in accumlator membership proofs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct MembershipProvingKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { MembershipProvingKey }

/// Contains an accumulator's secret and public data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorData {

    #[serde(rename = "accumulatorPublicData")]
    pub accumulator_public_data: AccumulatorPublicData,

    #[serde(rename = "accumulatorSecretData")]
    pub accumulator_secret_data: AccumulatorSecretData,
}

/// An accumulator's public keys.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorPublicData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorPublicData }

/// An accumulator's secret keys.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorSecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorSecretData }

/// A witness that a particular AccumulatorElement is a member of an accumulator.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorMembershipWitness(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorMembershipWitness }

/// An element that may be added to or removed from an accumulator.  Note, elements are created from text (see createAccumulatorElement).
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorElement(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorElement }

/// Data used to update an AccumulatorMembershipWitness after elements have been added to and/or removed from an accumulator.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorWitnessUpdateInfo(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AccumulatorWitnessUpdateInfo }

/// Used to identify the Holder associated with a value added to an accumulator, to enable sending its new witness.  Note: can be ephemeral: used only to enable Revocation Manager to add an element and provide Issuer with means to associate new witness with intended Holder.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
// TODO: this does not need to be OpaqueMaterial, String will suffice.  It is not specific to an underlying ZKP library.  Nonetheless,
// perhaps it is useful to be able to display a truncated version for debugging.
pub struct HolderID(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { HolderID }

/// Contains the AccumulatorData and the Accumulator.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CreateAccumulatorResponse  {
    #[serde(rename = "accumulatorData")]
    pub accumulator_data  : AccumulatorData,
    #[serde(rename = "accumulator")]
    pub accumulator       : Accumulator,
}

/// Response from call to AccumulatorAddRemove, including data to update witnesses, witnesses for added elements, and updated accumlator data and value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccumulatorAddRemoveResponse {

    /// Data to use to update existing witnesses.
    #[serde(rename = "witnessUpdateInfo")]
    pub witness_update_info: AccumulatorWitnessUpdateInfo,

    /// A new witnesses for each element added.
    #[serde(rename = "witnessesForNew")]
    pub witnesses_for_new: HashMap<HolderID, AccumulatorMembershipWitness>,

    /// Updated accumulator data.
    #[serde(rename = "accumulatorData")]
    pub accumulator_data: AccumulatorData,

    /// Updated accumulator value.
    #[serde(rename = "accumulator")]
    pub accumulator: Accumulator,
}

// ------------------------------------------------------------------------------
// range proof data

/// Key to use in range proofs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct RangeProofProvingKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { RangeProofProvingKey }

// ------------------------------------------------------------------------------
// verifiable encryption data

/// An Authority's public key.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityPublicData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthorityPublicData }

/// An Authority's secret key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuthoritySecretData(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthoritySecretData }

/// An Authority's decryption key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityDecryptionKey(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { AuthorityDecryptionKey }

/// Contains an Authority's secret, public, and decryption keys.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityData {

    /// An Authority's public key.
    #[serde(rename = "authorityPublicData")]
    pub authority_public_data: AuthorityPublicData,

    /// An Authority's secret key.
    #[serde(rename = "authoritySecretData")]
    pub authority_secret_data: AuthoritySecretData,

    /// An Authority's decryption key.
    #[serde(rename = "authorityDecryptionKey")]
    pub authority_decryption_key: AuthorityDecryptionKey,
}

impl AuthorityData {
    pub fn new(authority_public_data: AuthorityPublicData,
               authority_secret_data: AuthoritySecretData,
               authority_decryption_key: AuthorityDecryptionKey) -> AuthorityData {
        AuthorityData { authority_public_data, authority_secret_data, authority_decryption_key }
    }
}

// ------------------------------------------------------------------------------
// Proof

/// A proof returned from createProof.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Proof(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { Proof }

pub type AccumulatorBatchSeqNo = u64;

pub type AllAccumulatorWitnesses = HashMap<CredAttrIndex,BTreeMap<AccumulatorBatchSeqNo,AccumulatorMembershipWitness>>;

pub type AccumulatorWitnesses = HashMap<CredAttrIndex, AccumulatorMembershipWitness>;

/// A Signature and other related data, including attribute values signed and witnesses for accumlators.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureAndRelatedData {

    #[serde(rename = "signature")]
    /// The signature from a Signer signing data values.
    pub signature: Signature,

    #[serde(rename = "values")]
    /// The data values used to produce the signature.
    pub values: Vec<DataValue>,

    #[serde(rename = "accumulatorWitnesses")]
    /// Accumulator witnesses.
    pub accumulator_witnesses: AccumulatorWitnesses,
}

impl SignatureAndRelatedData {
    pub fn new(signature: Signature, values: Vec<DataValue>,
               accumulator_witnesses: AccumulatorWitnesses) -> SignatureAndRelatedData {
        SignatureAndRelatedData { signature, values, accumulator_witnesses }
    }
}

// ------------------------------------------------------------------------------
// decryption

/// Keys for decryption.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptRequest {

    /// Authority secret data.
    #[serde(rename = "authoritySecretData")]
    pub authority_secret_data: AuthoritySecretData,

    /// Authority decryption key.
    #[serde(rename = "authorityDecryptionKey")]
    pub authority_decryption_key: AuthorityDecryptionKey,
}

/// Proof that specified value is correctly decrypted from proof created by Prover.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptionProof(pub OpaqueMaterial);
impl_Debug_for_OpaqueMaterial_wrapper! { DecryptionProof }

impl DecryptRequest {
    pub fn new(authority_secret_data: AuthoritySecretData,
               authority_decryption_key: AuthorityDecryptionKey) -> DecryptRequest {
        DecryptRequest { authority_secret_data, authority_decryption_key }
    }
}

/// Decrypted values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptResponse {

    /// The decrypted value.
    #[serde(rename = "value")]
    pub value: String,

    /// A proof that the value is correctly decrypted from proof created by Prover.
    #[serde(rename = "decryptionProof")]
    pub decryption_proof: DecryptionProof
}

impl DecryptResponse {
    pub fn new(value: String, decryption_proof: DecryptionProof) -> DecryptResponse {
        DecryptResponse { value, decryption_proof }
    }
}

// ------------------------------------------------------------------------------
// types passed between roles

/// Either a single value or a list of of values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(content = "contents", tag = "tag")]
pub enum SharedParamValue {
    SPVOne(DataValue),
    SPVList(Vec<DataValue>),
}

#[derive(Clone, Eq, Debug, PartialEq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct CredAttrIndexAndDataValue {

    #[serde(rename = "index")]
    pub index: CredAttrIndex,

    #[serde(rename = "value")]
    pub value: DataValue,
}

impl CredAttrIndexAndDataValue {
    pub fn new(index: CredAttrIndex, value: DataValue) -> CredAttrIndexAndDataValue {
        CredAttrIndexAndDataValue { index, value }
    }
}

/// Data returned from 'createProof'.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DataForVerifier {

    /// Data values disclosed by (two-level map keyed by CredentialLabel and CredAttrIndex).
    #[serde(rename = "revealedIdxsAndVals")]
    pub revealed_idxs_and_vals: HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,

    /// A proof.
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

/// Warnings and DataForVerifier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WarningsAndDataForVerifier {

    /// A list of warnings.
    #[serde(rename = "warnings")]
    pub warnings: Vec<Warning>,

    /// Data to be sent to Verifier.
    #[serde(rename = "dataForVerifier")]
    pub data_for_verifier: DataForVerifier
}

impl WarningsAndDataForVerifier {
    pub fn new(warnings: Vec<Warning>, data_for_verifier: DataForVerifier) -> WarningsAndDataForVerifier {
        WarningsAndDataForVerifier { warnings, data_for_verifier }
    }
}

/// Returned from 'verifyProof' if the given proof is valid.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WarningsAndDecryptResponses {

    /// Warnings, e.g., unsupported features, potentially unintended requests, etc.
    #[serde(rename = "warnings")]
    pub warnings: Vec<Warning>,

    /// Data values decrypted (three-level map keyed by CredentialLabel, CredAttrIndex and AuthorityLabel).
    #[serde(rename = "decryptResponses")]
    pub decrypt_responses: HashMap<CredentialLabel,
                                   HashMap<CredAttrIndex,
                                           HashMap<AuthorityLabel, DecryptResponse>>>,
}

impl WarningsAndDecryptResponses {
    pub fn new(warnings: Vec<Warning>,
               decrypt_responses: HashMap<CredentialLabel,
                                          HashMap<CredAttrIndex,
                                                  HashMap<AuthorityLabel, DecryptResponse>>>,
    ) -> WarningsAndDecryptResponses {
        WarningsAndDecryptResponses { warnings, decrypt_responses }
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
pub enum ProofMode {
    // Allow warnings when creating or verifying a proof
    Loose,
    // Forbid warnings
    Strict,
    // Allow warnings and also suppress errors from General, enabling testing backend calls even
    // when General would throw an error for honest provers
    TestBackend
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(content = "contents", tag = "tag")]
pub enum Warning {
    UnsupportedFeature(String),
    RevealPrivacyWarning(CredentialLabel, CredAttrIndex, String)
}
