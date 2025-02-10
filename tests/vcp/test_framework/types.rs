// -----------------------------------------------------------------------------
use credx::vcp::api;
use credx::vcp::VCPResult;
// -----------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
// -----------------------------------------------------------------------------

pub type IssuerLabel                  = String;
/// See simplifying assumption below.
pub type IssuerLabelAsCredentialLabel = IssuerLabel;
pub type HolderLabel                  = String;

pub type AllSignerData = HashMap<IssuerLabel, api::SignerData>;
pub type AllAuthorityData = HashMap<api::AuthorityLabel,api::AuthorityData>;
pub type AccumsForSigner =
    HashMap<api::CredAttrIndex, (api::AccumulatorData,
                                 // Original accumulator
                                 api::Accumulator,
                                 // For sequence number n, the update info to update a
                                 // witness for nth accumulator to witness for (n+1)st
                                 // accumulator, plus the (n+1)st accumulator itself
                                 HashMap<api::AccumulatorBatchSeqNo, (api::AccumulatorWitnessUpdateInfo,
                                                                      api::Accumulator)>)>;
// TODO: Should be by AccumulatorPublicData, to enable modeling different Issuers using
// common RevocationManagers
pub type AllSignerAccumulatorData = HashMap<api::SignerPublicData, AccumsForSigner>;
pub type HolderSigsAndRelatedData =
    HashMap<HolderLabel, HashMap<IssuerLabelAsCredentialLabel, api::SignatureAndRelatedData>>;
pub type HolderAllWitnesses       =
    HashMap<HolderLabel,HashMap<IssuerLabelAsCredentialLabel,api::AllAccumulatorWitnesses>>;
pub type AllProofReqs =
    HashMap<HolderLabel, HashMap<IssuerLabelAsCredentialLabel, api::CredentialReqs>>;
pub type AllDecryptReqs =
    HashMap<HolderLabel, HashMap<IssuerLabelAsCredentialLabel,
                                 HashMap<api::CredAttrIndex,
                                         HashMap<api::AuthorityLabel,api::DecryptRequest>>>>;
pub type AllDecryptResps =
    HashMap<HolderLabel, HashMap<IssuerLabelAsCredentialLabel,
                                 HashMap<api::CredAttrIndex,
                                         HashMap<api::AuthorityLabel,api::DecryptResponse>>>>;

/// TestState captures the state as we run a test, keeping track of all data by
/// all roles, which is updated by each TestStep.
///
/// Simplifying assumption: each holder has at most one credential signed by
/// each Issuer, therefore we can use IssuerLabel as CredentialLabel; we also
/// use IssuerLabel as SharedParamsKey for the public signer data for Issuers.
#[derive(Clone)]
pub struct TestState {
    pub sparms: HashMap<api::SharedParamKey, api::SharedParamValue>,
    pub all_signer_data: AllSignerData,
    pub sigs_and_rel_data: HolderSigsAndRelatedData,
    pub accum_witnesses: HolderAllWitnesses,
    pub accums: AllSignerAccumulatorData,
    pub all_authority_data: AllAuthorityData,
    pub decrypt_requests: AllDecryptReqs,
    pub preqs: AllProofReqs,
    // -----
    // Below here are for recording/reporting/evaluatiung outcomes of the most recent
    // CreateAndVerifyProof step
    pub warnings_and_data_for_verifier: api::WarningsAndDataForVerifier,
    pub verification_warnings: Vec<api::Warning>,
    pub last_decrypt_responses: AllDecryptResps,
}

impl std::fmt::Debug for TestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestState")
            .field(
                "sparms",
                &self
                    .sparms
                    .keys()
                    .map(|k| (k, "..."))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "all_signer_data",
                &self
                    .all_signer_data
                    .keys()
                    .map(|k| (k, "..."))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "all_authority_data",
                &self
                    .all_authority_data
                    .keys()
                    .map(|k| (k, "..."))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "decrypt_requests",
                &self
                    .decrypt_requests
                    .keys()
                    .map(|k| (k, "..."))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "sigs_and_rel_data",
                &self.sigs_and_rel_data
            )
            .field(
                "accums",
                &self.accums
                    .keys()
                    .map(|k| (format!("SignerPublicData {{ signer_public_setup_data: ..., signer_public_schema: {:?} }}", k.signer_public_schema), "..."))
                    .collect::<HashMap<_, _>>(),
            )
            .field(
                "accum_witnesses",
                &self.accum_witnesses
            )
            .field("preqs", &self.preqs)
            .field(
                "warnings_and_data_for_verifier",
                &self.warnings_and_data_for_verifier,
            )
            .field(
                "verification_warnings",
                &self.verification_warnings,
            )
            .finish()
    }
}

/// How much flexibility do we want?  Warnings for create and verify? No
/// warnings allowed, for each? Or just save everything in state, enabling
/// "external" validation?
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum CreateVerifyExpectation {
    BothSucceedNoWarnings,
    CreateProofFails,
    /// implies createProof succeeds
    VerifyProofFails,
    CreateOrVerifyFails,
}

#[derive(Eq, PartialEq, Debug)]
pub enum PerturbDecryptedValue {
    Perturb, DontPerturb
}

/// Each TestStep defines a step to take in a test.  Each step can be specified
/// simply, e.g., in JSON, with no need to call any crypto library.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "tag", content = "contents")]
pub enum TestStep {
    CreateIssuer(IssuerLabel, Vec<api::ClaimType>),
    CreateAccumulators(IssuerLabel),
    SignCredential(IssuerLabel, HolderLabel, Vec<api::DataValue>),
    AccumulatorAddRemove(
        IssuerLabel,
        api::CredAttrIndex,
        HashMap<HolderLabel, api::DataValue>,
        Vec<api::DataValue>,
    ),
    UpdateAccumulatorWitness(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        api::AccumulatorBatchSeqNo,
    ),
    Reveal(HolderLabel, IssuerLabel, Vec<api::CredAttrIndex>),
    InRange(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        u64,   // NOTE: AnonCreds allows Option for min and max, but we do not provide that
        u64,   // generality (yet?) in our abstraction, and therefore not here either
    ),
    InAccum(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        api::AccumulatorBatchSeqNo,
    ),
    Equality(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        Vec<(IssuerLabel, api::CredAttrIndex)>,
    ),
    CreateAndVerifyProof(HolderLabel, CreateVerifyExpectation),
    CreateAuthority(api::AuthorityLabel),
    EncryptFor(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        api::AuthorityLabel
    ),
    Decrypt(
        HolderLabel,
        IssuerLabel,
        api::CredAttrIndex,
        api::AuthorityLabel
    ),
    VerifyDecryption(HolderLabel),
}

pub type TestSequence = Vec<TestStep>;

// This type defines the type of a function that performs on step in a test,
// updating the TestState according to the step being executed. Each TestStep is
// executed according to its type (see extendTest in Utils), using the functions
// defined in Steps.
pub type AddTestStep = Arc<dyn Fn(&mut TestState) -> VCPResult<()> + Send + Sync >;

/// Used by test to create base CredentialReqs given an IssuerLabel. Would fit
/// better in Utils, but that causes an import cycle.
pub fn new_credential_reqs(i_lbl: IssuerLabel) -> api::CredentialReqs {
    api::CredentialReqs {
        signer_label: i_lbl,
        disclosed: api::Disclosed(vec![]),
        in_accum: api::InAccum(vec![]),
        not_in_accum: api::NotInAccum(vec![]),
        in_range: api::InRange(vec![]),
        encrypted_for: api::EncryptedFor(vec![]),
        equal_to: api::EqualTo(vec![]),
    }
}
