//! See the module comment for [`crate::vcp::interfaces::primitives`].
// ---------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::types::*;
// ---------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
// ---------------------------------------------------------------------------

pub type CreateProof = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &HashMap<CredentialLabel, SignatureAndRelatedData>,
            ProofMode,
            Option<Nonce>,
        ) -> VCPResult<WarningsAndDataForVerifier>
        + Send
        + Sync,
>;

pub type VerifyProof = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &DataForVerifier,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
            ProofMode,
            Option<Nonce>,
        ) -> VCPResult<WarningsAndDecryptResponses>
        + Send
        + Sync,
>;

pub type VerifyDecryption = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &Proof,
            &HashMap<SharedParamKey, AuthorityDecryptionKey>,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptResponse>>>,
            ProofMode,
            Option<Nonce>,
        ) -> VCPResult<Vec<Warning>>
        + Send
        + Sync,
>;

