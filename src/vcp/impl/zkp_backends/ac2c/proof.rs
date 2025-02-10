// ------------------------------------------------------------------------------
use crate::get_location_and_backtrace_on_panic;
use crate::vcp::{convert_to_crypto_library_error, Error, VCPResult, UnexpectedError};
use crate::vcp::r#impl::common::catch_unwind_util::*;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::common::types::WarningsAndResult;
use crate::vcp::r#impl::common::util::Assert;
use crate::vcp::r#impl::zkp_backends::ac2c::presentation_request_setup::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use crate::claim::ClaimData;
use crate::prelude::{Presentation, PresentationCredential, PresentationSchema};
// ------------------------------------------------------------------------------
use indexmap::IndexMap;
use std::collections::HashMap;
use std::str;
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn specific_prover_ac2c() -> SpecificProver {
    Arc::new(|prf_instrs, eqs, sigs_and_related_data, nonce| {
        let credentials = presentation_credentials_from(sigs_and_related_data)?;
        // println!("specific_prover_ac2c: credentials: {:?}", credentials);
        let WarningsAndResult {
            warnings: warns,
            result: pres_sch,
        } = presentation_schema_from(prf_instrs, eqs)?;
        // println!("specific_prover_ac2c: pres_sch: {:?}", pres_sch);
        let prf = get_location_and_backtrace_on_panic!(
            Presentation::create(&credentials, &pres_sch, nonce.as_bytes())
                .map_err(|e| convert_to_crypto_library_error("AC2C", "specific_prover_ac2c", e)))?;
        Ok(WarningsAndProof {
            warnings: warns,
            proof: to_api(prf)?,
        })
    })
}

pub fn specific_verifier_ac2c() -> SpecificVerifier {
    Arc::new(|prf_instrs, eqs, proof_api, decr_reqs, nonce| {
        let WarningsAndResult {
            warnings: warns,
            result: pres_sch,
        } = presentation_schema_from(prf_instrs, eqs)?;
        let proof_ac2c = from_api(proof_api)?;
        // throws if verify fails
        get_location_and_backtrace_on_panic!(
            Presentation::verify(&proof_ac2c, &pres_sch, nonce.as_bytes())
                .map_err(|e| convert_to_crypto_library_error("AC2C", "specific_verifier_ac2c", e)))?;
        // TODO-VERIFIABLE-ENCRYPTION: get decrypt responses when supported by AC2C
        if !decr_reqs.is_empty() {
            unimplemented!("specific_verifier_ac2c: decryption")
        }
        Ok(WarningsAndDecryptResponses {
            warnings: warns,
            decrypt_responses: HashMap::new()
        })
    })
}

pub fn specific_verify_decryption_ac2c() -> SpecificVerifyDecryption {
    Arc::new(|_prf_instrs, _eqs, _proof_api, _decr_reqs, _auth_dks| {
        unimplemented!("specific_verify_decryption_ac2c");
    })
}
