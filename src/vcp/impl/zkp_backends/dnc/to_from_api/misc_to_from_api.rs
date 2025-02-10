// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::dnc::types::*;
use crate::vcp::interfaces::types as api;
// ------------------------------------------------------------------------------

impl VcpTryFrom<(ImplSignature, Vec<api::DataValue>, AccumWitnesses)> for api::SignatureAndRelatedData {
    fn vcp_try_from((s,values,w) : (ImplSignature, Vec<api::DataValue>, AccumWitnesses)) -> VCPResult<api::SignatureAndRelatedData> {
        let signature             = to_api(s)?;
        let accumulator_witnesses = to_api(w)?;
        Ok(api::SignatureAndRelatedData {signature, values, accumulator_witnesses})
    }
}

impl VcpTryFrom<&api::SignatureAndRelatedData> for (ImplSignature, Vec<api::DataValue>, AccumWitnesses) {
    fn vcp_try_from(x: &api::SignatureAndRelatedData) -> VCPResult<(ImplSignature, Vec<api::DataValue>, AccumWitnesses)> {
        let api::SignatureAndRelatedData { signature, values, accumulator_witnesses } = x;
        Ok((from_api(signature)?, values.to_vec(), from_api(accumulator_witnesses)?))
    }
}

