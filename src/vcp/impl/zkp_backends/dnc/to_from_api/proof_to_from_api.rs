// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::dnc::types::*;
use crate::vcp::interfaces::types as api;
// ------------------------------------------------------------------------------

impl VcpTryFrom<ProofG1> for api::Proof {
    fn vcp_try_from(x: ProofG1) -> VCPResult<api::Proof> {
        Ok(api::Proof(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::Proof> for ProofG1 {
    fn vcp_try_from(x: &api::Proof) -> VCPResult<ProofG1> {
        from_opaque_json(&x.0)
    }
}

