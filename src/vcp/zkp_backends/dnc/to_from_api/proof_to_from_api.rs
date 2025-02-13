// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::types::*;
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

