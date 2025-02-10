// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::Presentation;
// ------------------------------------------------------------------------------

impl VcpTryFrom<Presentation> for Proof {
    fn vcp_try_from(x: Presentation) -> VCPResult<Proof> {
        Ok(Proof(to_opaque_cbor(&x)?))
    }
}

impl VcpTryFrom<&Proof> for Presentation {
    fn vcp_try_from(x: &Proof) -> VCPResult<Presentation> {
        from_opaque_cbor(&x.0)
    }
}

