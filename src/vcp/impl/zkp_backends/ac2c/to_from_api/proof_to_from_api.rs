// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::Presentation;
// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcpTryFrom<Presentation<S>> for Proof {
    fn vcp_try_from(x: Presentation<S>) -> VCPResult<Proof> {
        Ok(Proof(to_opaque_cbor(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&Proof> for Presentation<S> {
    fn vcp_try_from(x: &Proof) -> VCPResult<Presentation<S>> {
        from_opaque_cbor(&x.0)
    }
}

