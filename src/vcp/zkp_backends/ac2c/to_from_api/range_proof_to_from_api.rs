// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::inner_types::G1Projective;
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeProofCommitmentSetup {
    pub message_generator : G1Projective,
    pub blinder_generator : G1Projective,
}

impl VcpTryFrom<&RangeProofCommitmentSetup> for RangeProofProvingKey {
    fn vcp_try_from(x: &RangeProofCommitmentSetup) -> VCPResult<RangeProofProvingKey> {
        Ok(RangeProofProvingKey(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&RangeProofProvingKey> for RangeProofCommitmentSetup {
    fn vcp_try_from(x: &RangeProofProvingKey) -> VCPResult<RangeProofCommitmentSetup> {
        from_opaque_json(&x.0)
    }
}

