// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::interfaces::types as api;
// ------------------------------------------------------------------------------
use legogroth16;
// ------------------------------------------------------------------------------
use ark_bls12_381::Bls12_381;
// ------------------------------------------------------------------------------

impl VcpTryFrom<legogroth16::ProvingKey<Bls12_381>> for api::RangeProofProvingKey {
    fn vcp_try_from(x: legogroth16::ProvingKey<Bls12_381>) -> VCPResult<api::RangeProofProvingKey> {
        Ok(api::RangeProofProvingKey(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::RangeProofProvingKey> for legogroth16::ProvingKey<Bls12_381> {
    fn vcp_try_from(x: &api::RangeProofProvingKey) -> VCPResult<legogroth16::ProvingKey<Bls12_381>> {
        from_opaque_ark(&x.0)
    }
}

