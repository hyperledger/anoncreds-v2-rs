// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::SecretKey> for AccumulatorSecretData {
    fn vcp_try_from(x: vb20::SecretKey) -> VCPResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorSecretData> for vb20::SecretKey {
    fn vcp_try_from(x: &AccumulatorSecretData) -> VCPResult<vb20::SecretKey> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<&vb20::SecretKey> for AccumulatorSecretData {
    fn vcp_try_from(x: &vb20::SecretKey) -> VCPResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&str> for vb20::SecretKey {
    fn vcp_try_from(s: &str) -> VCPResult<vb20::SecretKey> {
        from_opaque_json(s)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::PublicKey> for AccumulatorPublicData {
    fn vcp_try_from(x: vb20::PublicKey) -> VCPResult<AccumulatorPublicData> {
        Ok(AccumulatorPublicData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorPublicData> for vb20::PublicKey {
    fn vcp_try_from(x: &AccumulatorPublicData) -> VCPResult<vb20::PublicKey> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<(vb20::SecretKey, vb20::PublicKey)> for AccumulatorData {
    fn vcp_try_from((sk, pk) : (vb20::SecretKey, vb20::PublicKey)
    ) -> VCPResult<AccumulatorData> {
        Ok(AccumulatorData {
            accumulator_public_data : AccumulatorPublicData(to_opaque_json(&pk)?),
            accumulator_secret_data : AccumulatorSecretData(to_opaque_json(&sk)?),
        })
    }
}

impl VcpTryFrom<&AccumulatorData> for (vb20::SecretKey, vb20::PublicKey) {
    fn vcp_try_from(x: &AccumulatorData) -> VCPResult<(vb20::SecretKey, vb20::PublicKey)> {
        let AccumulatorData { accumulator_secret_data, accumulator_public_data } = x;
        let sk                                           = from_opaque_json(&accumulator_secret_data.0)?;
        let pk                                           = from_opaque_json(&accumulator_public_data.0)?;
        Ok((sk, pk))
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::Accumulator> for Accumulator {
    fn vcp_try_from(x: vb20::Accumulator) -> VCPResult<Accumulator> {
        Ok(Accumulator(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&Accumulator> for vb20::Accumulator {
    fn vcp_try_from(x: &Accumulator) -> VCPResult<vb20::Accumulator> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::Element> for AccumulatorElement {
    fn vcp_try_from(x : vb20::Element) -> VCPResult<AccumulatorElement> {
        Ok(AccumulatorElement(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorElement> for vb20::Element {
    fn vcp_try_from(x: &AccumulatorElement) -> VCPResult<vb20::Element> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::MembershipWitness> for AccumulatorMembershipWitness {
    fn vcp_try_from(x : vb20::MembershipWitness) -> VCPResult<AccumulatorMembershipWitness> {
        Ok(AccumulatorMembershipWitness(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorMembershipWitness> for vb20::MembershipWitness {
    fn vcp_try_from(x: &AccumulatorMembershipWitness) -> VCPResult<vb20::MembershipWitness> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AC2CWitnessUpdateInfo {
    pub ac2c_adds         : Vec<AccumulatorElement>,
    pub ac2c_rms          : Vec<AccumulatorElement>,
    pub ac2c_coefficients : Vec<Coefficient>,
}


impl VcpTryFrom<AC2CWitnessUpdateInfo> for AccumulatorWitnessUpdateInfo {
    fn vcp_try_from(x : AC2CWitnessUpdateInfo) -> VCPResult<AccumulatorWitnessUpdateInfo> {
        Ok(AccumulatorWitnessUpdateInfo(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorWitnessUpdateInfo> for AC2CWitnessUpdateInfo {
    fn vcp_try_from(x: &AccumulatorWitnessUpdateInfo) -> VCPResult<AC2CWitnessUpdateInfo> {
        from_opaque_json(&x.0)
    }
}
