// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::in_memory_state::test::*;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use vb_accumulator::prelude::Keypair              as VbaKeypair;
use vb_accumulator::prelude::MembershipProvingKey as VbaMembershipProvingKey;
use vb_accumulator::prelude::MembershipWitness;
use vb_accumulator::prelude::Omega;
use vb_accumulator::prelude::PositiveAccumulator;
use vb_accumulator::prelude::PublicKey            as VbaPublicKey;
use vb_accumulator::prelude::SetupParams          as VbaSetupParams;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr,G1Affine};
// ------------------------------------------------------------------------------
use serde::*;
use std::collections::{HashMap,HashSet};
// ------------------------------------------------------------------------------

type AccumWitnessesAPI  = HashMap<api::CredAttrIndex, api::AccumulatorMembershipWitness>;

// ------------------------------------------------------------------------------

impl VcpTryFrom<Fr> for api::AccumulatorElement {
    fn vcp_try_from(x: Fr) -> VCPResult<api::AccumulatorElement> {
        Ok(api::AccumulatorElement(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::AccumulatorElement> for Fr {
    fn vcp_try_from(x: &api::AccumulatorElement) -> VCPResult<Fr> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<Vec<Fr>> for Vec<String> {
    fn vcp_try_from(x: Vec<Fr>) -> VCPResult<Vec<String>> {
        x.iter().map(to_opaque_ark).collect()
    }
}

impl VcpTryFrom<&Vec<String>> for Vec<Fr> {
    fn vcp_try_from(x: &Vec<String>) -> VCPResult<Vec<Fr>> {
        x.iter().map(|s : &String| from_opaque_ark(s)).collect()
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<(Omega::<G1>, Vec<Fr>, Vec<Fr>)> for api::AccumulatorWitnessUpdateInfo {
    fn vcp_try_from((o,a,r): (Omega::<G1>, Vec<Fr>, Vec<Fr>)) -> VCPResult<api::AccumulatorWitnessUpdateInfo> {
        let ap : Vec<String> = to_api(a)?;
        let rp : Vec<String> = to_api(r)?;
        Ok(api::AccumulatorWitnessUpdateInfo(to_opaque_json(&(o, ap, rp))?))
    }
}

impl VcpTryFrom<&api::AccumulatorWitnessUpdateInfo> for (Omega::<G1>, Vec<Fr>, Vec<Fr>) {
    fn vcp_try_from(x: &api::AccumulatorWitnessUpdateInfo) -> VCPResult<(Omega::<G1>, Vec<Fr>, Vec<Fr>)> {
        let (o, ap, rp) : (Omega::<G1>, Vec<String>, Vec<String>) = from_opaque_json(&x.0)?;
        let a : Vec<Fr> = from_api(&ap)?;
        let r : Vec<Fr> = from_api(&rp)?;
        Ok( (o, a, r) )
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<VbaMembershipProvingKey::<G1>> for api::MembershipProvingKey {
    fn vcp_try_from(x: VbaMembershipProvingKey::<G1>) -> VCPResult<api::MembershipProvingKey> {
        Ok(api::MembershipProvingKey(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::MembershipProvingKey> for VbaMembershipProvingKey::<G1> {
    fn vcp_try_from(x: &api::MembershipProvingKey) -> VCPResult<VbaMembershipProvingKey::<G1>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<PositiveAccumulator::<G1Affine>> for api::Accumulator {
    fn vcp_try_from(x: PositiveAccumulator::<G1Affine>) -> VCPResult<api::Accumulator> {
        Ok(api::Accumulator(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::Accumulator> for PositiveAccumulator::<G1Affine> {
    fn vcp_try_from(x: &api::Accumulator) -> VCPResult<PositiveAccumulator::<G1Affine>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<(&VbaSetupParams::<Bls12_381>,  &VbaPublicKey::<Bls12_381>)> for api::AccumulatorPublicData {
    fn vcp_try_from(x: (&VbaSetupParams::<Bls12_381>,  &VbaPublicKey::<Bls12_381>)) -> VCPResult<api::AccumulatorPublicData> {
        Ok(api::AccumulatorPublicData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::AccumulatorPublicData> for (VbaSetupParams::<Bls12_381>,  VbaPublicKey::<Bls12_381>) {
    fn vcp_try_from(x: &api::AccumulatorPublicData) -> VCPResult<(VbaSetupParams::<Bls12_381>,  VbaPublicKey::<Bls12_381>)> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct AccumulatorSecretDataOpaque {
    pub acc : PositiveAccumulator::<G1Affine>,
    pub ims : InMemoryStateOpaque,
    pub kp  : VbaKeypair::<Bls12_381>,
}

impl VcpTryFrom<(&PositiveAccumulator::<G1Affine>,
                 &InMemoryState::<Fr>,
                 &VbaKeypair::<Bls12_381>)> for api::AccumulatorSecretData {
    fn vcp_try_from((acc,ims,kp): (&PositiveAccumulator::<G1Affine>,
                                   &InMemoryState::<Fr>,
                                   &VbaKeypair::<Bls12_381>)) -> VCPResult<api::AccumulatorSecretData> {
        let ims : InMemoryStateOpaque = to_api(ims)?;
        Ok(api::AccumulatorSecretData(to_opaque_json(&(acc, ims, kp))?))
    }
}

impl VcpTryFrom<&api::AccumulatorSecretData> for (PositiveAccumulator::<G1Affine>,
                                                  InMemoryState::<Fr>,
                                                  VbaKeypair::<Bls12_381>) {
    fn vcp_try_from(x: &api::AccumulatorSecretData) -> VCPResult<(PositiveAccumulator::<G1Affine>,
                                                                  InMemoryState::<Fr>,
                                                                  VbaKeypair::<Bls12_381>)> {
        let AccumulatorSecretDataOpaque { acc, ims, kp} = from_opaque_json(&x.0)?;
        Ok( (acc, from_api(&ims)?, kp) )
    }
}

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct InMemoryStateOpaque(pub api::OpaqueMaterial);

impl VcpTryFrom<&InMemoryState::<Fr>> for InMemoryStateOpaque {
    fn vcp_try_from(state: &InMemoryState::<Fr>) -> VCPResult<InMemoryStateOpaque> {
        let mut v = vec![];
        for elem in state.db.iter() { v.push(*elem); }
        Ok(InMemoryStateOpaque(to_opaque_ark(&v)?))
    }
}

impl VcpTryFrom<&InMemoryStateOpaque> for InMemoryState::<Fr> {
    fn vcp_try_from(x: &InMemoryStateOpaque) -> VCPResult<InMemoryState::<Fr>> {
        let v : Vec<Fr> = from_opaque_ark(&x.0)?;
        let mut db      = HashSet::<Fr>::new();
        for e in v { db.insert(e); }
        let mut ims     = InMemoryState::<Fr>::new();
        ims.db          = db;
        Ok(ims)
    }
}

// ------------------------------------------------------------------------------

pub fn to_api_accumulator_data(
    sp  : &VbaSetupParams::<Bls12_381>,
    kp  : &VbaKeypair::<Bls12_381>,
    ims : &InMemoryState::<Fr>,
    acc : &PositiveAccumulator::<G1Affine>
) -> VCPResult<api::AccumulatorData>
{
    let ad = api::AccumulatorData {
        accumulator_public_data : to_api((sp, &kp.public_key))?,
        accumulator_secret_data : to_api((acc, ims, kp))?
    };
    Ok(ad)
}

#[allow(clippy::type_complexity)]
pub fn from_api_accumulator_data(
    ad : &api::AccumulatorData
) -> VCPResult<(VbaSetupParams::<Bls12_381>,
                VbaKeypair::<Bls12_381>,
                InMemoryState::<Fr>,
                PositiveAccumulator::<G1Affine>)>
{
    let api::AccumulatorData { accumulator_public_data, accumulator_secret_data } = ad;
    let (sp, _pk)          = from_api(accumulator_public_data)?;
    let (acc, mut ims, kp) = from_api(accumulator_secret_data)?;
    Ok((sp, kp, ims, acc))
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<MembershipWitness::<G1>> for api::AccumulatorMembershipWitness {
    fn vcp_try_from(x: MembershipWitness::<G1>) -> VCPResult<api::AccumulatorMembershipWitness> {
        Ok(api::AccumulatorMembershipWitness(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::AccumulatorMembershipWitness> for MembershipWitness::<G1> {
    fn vcp_try_from(x: &api::AccumulatorMembershipWitness) -> VCPResult<MembershipWitness::<G1>> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<AccumWitnesses> for AccumWitnessesAPI {
    fn vcp_try_from(x: AccumWitnesses) -> VCPResult<AccumWitnessesAPI> {
        let mut hm = HashMap::new();
        for (k,v) in x { hm.insert(k, to_api(v)?); }
        Ok(hm)
    }
}

impl VcpTryFrom<&AccumWitnessesAPI> for AccumWitnesses {
    fn vcp_try_from(x: &AccumWitnessesAPI) -> VCPResult<AccumWitnesses> {
        let mut hm = HashMap::new();
        for (k,v) in x { hm.insert(*k, from_api(v)?); }
        Ok(hm)
    }
}

