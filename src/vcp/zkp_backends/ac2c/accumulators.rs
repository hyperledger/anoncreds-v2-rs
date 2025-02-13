// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::interfaces::types::*;
use crate::vcp::zkp_backends::ac2c::to_from_api::accumulators_to_from_api::*;
// ------------------------------------------------------------------------------
use crate::{random_string, CredxResult};
use crate::claim::{ClaimType, HashedClaim, RevocationClaim};
use crate::credential::{ClaimSchema, CredentialSchema};
use crate::error::*;
use crate::knox::short_group_sig_core::{ProofMessage,HiddenMessage};
use crate::prelude::{
    vb20,
    ClaimData, CredentialBundle,
    Issuer, IssuerPublic,
    MembershipClaim, MembershipCredential, MembershipRegistry,
    MembershipSigningKey, MembershipStatement, MembershipVerificationKey,
};
use crate::presentation::{Presentation, PresentationSchema};
use crate::statement::{RevocationStatement, SignatureStatement};
// ------------------------------------------------------------------------------
extern crate alloc;
use indexmap::indexmap;
use rand::thread_rng;
use rand_core::RngCore;
use serde::*;
use std::collections::HashMap;
use std::{rc::*, sync::Arc};
use std::vec::Vec;
// ------------------------------------------------------------------------------

pub fn create_accumulator_data() -> CreateAccumulatorData {
    Arc::new(|rng_seed| {
        let sk  = vb20::SecretKey::new(Some(&to_bytes_l(rng_seed)));
        let pk  = vb20::PublicKey::from(&sk);
        let acc = vb20::Accumulator::with_elements(&sk, &[]);
        let ad  = AccumulatorData { accumulator_public_data: to_api(pk)?, accumulator_secret_data: to_api(sk)?, };
        Ok(CreateAccumulatorResponse { accumulator_data : ad, accumulator : to_api(acc)? })
    })
}

fn to_bytes_l(mut n : Natural) -> Vec<u8> {
    let mut v = vec![];
    loop {
        if n == 0 {
            break v;
        } else {
            v.push(n.rem_euclid(256) as u8);
            n = n.div_euclid(256);
        }
    }
}

pub fn create_membership_proving_key() -> CreateMembershipProvingKey {
    Arc::new(|_| {
        Ok(MembershipProvingKey("not used: AC2C MembershipProvingKey".to_string()))
    })
}

pub fn create_accumulator_element() -> CreateAccumulatorElement {
    Arc::new(|x| {
        let cd = ClaimData::from(HashedClaim::from(x));
        let mc = MembershipClaim::from(cd).0;
        to_api(mc)
    })
}

pub fn accumulator_add_remove() -> AccumulatorAddRemove {
    Arc::new(|ad, acc, adds, rms| {
        let acc : vb20::Accumulator = from_api(acc)?;
        let (sk,_pk) = from_api(ad)?;
        let a        = adds.iter().map(|(_,x)| from_api(x)).collect::<VCPResult<Vec<_>>>()?;
        let r        = rms .iter().map(        from_api)   .collect::<VCPResult<Vec<_>>>()?;
        let (acc2, coefficients) = acc.update(&sk, &a, &r);
        let mut witnesses_for_new : HashMap<HolderID, AccumulatorMembershipWitness> = HashMap::new();
        for (hid, el) in adds {
            let e   = from_api(el)?;
            let wit = vb20::MembershipWitness::new(e, acc2, &sk);
            witnesses_for_new.insert(hid.clone(), to_api(wit)?);
        }
        let wui = AC2CWitnessUpdateInfo {
            ac2c_adds         : adds.values().cloned().collect::<Vec<_>>(),
            ac2c_rms          : rms.to_vec(),
            ac2c_coefficients : coefficients
        };
        let r = AccumulatorAddRemoveResponse {
            witness_update_info : to_api(wui)?,
            witnesses_for_new,
            accumulator_data    : ad.clone(),
            accumulator         : to_api(acc2)?,
        };
        Ok(r)
    })
}

pub fn update_accumulator_witness() -> UpdateAccumulatorWitness {
    Arc::new(|witness, element, update_info| {
        let w  : vb20::MembershipWitness  = from_api(witness)?;
        let e                             = from_api(element)?;
        let AC2CWitnessUpdateInfo { ac2c_adds, ac2c_rms, ac2c_coefficients } = from_api(update_info)?;
        let a  = ac2c_adds.iter().map(from_api).collect::<VCPResult<Vec<_>>>()?;
        let r  = ac2c_rms .iter().map(from_api).collect::<VCPResult<Vec<_>>>()?;
        let wu = w.batch_update(e, &a, &r, &ac2c_coefficients);
        to_api(wu)
    })
}

