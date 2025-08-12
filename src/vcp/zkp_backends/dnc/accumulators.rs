// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::generate_frs::*;
use crate::vcp::zkp_backends::dnc::in_memory_state::test::*;
use crate::vcp::zkp_backends::dnc::signer::*;
use crate::vcp::zkp_backends::dnc::to_from_api::accumulators_to_from_api::*;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use vb_accumulator::positive::Accumulator;
use vb_accumulator::prelude::MembershipProvingKey as VbaMembershipProvingKey;
use vb_accumulator::prelude::MembershipWitness;
use vb_accumulator::prelude::PositiveAccumulator;
use vb_accumulator::prelude::Keypair              as VbaKeypair;
use vb_accumulator::prelude::Omega;
use vb_accumulator::prelude::PublicKey            as VbaPublicKey;
use vb_accumulator::prelude::SetupParams          as VbaSetupParams;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr,G1Affine};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
// ------------------------------------------------------------------------------
use std::iter::zip;
use std::sync::Arc;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

pub fn create_accumulator_data() -> CreateAccumulatorData {
    Arc::new(|rng_seed| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let sp      = VbaSetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let kp      = VbaKeypair::<Bls12_381>::generate_using_rng(&mut rng, &sp);
        let pk      = &kp.public_key;
        let ims : InMemoryState::<Fr> = InMemoryState::<Fr>::new();
        let acc     = PositiveAccumulator::initialize(&sp);
        let ad      = to_api_accumulator_data(&sp, &kp)?;
        #[cfg(not(feature="in_memory_state"))]
        let accumulator : api::Accumulator
                    = to_api(&acc)?;
        #[cfg(feature="in_memory_state")]
        let accumulator : api::Accumulator
                    = to_api((&acc, &ims))?;
        Ok(CreateAccumulatorResponse { accumulator_data : ad, accumulator })
    })
}

// ------------------------------------------------------------------------------

pub fn create_membership_proving_key() -> CreateMembershipProvingKey {
    Arc::new(|rng_seed| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let mpk     = VbaMembershipProvingKey::<G1>::generate_using_rng(&mut rng);
        to_api(mpk)
    })
}

// ------------------------------------------------------------------------------

pub fn create_accumulator_element() -> CreateAccumulatorElement {
    Arc::new(|x| {
        let fr = generate_fr_from_val_and_ct((&ClaimType::CTAccumulatorMember, &DataValue::DVText(x)))?;
        to_api(fr)
    })
}

// ------------------------------------------------------------------------------

pub fn accumulator_add_remove() -> AccumulatorAddRemove {
    Arc::new(|ad, acc, adds, rms| {
        let (sp, kp)              = from_api_accumulator_data(ad)?;

        #[cfg(not(feature="in_memory_state"))]
        let pa1: PositiveAccumulator<_> = from_api(acc)?;
        #[cfg(feature="in_memory_state")]
        let (pa1, mut ims)        = from_api(acc)?;

        let afl                   = adds.iter().map(|(_,e)| from_api(e)).collect::<VCPResult<Vec<Fr>>>()?;
        let rfl                   = rms .iter().map(        from_api)   .collect::<VCPResult<Vec<Fr>>>()?;

        let o                     = Omega::new(&afl, &rfl, pa1.value(), &kp.secret_key);
        // The 'afl.clone() is necessary because of the docknetwork/crypto 'add_batch' definition.
        // TODO : is it technically possible to change docknetwork/crypto to take a reference?
        #[cfg(not(feature="in_memory_state"))]
        let pa2                   = PositiveAccumulator(pa1.compute_new_post_add_batch(&afl.clone(), &kp.secret_key));
        #[cfg(feature="in_memory_state")]
        let pa2                   = pa1.add_batch(   afl.clone(), &kp.secret_key, &mut ims)
            .map_err(|e| Error::General(format!("DNC accumulator_add_remove add {:?}", e)))?;

        #[cfg(not(feature="in_memory_state"))]
        let pa3                   = PositiveAccumulator(pa2.compute_new_post_remove_batch(&rfl,      &kp.secret_key));
        #[cfg(feature="in_memory_state")]
        let pa3                   = pa2.remove_batch(&rfl,        &kp.secret_key, &mut ims)
            .map_err(|e| Error::General(format!("DNC accumulator_add_remove rm  {:?}", e)))?;

        let mut witnesses_for_new = HashMap::<HolderID, api::AccumulatorMembershipWitness>::new();
        for ((k,_),v) in zip(adds, &afl) {
            #[cfg(not(feature="in_memory_state"))]
            let wit = pa3.compute_membership_witness(v, &kp.secret_key);
            #[cfg(feature="in_memory_state")]
            let wit = pa3.get_membership_witness(v, &kp.secret_key, &ims)
                .map_err(|e| Error::General(format!("DNC accumulator_add_remove gmw {:?}", e)))?;
            // The 'k.clone' is necessary because the key needs to live in two maps : 'afl' and 'witnesses_for_new'.
            witnesses_for_new.insert(k.clone(), to_api(wit)?);
        }
        let witness_update_info : AccumulatorWitnessUpdateInfo = to_api( (o, afl, rfl) )?;
        let accumulator_data      = to_api_accumulator_data(&sp, &kp)?;
        #[cfg(not(feature="in_memory_state"))]
        let accumulator           = to_api(&pa3)?;
        #[cfg(feature="in_memory_state")]
        let accumulator           = to_api((&pa3,&ims))?;
        Ok(AccumulatorAddRemoveResponse { witness_update_info, witnesses_for_new,
                                          accumulator })
    })
}

// ------------------------------------------------------------------------------

pub fn get_accumulator_witness() -> GetAccumulatorWitness {
    Arc::new(|accumulator_data, accumulator, element| {
        #[cfg(not(feature="in_memory_state"))]
        let pa: PositiveAccumulator::<G1Affine> = from_api(accumulator)?;
        #[cfg(feature="in_memory_state")]
        let (pa, ims_a): (PositiveAccumulator::<G1Affine>, InMemoryState::<Fr>) = from_api(accumulator)?;
        let (sp, kp) = from_api_accumulator_data(accumulator_data)?;
        let e : Fr   = from_api(element)?;
        // TODO: feature gate - use compute_membership_witness if InMemoryState not available
        #[cfg(not(feature="in_memory_state"))]
        let wit      = pa.compute_membership_witness(&e, &kp.secret_key);
        #[cfg(feature="in_memory_state")]
        let wit      = pa.get_membership_witness(&e, &kp.secret_key, &ims_a)
            .map_err(|e| Error::General(format!("DNC get_accumulator_witness {:?}", e)))?;
        to_api(wit)
    })
}

// ------------------------------------------------------------------------------

pub fn update_accumulator_witness() -> UpdateAccumulatorWitness {
    Arc::new(|witness, element, update_info| {
        let wit : MembershipWitness::<G1> = from_api(witness)?;
        let (omega, adds, rms)            = from_api(update_info)?;
        let fr                            = from_api(element)?;
        let v                             = vec!((adds.as_slice(), rms.as_slice(), &omega));
        let uw = wit.update_using_public_info_after_multiple_batch_updates(v, &fr)
            .map_err(|e| Error::General(format!("DNC update_accumulator_witness {:?}", e)))?;
        let uw_api                        = to_api(uw)?;
        Ok(uw_api)
    })
}
