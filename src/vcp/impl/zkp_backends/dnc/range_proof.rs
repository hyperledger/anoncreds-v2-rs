// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use proof_system::sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check;
// ------------------------------------------------------------------------------
use ark_bls12_381::Bls12_381;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn create_range_proof_proving_key() -> CreateRangeProofProvingKey {
    Arc::new(|rng_seed| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let rpk     = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng)
            .map_err(|e| Error::General(format!("DNC create_range_proof_proving_key {:?}", e)))?;
        to_api(rpk)
    })
}
