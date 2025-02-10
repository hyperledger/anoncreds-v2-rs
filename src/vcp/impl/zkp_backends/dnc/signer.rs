// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::dnc::generate_frs::*;
use crate::vcp::r#impl::zkp_backends::dnc::reversible_encoding::text_to_field_element;
use crate::vcp::r#impl::zkp_backends::dnc::types::*;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

pub fn create_signer_data() -> CreateSignerData {
    Arc::new(|rng_seed, sdcts| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let sp      = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, (*sdcts).len() as u32);
        let kp      = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &sp);
        let spsd    = to_api((sp, kp.public_key.clone()))?;
        let spd     = SignerPublicData::new(spsd, sdcts.to_vec());
        Ok(SignerData::new(spd, to_api(kp.secret_key.clone())?))
    })
}

pub fn sign() -> Sign {
    Arc::new(|rng_seed, vals, sd| {
        let SignerData { signer_public_data, signer_secret_data } = sd;
        let sk : SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let SignerPublicData { signer_public_setup_data, signer_public_schema } = *signer_public_data.clone();
        let (sp, _) : (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) = from_api(&signer_public_setup_data)?;
        let frs = generate_frs_from_vals_and_ct(vals, &signer_public_schema, "sign")?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let s = SignatureG1::<Bls12_381>::new(&mut rng, &frs, &sk, &sp)
            .map_err(|e| Error::General(format!("sign, {:?}", e)))?;
        to_api(s)
    })
}

