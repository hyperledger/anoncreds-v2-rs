// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use saver::keygen::DecryptionKey as SaverDecryptionKey;
use saver::keygen::SecretKey     as SaverSecretKey;
use saver::prelude::*;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,G1Affine};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn create_authority_data() -> CreateAuthorityData {
    Arc::new(move |rng_seed| {
        let chunk_bit_size    = 8;
        let mut rng           = StdRng::seed_from_u64(rng_seed);
        let enc_gens          = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
        let chunked_comm_gens = ChunkedCommitmentGens::<G1>::new_using_rng(&mut rng);
        let (snark_proving_key, sk, encryption_key, dk)
                              = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens)
            .map_err(|e| Error::General(format!("DNC create_authority_data {:?}", e)))?;
        let apsd = AuthorityPublicSetupData { chunk_bit_size, chunked_comm_gens,
                                              enc_gens, encryption_key, snark_proving_key };
        Ok( AuthorityData {
            authority_public_data    : to_api(apsd)?,
            authority_secret_data    : to_api(sk)?,
            authority_decryption_key : to_api(dk)?,
        })
    })
}
