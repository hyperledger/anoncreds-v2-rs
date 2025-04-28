use crate::str_vec_from;
use crate::vcp::r#impl::util::*;
// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::dnc::generate_frs::*;
use crate::vcp::zkp_backends::dnc::reversible_encoding::text_to_field_element;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use ark_std::UniformRand;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

pub fn specific_create_signer_data() -> SpecificCreateSignerData {
    Arc::new(|rng_seed, schema, _| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let sp      = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, (*schema).len() as u32);
        let kp      = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &sp);
        let spsd    = to_api((sp, kp.public_key.clone()))?;
        Ok((spsd, to_api(kp.secret_key.clone())?))
    })
}

pub fn sign() -> SpecificSign {
    Arc::new(|rng_seed, vals, sd| {
        let SignerData { signer_public_data, signer_secret_data } = sd;
        let sk : SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let SignerPublicData { signer_public_setup_data, signer_public_schema, .. } = *signer_public_data.clone();
        let (sp, _) : (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) = from_api(&signer_public_setup_data)?;
        let frs = generate_frs_from_vals_and_ct(vals, &signer_public_schema, "sign")?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let s = SignatureG1::<Bls12_381>::new(&mut rng, &frs, &sk, &sp)
            .map_err(|e| Error::General(format!("sign, {:?}", e)))?;
        to_api(s)
    })
}

pub fn specific_create_blind_signing_info() -> SpecificCreateBlindSigningInfo {
    Arc::new(|rng_seed, spsd, schema, blind_attrs| {
        let (sp, _) = from_api(spsd)?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let blinder = Fr::rand(&mut rng);
        let committed_messages_0: Vec<(usize,Fr)> =
            create_index_fr_pairs("create_blind_signing_info, DNC", blind_attrs, schema)?;
        let committed_messages = committed_messages_0
            .iter()
            .map(|(x,y)| (*x,y))
            .collect::<Vec<(usize,&Fr)>>();
        let blind_credential_commitment = sp.commit_to_messages(committed_messages, &blinder)
            .map_err(|e| Error::General(ic_semi(&str_vec_from!(
                "specific_create_blind_signing_info", format!("{e:?}")))))?;
        Ok(BlindSigningInfo {
            blind_info_for_signer: to_api(blind_credential_commitment)?,
            blinded_attributes: blind_attrs.to_vec(),
            info_for_unblinding: to_api(blinder)?})
    })
}

pub fn specific_sign_with_blinded_attributes() -> SpecificSignWithBlindedAttributes {
    Arc::new(|rng_seed, schema, non_blinded_attrs, bifs, signer_public_setup_data, signer_secret_data | {
        let sk : SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let (sp, _) : (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) =
            from_api(signer_public_setup_data)?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let uncommitted_messages_0 =
            create_index_fr_pairs("specific_sign_with_blinded_attributes, DNC", non_blinded_attrs, schema)?;
        let uncommitted_messages = uncommitted_messages_0
            .iter()
            .map(|(x,y)| (*x,y))
            .collect::<BTreeMap<usize,&Fr>>();
        let commitment: G1Affine = from_api(bifs)?;
        let sig = SignatureG1::<Bls12_381>::new_with_committed_messages(
            &mut rng, &commitment, uncommitted_messages, &sk, &sp)
            .map_err(|e| Error::General(ic_semi(&str_vec_from!(
                "specific_sign_with_blinded_attributes",
                format!("{e:?}")))))?;
        to_api(sig)
    })
}

pub fn specific_unblind_blinded_signature(
) -> SpecificUnblindBlindedSignature {
    Arc::new(|_, _, blinded_sig, blinder_api| {
        let blinder = from_api(blinder_api)?;
        let blinded_sig: SignatureG1::<Bls12_381> = from_api(blinded_sig)?;
        to_api(blinded_sig.unblind(&blinder))
    })
}

fn create_index_fr_pair(
    s      : &str,
    schema : &[ClaimType],
    CredAttrIndexAndDataValue { index, value } : &CredAttrIndexAndDataValue,
) -> VCPResult<(usize, Fr)> {
    let ct = lookup_throw_if_out_of_bounds(
        schema, *index as usize, Error::General,
        &str_vec_from!(s,"createLabelFrPair", "DNC"))?;
    Ok((*index as usize, generate_fr_from_val_and_ct((ct, value))?))
}

fn create_index_fr_pairs(s: &str,
             attrs_and_vals: &[CredAttrIndexAndDataValue],
             schema: &[ClaimType]
) -> VCPResult<Vec<(usize,Fr)>> {
    attrs_and_vals
        .iter()
        .map(|cred_attr_index_and_data_value| {
            create_index_fr_pair(s, schema, cred_attr_index_and_data_value)
        })
        .collect::<Vec<VCPResult<(usize,Fr)>>>()
        .into_iter()
        .collect::<VCPResult<Vec<(usize,Fr)>>>()
}

