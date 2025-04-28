// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl VcpTryFrom<(SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)> for api::SignerPublicSetupData {
    fn vcp_try_from((sp, pk): (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)) -> VCPResult<api::SignerPublicSetupData> {
        Ok(api::SignerPublicSetupData(to_opaque_json(&(sp, pk.clone()))?)) // TODO no clone
    }
}

impl VcpTryFrom<&api::SignerPublicSetupData> for (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) {
    fn vcp_try_from(x: &api::SignerPublicSetupData) -> VCPResult<(SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<SecretKeyBls12_381> for api::SignerSecretData {
    fn vcp_try_from(x: SecretKeyBls12_381) -> VCPResult<api::SignerSecretData> {
        Ok(api::SignerSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::SignerSecretData> for SecretKeyBls12_381 {
    fn vcp_try_from(x: &api::SignerSecretData) -> VCPResult<SecretKeyBls12_381> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<SignatureG1::<Bls12_381>> for api::Signature {
    fn vcp_try_from(x: SignatureG1::<Bls12_381>) -> VCPResult<api::Signature> {
        Ok(api::Signature(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::Signature> for SignatureG1::<Bls12_381> {
    fn vcp_try_from(x: &api::Signature) -> VCPResult<SignatureG1::<Bls12_381>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<G1Affine> for api::BlindInfoForSigner {
    fn vcp_try_from(x: G1Affine) -> VCPResult<api::BlindInfoForSigner> {
        Ok(api::BlindInfoForSigner(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::BlindInfoForSigner> for G1Affine {
    fn vcp_try_from(x: &api::BlindInfoForSigner) -> VCPResult<G1Affine> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<Fr> for api::InfoForUnblinding {
    fn vcp_try_from(x: Fr) -> VCPResult<api::InfoForUnblinding> {
        Ok(api::InfoForUnblinding(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::InfoForUnblinding> for Fr {
    fn vcp_try_from(x: &api::InfoForUnblinding) -> VCPResult<Fr> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl<E:Pairing> VcpTryFrom<SignatureG1<E>> for api::BlindSignature {
    fn vcp_try_from(x: SignatureG1<E>) -> VCPResult<api::BlindSignature> {
        Ok(api::BlindSignature(to_opaque_json(&x)?))
    }
}

impl<E: Pairing> VcpTryFrom<&api::BlindSignature> for SignatureG1<E> {
    fn vcp_try_from(x: &api::BlindSignature) -> VCPResult<SignatureG1<E>> {
        from_opaque_json(&x.0)
    }
}

