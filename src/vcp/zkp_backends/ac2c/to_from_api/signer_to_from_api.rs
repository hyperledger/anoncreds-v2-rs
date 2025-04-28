use crate::blind::BlindCredentialRequest;
// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{BlindCredentialBundle, CredentialBundle, Issuer, IssuerPublic};
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
use crate::prelude::blsful::inner_types::*;
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

// TODO: this should not be for a triple, two components of which are not AC2C-specific
impl<S: ShortGroupSignatureScheme> VcpTryFrom<(IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>)> for SignerPublicData {
    fn vcp_try_from((issuer_public, sch, b_idxs): (IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>))
                    -> VCPResult<SignerPublicData> {
         Ok(SignerPublicData {
             signer_public_setup_data : SignerPublicSetupData(to_opaque_json(&issuer_public)?),
             signer_public_schema     : sch,
             signer_blinded_attr_idxs : b_idxs
         })
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&Box::<SignerPublicData>> for
    (IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>) {
    fn vcp_try_from(x: &Box::<SignerPublicData>) -> VCPResult<(IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>)> {
        let ip : IssuerPublic<S> = from_opaque_json(&x.signer_public_setup_data.0)?;
        Ok((ip, x.signer_public_schema.clone(), x.signer_blinded_attr_idxs.clone()))
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcpTryFrom<IssuerPublic<S>> for SignerPublicSetupData {
    fn vcp_try_from(x: IssuerPublic<S>) -> VCPResult<SignerPublicSetupData> {
        Ok(SignerPublicSetupData(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&SignerPublicSetupData> for IssuerPublic<S> {
    fn vcp_try_from(x: &SignerPublicSetupData) -> VCPResult<IssuerPublic<S>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcpTryFrom<Issuer<S>> for SignerSecretData {
    fn vcp_try_from(x: Issuer<S>) -> VCPResult<SignerSecretData> {
        Ok(SignerSecretData(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&SignerSecretData> for Issuer<S> {
    fn vcp_try_from(x: &SignerSecretData) -> VCPResult<Issuer<S>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcpTryFrom<CredentialBundle<S>> for Signature {
    fn vcp_try_from(x: CredentialBundle<S>) -> VCPResult<Signature> {
        Ok(Signature(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&Signature> for CredentialBundle<S> {
    fn vcp_try_from(x: &Signature) -> VCPResult<CredentialBundle<S>> {
        from_opaque_json(&x.0)
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<BlindCredentialRequest<S>> for BlindInfoForSigner {
    fn vcp_try_from(x: BlindCredentialRequest<S>) -> VCPResult<BlindInfoForSigner> {
        Ok(BlindInfoForSigner(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&BlindInfoForSigner> for BlindCredentialRequest<S> {
    fn vcp_try_from(x: &BlindInfoForSigner) -> VCPResult<BlindCredentialRequest<S>> {
        from_opaque_json(&x.0)
    }
}

impl VcpTryFrom<Scalar> for InfoForUnblinding {
    fn vcp_try_from(x: Scalar) -> VCPResult<InfoForUnblinding> {
        Ok(InfoForUnblinding(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&InfoForUnblinding> for Scalar {
    fn vcp_try_from(x: &InfoForUnblinding) -> VCPResult<Scalar> {
        from_opaque_json(&x.0)
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<BlindCredentialBundle<S>> for BlindSignature {
    fn vcp_try_from(x: BlindCredentialBundle<S>) -> VCPResult<BlindSignature> {
        Ok(BlindSignature(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&BlindSignature> for BlindCredentialBundle<S> {
    fn vcp_try_from(x: &BlindSignature) -> VCPResult<BlindCredentialBundle<S>> {
        from_opaque_json(&x.0)
    }
}

