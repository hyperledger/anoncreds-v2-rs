// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{CredentialBundle, Issuer, IssuerPublic};
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcpTryFrom<(IssuerPublic<S>, Vec<ClaimType>)> for SignerPublicData {
    fn vcp_try_from((issuer_public, cts): (IssuerPublic<S>, Vec<ClaimType>)) -> VCPResult<SignerPublicData> {
         Ok(SignerPublicData {
             signer_public_setup_data : SignerPublicSetupData(to_opaque_json(&issuer_public)?),
             signer_public_schema     : cts,
         })
    }
}

impl<S: ShortGroupSignatureScheme> VcpTryFrom<&Box::<SignerPublicData>> for (IssuerPublic<S>, Vec<ClaimType>) {
    fn vcp_try_from(x: &Box::<SignerPublicData>) -> VCPResult<(IssuerPublic<S>, Vec<ClaimType>)> {
        let ip : IssuerPublic<S> = from_opaque_json(&x.signer_public_setup_data.0)?;
        Ok((ip, x.signer_public_schema.clone()))
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

