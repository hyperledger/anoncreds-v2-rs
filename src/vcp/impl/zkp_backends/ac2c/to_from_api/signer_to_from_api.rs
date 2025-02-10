// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::{CredentialBundle, Issuer, IssuerPublic};
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl VcpTryFrom<(IssuerPublic, Vec<ClaimType>)> for SignerPublicData {
    fn vcp_try_from((issuer_public, cts): (IssuerPublic, Vec<ClaimType>)) -> VCPResult<SignerPublicData> {
         Ok(SignerPublicData {
             signer_public_setup_data : SignerPublicSetupData(to_opaque_json(&issuer_public)?),
             signer_public_schema     : cts,
         })
    }
}

impl VcpTryFrom<&Box::<SignerPublicData>> for (IssuerPublic, Vec<ClaimType>) {
    fn vcp_try_from(x: &Box::<SignerPublicData>) -> VCPResult<(IssuerPublic, Vec<ClaimType>)> {
        let ip : IssuerPublic = from_opaque_json(&x.signer_public_setup_data.0)?;
        Ok((ip, x.signer_public_schema.clone()))
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<IssuerPublic> for SignerPublicSetupData {
    fn vcp_try_from(x: IssuerPublic) -> VCPResult<SignerPublicSetupData> {
        Ok(SignerPublicSetupData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&SignerPublicSetupData> for IssuerPublic {
    fn vcp_try_from(x: &SignerPublicSetupData) -> VCPResult<IssuerPublic> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<Issuer> for SignerSecretData {
    fn vcp_try_from(x: Issuer) -> VCPResult<SignerSecretData> {
        Ok(SignerSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&SignerSecretData> for Issuer {
    fn vcp_try_from(x: &SignerSecretData) -> VCPResult<Issuer> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<CredentialBundle> for Signature {
    fn vcp_try_from(x: CredentialBundle) -> VCPResult<Signature> {
        Ok(Signature(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&Signature> for CredentialBundle {
    fn vcp_try_from(x: &Signature) -> VCPResult<CredentialBundle> {
        from_opaque_json(&x.0)
    }
}

