// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

impl VcpTryFrom<SecretKey<Bls12381G2Impl>> for AuthoritySecretData {
    fn vcp_try_from(x: SecretKey<Bls12381G2Impl>) -> VCPResult<AuthoritySecretData> {
        Ok(AuthoritySecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AuthoritySecretData> for SecretKey<Bls12381G2Impl> {
    fn vcp_try_from(x: &AuthoritySecretData) -> VCPResult<SecretKey<Bls12381G2Impl>> {
        from_opaque_json(&x.0)
    }
}

impl VcpTryFrom<SecretKey<Bls12381G2Impl>> for AuthorityDecryptionKey {
    fn vcp_try_from(x: SecretKey<Bls12381G2Impl>) -> VCPResult<AuthorityDecryptionKey> {
        Ok(AuthorityDecryptionKey(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AuthorityDecryptionKey> for SecretKey<Bls12381G2Impl> {
    fn vcp_try_from(x: &AuthorityDecryptionKey) -> VCPResult<SecretKey<Bls12381G2Impl>> {
        from_opaque_json(&x.0)
    }
}

