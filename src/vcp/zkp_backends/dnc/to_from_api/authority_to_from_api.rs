// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::types as api;
use crate::vcp::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use saver::keygen::DecryptionKey as SaverDecryptionKey;
use saver::keygen::SecretKey     as SaverSecretKey;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr};
// ------------------------------------------------------------------------------

impl VcpTryFrom<AuthorityPublicSetupData> for api::AuthorityPublicData {
    fn vcp_try_from(x: AuthorityPublicSetupData) -> VCPResult<api::AuthorityPublicData> {
        Ok(api::AuthorityPublicData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::AuthorityPublicData> for AuthorityPublicSetupData {
    fn vcp_try_from(x: &api::AuthorityPublicData) -> VCPResult<AuthorityPublicSetupData> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<SaverSecretKey::<Fr>> for api::AuthoritySecretData {
    fn vcp_try_from(x: SaverSecretKey::<Fr>) -> VCPResult<api::AuthoritySecretData> {
        Ok(api::AuthoritySecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::AuthoritySecretData> for SaverSecretKey::<Fr> {
    fn vcp_try_from(x: &api::AuthoritySecretData) -> VCPResult<SaverSecretKey::<Fr>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<SaverDecryptionKey::<Bls12_381>> for api::AuthorityDecryptionKey {
    fn vcp_try_from(x: SaverDecryptionKey::<Bls12_381>) -> VCPResult<api::AuthorityDecryptionKey> {
        Ok(api::AuthorityDecryptionKey(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&api::AuthorityDecryptionKey> for SaverDecryptionKey::<Bls12_381> {
    fn vcp_try_from(x: &api::AuthorityDecryptionKey) -> VCPResult<SaverDecryptionKey::<Bls12_381>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<(Fr, G1)> for api::DecryptionProof {
    fn vcp_try_from(x: (Fr, G1)) -> VCPResult<api::DecryptionProof> {
        Ok(api::DecryptionProof(to_opaque_ark(&x)?))
    }
}

impl VcpTryFrom<&api::DecryptionProof> for (Fr, G1) {
    fn vcp_try_from(x: &api::DecryptionProof) -> VCPResult<(Fr, G1)> {
        from_opaque_ark(&x.0)
    }
}

