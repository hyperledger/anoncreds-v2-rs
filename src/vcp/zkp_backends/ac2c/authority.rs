// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::ac2c::signer::create_signer_data;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{Issuer, IssuerPublic};
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

// Because AC2C conflates Issuer and Authority, it is convenient to just create a new Issuer to
// represent the Authority.  Using Verifiable Encryption functionality directly may make sense in
// future, but not before AC2C supports decryption.  Therefore, for now, we create a dummy Issuer to
// be used only for the purposes of verifiable encryption.
pub fn create_authority_data<S: ShortGroupSignatureScheme>() -> CreateAuthorityData {
    let create_signer_data = create_signer_data::<S>().clone();
    Arc::new(move |rng_seed| {
        // The schema is empty because we use the API-level create_signer_data, which adds the revocation
        // claim required by AC2C's "opinionated" requirement
        let schema = [];
        let SignerData {signer_public_data, signer_secret_data} = create_signer_data(rng_seed,&schema)?;
        let SignerPublicData {signer_public_setup_data, signer_public_schema} = *signer_public_data;
        let IssuerPublic::<S> {verifiable_encryption_key, ..} = from_api(&signer_public_setup_data)?;
        let Issuer::<S> {verifiable_decryption_key, ..} = from_api(&signer_secret_data)?;
        Ok(AuthorityData::new(AuthorityPublicData(signer_public_setup_data.0),
                              to_api(verifiable_decryption_key)?,
                              // NOTE: this is the key for verifying correct decryption (e.g., by
                              // Governance Body), *not* for actual decryption.
                              // TODO-VERIFIABLE-ENCRYPTION: replace with real data if needed when AC2C supports verifying
                              // correct decryption
                              AuthorityDecryptionKey("BOGUS-SEE-TODO-VERIFIABLE-ENCRYPTION".to_string())))
    })
}

