// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::r#impl::ac2c::accumulator::*;
use crate::vcp::r#impl::ac2c::proof::*;
use crate::vcp::r#impl::ac2c::signer::{create_signer_data, sign};
use crate::vcp::r#impl::ac2c::to_from_api::*;
use crate::vcp::r#impl::to_from::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::inner_types::*;
use crate::prelude::{Issuer, IssuerPublic, MembershipSigningKey, MembershipVerificationKey};
use crate::knox::accumulator::vb20;
// ------------------------------------------------------------------------------
use lazy_static::lazy_static;
use std::rc::*;
use std::sync::Arc;
// ------------------------------------------------------------------------------

lazy_static! {
    pub static ref CRYPTO_INTERFACE_AC2C: CryptoInterface = CryptoInterface {
        create_signer_data: create_signer_data(),
        sign: sign(),
        create_range_proof_proving_key: create_range_proof_proving_key(),
        create_authority_data: create_authority_data(),
        create_accumulator_data: create_accumulator_data(),
        create_membership_proving_key: create_membership_proving_key(),
        create_accumulator_element: create_accumulator_element(),
        accumulator_add_remove: accumulator_add_remove(),
        update_accumulator_witness: update_accumulator_witness(),
        specific_prover: specific_prover_ac2c(),
        specific_verifier: specific_verifier_ac2c(),
        specific_verify_decryption: specific_verify_decryption_ac2c(),
    };
}

pub fn create_range_proof_proving_key() -> CreateRangeProofProvingKey {
    Arc::new(|_rng_seed| {
        let message_generator = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"message generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        let blinder_generator = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            b"blinder generator",
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
        to_api(&RangeProofCommitmentSetup { message_generator, blinder_generator })
    })
}

// Because AC2C conflates Issuer and Authority, it is convenient to just create a new Issuer to
// represent the Authority.  Using Verifiable Encryption functionality directly may make sense in
// future, but not before AC2C supports decryption.  Therefore, for now, we create a dummy Issuer to
// be used only for the purposes of verifiable encryption.
pub fn create_authority_data() -> CreateAuthorityData {
    let create_signer_data = create_signer_data().clone();
    Arc::new(move |rng_seed| {
        // The schema is empty because we use the API-level create_signer_data, which adds the revocation
        // claim required by AC2C's "opinionated" requirement
        let schema = [];
        let SignerData {signer_public_data, signer_secret_data} = create_signer_data(rng_seed,&schema)?;
        let SignerPublicData {signer_public_setup_data, signer_public_schema} = *signer_public_data;
        let IssuerPublic {verifiable_encryption_key, ..} = from_api(&signer_public_setup_data)?;
        let Issuer {verifiable_decryption_key, ..} = from_api(&signer_secret_data)?;
        Ok(AuthorityData::new(AuthorityPublicData(signer_public_setup_data.0),
                              to_api(verifiable_decryption_key)?,
                              // NOTE: this is the key for verifying correct decryption (e.g., by
                              // Governance Body), *not* for actual decryption.
                              // TODO-VERIFIABLE-ENCRYPTION: replace with real data if needed when AC2C supports verifying
                              // correct decryption
                              AuthorityDecryptionKey("BOGUS-SEE-TODO-VERIFIABLE-ENCRYPTION".to_string())))
    })
}

