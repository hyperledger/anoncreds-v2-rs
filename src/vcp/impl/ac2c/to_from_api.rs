// ------------------------------------------------------------------------------
use crate::vcp::VCPResult;
use crate::vcp::r#impl::to_from::*;
use crate::vcp::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::{
    blsful::inner_types::G1Projective,
    blsful::{Bls12381G2Impl, SecretKey},
    CredentialBundle,
    Issuer, IssuerPublic,
    MembershipClaim,
    MembershipSigningKey,
    MembershipVerificationKey,
    Presentation,
};
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------
use serde::*;
use serde_cbor::*;
// ------------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeProofCommitmentSetup {
    pub message_generator : G1Projective,
    pub blinder_generator : G1Projective,
}

impl VcpTryFrom<&RangeProofCommitmentSetup> for RangeProofProvingKey {
    fn vcp_try_from(x: &RangeProofCommitmentSetup) -> VCPResult<RangeProofProvingKey> {
        Ok(RangeProofProvingKey(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&RangeProofProvingKey> for RangeProofCommitmentSetup {
    fn vcp_try_from(x: &RangeProofProvingKey) -> VCPResult<RangeProofCommitmentSetup> {
        from_opaque_json(&x.0)
    }
}

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

// ------------------------------------------------------------------------------

impl VcpTryFrom<Presentation> for Proof {
    fn vcp_try_from(x: Presentation) -> VCPResult<Proof> {
        Ok(Proof(to_opaque_cbor(&x)?))
    }
}

impl VcpTryFrom<&Proof> for Presentation {
    fn vcp_try_from(x: &Proof) -> VCPResult<Presentation> {
        from_opaque_cbor(&x.0)
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

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::SecretKey> for AccumulatorSecretData {
    fn vcp_try_from(x: vb20::SecretKey) -> VCPResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorSecretData> for vb20::SecretKey {
    fn vcp_try_from(x: &AccumulatorSecretData) -> VCPResult<vb20::SecretKey> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<&vb20::SecretKey> for AccumulatorSecretData {
    fn vcp_try_from(x: &vb20::SecretKey) -> VCPResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&str> for vb20::SecretKey {
    fn vcp_try_from(s: &str) -> VCPResult<vb20::SecretKey> {
        from_opaque_json(s)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::PublicKey> for AccumulatorPublicData {
    fn vcp_try_from(x: vb20::PublicKey) -> VCPResult<AccumulatorPublicData> {
        Ok(AccumulatorPublicData(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorPublicData> for vb20::PublicKey {
    fn vcp_try_from(x: &AccumulatorPublicData) -> VCPResult<vb20::PublicKey> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<(vb20::SecretKey, vb20::PublicKey)> for AccumulatorData {
    fn vcp_try_from((sk, pk) : (vb20::SecretKey, vb20::PublicKey)
    ) -> VCPResult<AccumulatorData> {
        Ok(AccumulatorData {
            public_data : AccumulatorPublicData(to_opaque_json(&pk)?),
            secret_data : AccumulatorSecretData(to_opaque_json(&sk)?),
        })
    }
}

impl VcpTryFrom<&AccumulatorData> for (vb20::SecretKey, vb20::PublicKey) {
    fn vcp_try_from(x: &AccumulatorData) -> VCPResult<(vb20::SecretKey, vb20::PublicKey)> {
        let AccumulatorData { secret_data, public_data } = x;
        let sk                                           = from_opaque_json(&secret_data.0)?;
        let pk                                           = from_opaque_json(&public_data.0)?;
        Ok((sk, pk))
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::Accumulator> for Accumulator {
    fn vcp_try_from(x: vb20::Accumulator) -> VCPResult<Accumulator> {
        Ok(Accumulator(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&Accumulator> for vb20::Accumulator {
    fn vcp_try_from(x: &Accumulator) -> VCPResult<vb20::Accumulator> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::Element> for AccumulatorElement {
    fn vcp_try_from(x : vb20::Element) -> VCPResult<AccumulatorElement> {
        Ok(AccumulatorElement(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorElement> for vb20::Element {
    fn vcp_try_from(x: &AccumulatorElement) -> VCPResult<vb20::Element> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcpTryFrom<vb20::MembershipWitness> for AccumulatorMembershipWitness {
    fn vcp_try_from(x : vb20::MembershipWitness) -> VCPResult<AccumulatorMembershipWitness> {
        Ok(AccumulatorMembershipWitness(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumulatorMembershipWitness> for vb20::MembershipWitness {
    fn vcp_try_from(x: &AccumulatorMembershipWitness) -> VCPResult<vb20::MembershipWitness> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AC2CWitnessUpdateInfo {
    pub ac2c_adds         : Vec<AccumulatorElement>,
    pub ac2c_rms          : Vec<AccumulatorElement>,
    pub ac2c_coefficients : Vec<Coefficient>,
}


impl VcpTryFrom<AC2CWitnessUpdateInfo> for AccumWitnessUpdateInfo {
    fn vcp_try_from(x : AC2CWitnessUpdateInfo) -> VCPResult<AccumWitnessUpdateInfo> {
        Ok(AccumWitnessUpdateInfo(to_opaque_json(&x)?))
    }
}

impl VcpTryFrom<&AccumWitnessUpdateInfo> for AC2CWitnessUpdateInfo {
    fn vcp_try_from(x: &AccumWitnessUpdateInfo) -> VCPResult<AC2CWitnessUpdateInfo> {
        from_opaque_json(&x.0)
    }
}
