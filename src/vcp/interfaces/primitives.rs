//! The type aliases in this module and in [`crate::vcp::interfaces::non_primitives`]
//! are designed to enable:
//!   - defining the types of record fields using them (e.g. the `specific_prover` field of
//!     [`crate::vcp::interfaces::crypto_interface::CryptoInterface`] is defined to
//!     be of type `crate::vcp::interfaces::primitives::SpecificProver`),
//!     and similarly, the `create_proof` field of [`crate::vcp::api::PlatformApi`]
//!     is defined to be `crate::vcp::interfaces::non_primitives::CreateProof`
//!   - using them in the types of function definitions (e.g.
//!     [`crate::vcp::r#impl::general::proof::create_proof`] takes a function of type
//!        `crate::vcp::interfaces::primitives::SpecificProver` and returns a function
//!         of type `crate::vcp::interfaces::non_primitives::CreateProof`
//!
//! As a consequence of these goals, we wrote the function types in the form
//! [`Arc<dyn Fn(A) -> B + Send + Sync>`]. We arrive at this form via the
//! following propagation of constraints:
//!   - Some function definitions have the form `pub fn f(a: A) -> B { ... }`,
//!     where `B` is one of the function type aliases inside this module or
//!     [`crate::vcp::interfaces::non_primitives`].  (One example is
//!        [`crate::vcp::r#impl::general::proof::create_proof`].)
//!       - Because the function of type `B` is dynamically implemented (it is
//!         the output of `f`) and captures a variable, Rust requires it to be
//!         wrapped in `dyn`.
//!       - Because a `dyn` value does not have a statically determined size, it
//!         must be wrapped in a pointer type (e.g. [`Arc`] or [`Box`]).
//!       - Even though only some of the function definitions have the form
//!         `pub fn f(a: A) -> B { ... }` (i.e., some don't have a parameter), we
//!         define all of them in this style for consistency (so
//!         functions that don't require a parameter simply take 0
//!         parameters).
//!   - The function types are used in the field types of structs e.g.
//!     [`crate::vcp::interfaces::crypto_interface::CryptoInterface`].
//!       - Because pointers require allocation on the heap, and a term
//!         (e.g., [`crate::vcp::r#impl::ac2c::impl_ac2c::CRYPTO_INTERFACE_AC2C`]) of
//!         type [`crate::vcp::interfaces::crypto_interface::CryptoInterface`]
//!         is defined statically, that definition needs to be done inside a
//!         [`lazy_static::lazy_static`].
//!       - Because [`lazy_static::lazy_static`] requires that the definitions
//!         inside of it are safe in a multithreaded context, we must use an
//!         [`Arc`] as the pointer type to wrap the function types, and the
//!         dynamic function type inside of it must implement [`Send`] and
//!         [`Sync`].

// ------------------------------------------------------------------------------
pub use crate::vcp::VCPResult;
pub use crate::vcp::interfaces::primitives::types::*;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------
pub mod types;

// ---------------------------------------------------------------------------
// types of "primitive" functions that implementer must provide

pub type SpecificCreateSignerData = Arc<
    dyn Fn(
            Natural, // RNG seed
            &[ClaimType],
            &[CredAttrIndex],
        ) -> VCPResult<(SignerPublicSetupData,SignerSecretData)>
        + Send
        + Sync,
>;

pub type CreateAccumulatorData = Arc<
    dyn Fn(
            Natural, // RNG seed
    ) -> VCPResult<CreateAccumulatorResponse>
        + Send
        + Sync,
>;

pub type SpecificCreateBlindSigningInfo = Arc<
    dyn Fn(
            Natural, // RNG seed
            &SignerPublicSetupData,
            &[ClaimType],
            &[CredAttrIndexAndDataValue]  // Attributes to be blinded
        ) -> VCPResult<BlindSigningInfo>
        + Send
        + Sync,
>;

pub type SpecificSign = Arc<
    dyn Fn(
            Natural, // RNG seed
            &[DataValue],
            &SignerData,
        ) -> VCPResult<Signature>
        + Send
        + Sync,
>;

pub type SpecificSignWithBlindedAttributes = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[ClaimType],
        &[CredAttrIndexAndDataValue],  // Non-blinded attributes
        &BlindInfoForSigner,
        &SignerPublicSetupData,
        &SignerSecretData,
    ) -> VCPResult<BlindSignature>
    + Send
    + Sync,
>;

pub type SpecificUnblindBlindedSignature = Arc<
    dyn Fn(
        &[ClaimType],
        &[CredAttrIndexAndDataValue],  // Blinded attributes, same as used for CreateBlindSigningInfo
        &BlindSignature,
        &InfoForUnblinding
    ) -> VCPResult<Signature>
    + Send
    + Sync,
>;

pub type CreateAccumulatorElement = Arc<
    dyn Fn(
        AccumulatorMember
    ) -> VCPResult<AccumulatorElement>
    + Send
    + Sync,
>;

pub type AccumulatorAddRemove = Arc<
    dyn Fn(
            &AccumulatorData,
            &Accumulator,
            &HashMap<HolderID, AccumulatorElement>,
            &[AccumulatorElement],
        ) -> VCPResult<AccumulatorAddRemoveResponse>
        + Send
        + Sync,
>;

pub type GetAccumulatorWitness = Arc<
    dyn Fn(
        &AccumulatorData,
        &Accumulator,
        &AccumulatorElement,
    ) -> VCPResult<AccumulatorMembershipWitness>
    + Send
    + Sync,
>;

pub type UpdateAccumulatorWitness = Arc<
    dyn Fn(
            &AccumulatorMembershipWitness,
            &AccumulatorElement,
            &AccumulatorWitnessUpdateInfo,
        ) -> VCPResult<AccumulatorMembershipWitness>
        + Send
        + Sync,
>;

pub type CreateMembershipProvingKey = Arc<
    dyn Fn(
            Natural, // RNG seed
        ) -> VCPResult<MembershipProvingKey>
        + Send
        + Sync,
>;

pub type CreateRangeProofProvingKey = Arc<
    dyn Fn(
            Natural, // RNG seed
        ) -> VCPResult<RangeProofProvingKey>
        + Send
        + Sync,
    >;

pub type GetRangeProofMaxValue = Arc<
    dyn Fn() -> u64
        + Send
        + Sync,
    >;

pub type CreateAuthorityData = Arc<
    dyn Fn(
            Natural, // RNG seed
        ) -> VCPResult<AuthorityData>
        + Send
        + Sync,
>;

pub type SpecificProver = Arc<
    dyn Fn(
            &[ProofInstructionGeneral<ResolvedDisclosure>],
            &EqualityReqs,
            &HashMap<CredentialLabel, SignatureAndRelatedData>,
            Nonce,
        ) -> VCPResult<WarningsAndProof>
        + Send
        + Sync,
>;

pub type SpecificVerifier = Arc<
    dyn Fn(
            &[ProofInstructionGeneral<ResolvedDisclosure>],
            &EqualityReqs,
            &Proof,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
            Nonce,
        ) -> VCPResult<WarningsAndDecryptResponses>
        + Send
        + Sync,
>;

pub type SpecificVerifyDecryption = Arc<
    dyn Fn(
            &[ProofInstructionGeneral<ResolvedDisclosure>],
            &EqualityReqs,
            &Proof,
            &HashMap<AuthorityLabel, AuthorityDecryptionKey>,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptResponse>>>,
        ) -> VCPResult<Vec<Warning>>
        + Send
        + Sync,
>;
