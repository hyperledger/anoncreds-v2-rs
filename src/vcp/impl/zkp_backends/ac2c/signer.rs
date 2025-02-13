// ------------------------------------------------------------------------------
use crate::get_location_and_backtrace_on_panic;
use crate::vcp::{convert_to_crypto_library_error, Error, UnexpectedError, VCPResult};
use crate::vcp::r#impl::common::catch_unwind_util::*;
use crate::vcp::r#impl::common::to_from_api::*;
use crate::vcp::r#impl::zkp_backends::ac2c::presentation_request_setup::attr_label_for_idx;
use crate::vcp::interfaces::crypto_interface::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude;
use crate::prelude::{
    ClaimData,ClaimSchema,CredentialSchema,
    HashedClaim, Issuer, IssuerPublic, NumberClaim, RevocationClaim,
};
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

pub fn create_signer_data<S: ShortGroupSignatureScheme>() -> CreateSignerData {
    Arc::new(|_rng_seed, sdcts| {
        let schema_claims = create_schema_claims(sdcts)?;
        let cred_schema = get_location_and_backtrace_on_panic!(
            CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &[], &schema_claims)
                .map_err(|e| convert_to_crypto_library_error("AC2C", "create_signer_data", e)))?;
        let (issuer_public, issuer_secret) = Issuer::<S>::new(&cred_schema);
        Ok(SignerData::new(
            to_api((issuer_public, sdcts.to_vec()))?,
            to_api(issuer_secret)?,
        ))
    })
}

pub fn sign<S: ShortGroupSignatureScheme>() -> Sign {
    Arc::new(|_rng_seed, vals, sd| {
        let SignerData {
            signer_public_data,
            signer_secret_data,
        } = sd;
        let (_s, sdcts) : (IssuerPublic<S>, Vec<ClaimType>) = from_api(signer_public_data)?;
        let mut claim_data = vals_to_claim_data(&sdcts, vals)?;
        let rev_claim_data = RevocationClaim::from("NOT USED").into();
        claim_data.push(rev_claim_data);
        // This is `mut` because AC2C `sign_credential`, when it signs,
        // adds an element to the opinionated revocation accumulator
        // stored inside `Issuer`.
        // We ignore the accumulator, so the `mut` is to satisfy the compiler.
        let mut issuer : Issuer<S> = from_api(signer_secret_data)?;
        // cannot use get_location_and_backtrace_on_panic! (in its current form) here because
        // the type `&mut issuer::Issuer` may not be safely transferred across an unwind boundary
        let sig = issuer
            .sign_credential(&claim_data)
            .map_err(|e| convert_to_crypto_library_error("AC2C", "sign", e))?;
        to_api(sig)
    })
}

// ------------------------------------------------------------------------------

static LABEL       : &str = "Label needed to satisfy AC2C interface";
static DESCRIPTION : &str = "Description needed to satisfy AC2C interface";

fn create_schema_claim(
    (idx,ct) : (usize, &ClaimType)
) -> VCPResult<ClaimSchema>
{
    let aix = attr_label_for_idx(idx as u64);
    match ct {
        ClaimType::CTText =>
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Hashed,
                label          : aix,
                print_friendly : true,
                validators     : vec![],
            }),
        ClaimType::CTEncryptableText =>
            // TODO-VERIFIABLE-ENCRYPTION: reversible encoding, etc.
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Hashed,
                label          : aix,
                print_friendly : true,
                validators     : vec![],
            }),
        ClaimType::CTInt =>
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Number,
                label          : aix,
                print_friendly : true,
                validators     : vec![],
            }),
        ClaimType::CTAccumulatorMember =>
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Hashed,
                label          : aix,
                print_friendly : true,
                validators     : vec![],
            }),
    }
}

// pub for test
pub fn create_schema_claims(
    cts : &[ClaimType]
) -> VCPResult<Vec<ClaimSchema>>
{
    let rev_clm = ClaimSchema {
        claim_type     : prelude::ClaimType::Revocation,
        label          : "identifier".to_string(),
        print_friendly : false,
        validators     : vec![],
    };
    cts.iter()
        .enumerate()
        .map(create_schema_claim)
        .chain([Ok(rev_clm)])
        .collect::<VCPResult<Vec<_>>>()
}

fn val_to_claim_data(
    ct_dv : (&ClaimType, &DataValue)
) -> VCPResult<ClaimData>
{
    match ct_dv
    {
        (ClaimType::CTText             , DataValue::DVText(t)) => Ok(HashedClaim::from(t).into()),
        // TODO-VERIFIABLE-ENCRYPTION: need a new ReversiblyEncodedClaim; using HashedClaim for now
        // to make progress.  Will be better to implement and test reversible encoding when
        // decryption is implemented.
        (ClaimType::CTEncryptableText  , DataValue::DVText(t)) => Ok(HashedClaim::from(t).into()),
        (ClaimType::CTInt              , DataValue::DVInt(i))  => Ok(NumberClaim::from(*i as usize).into()),
        (ClaimType::CTAccumulatorMember, DataValue::DVText(t)) => Ok(HashedClaim::from(t).into()),
        _x => Err(Error::General(format!("val_to_claim_data, UNEXPECTED combination: {:?} {:?}", ct_dv.0, ct_dv.1)))
    }
}

fn vals_to_claim_data(
    sdcts : &[ClaimType],
    vals  : &[DataValue],
) -> VCPResult<Vec<ClaimData>>
{
    if sdcts.len() != vals.len() {
        Err(Error::General(format!(
            "vals_to_claim_data, number of values and claim types unequal: {:?} {:?}", sdcts, vals)))
    } else {
        sdcts.iter().zip(vals.iter())
            .map(val_to_claim_data)
            .collect::<VCPResult<Vec<_>>>()
    }
}
