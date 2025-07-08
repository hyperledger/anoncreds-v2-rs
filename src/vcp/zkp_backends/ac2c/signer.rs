use crate::blind::{BlindCredential, BlindCredentialBundle, BlindCredentialRequest};
// ------------------------------------------------------------------------------
use crate::{get_location_and_backtrace_on_panic, str_vec_from};
use crate::vcp::r#impl::util::{insert_throw_if_present, lookup_throw_if_out_of_bounds};
use crate::vcp::{convert_to_crypto_library_error, Error, UnexpectedError, VCPResult};
use crate::vcp::r#impl::catch_unwind_util::*;
use crate::vcp::r#impl::to_from_api::*;
use crate::vcp::r#impl::util::*;
use crate::vcp::interfaces::crypto_interface::*;
use crate::vcp::zkp_backends::ac2c::presentation_request_setup::attr_label_for_idx;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude;
use crate::prelude::{
    ClaimData,ClaimSchema,CredentialSchema, HashedClaim, Issuer,
    IssuerPublic, NumberClaim, RevocationClaim, ScalarClaim
};
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

// AC2C is "opinionated" and requires issuer to have a revocation claim, but we do not use it
static UNUSED_REVOCATION_LABEL: &str =
        "BOGUS KEY - SHOULD NOT CONFLICT WITH ATTRIBUTE LABELS";

pub fn specific_create_signer_data<S: ShortGroupSignatureScheme>() -> SpecificCreateSignerData {
    Arc::new(|_rng_seed, schema, blind_attr_idxs| {
        let schema_claims = create_schema_claims(schema)?;
        let blind_attrs_1 = blind_attr_idxs
            .iter()
            .map(|x| attr_label_for_idx(*x))
            .collect::<Vec<_>>();
        let blind_attrs = blind_attrs_1
            .iter()
            .map(|x| x.as_str())
            .collect::<Vec<&str>>();
        let cred_schema = get_location_and_backtrace_on_panic!(
            CredentialSchema::new(Some(LABEL), Some(DESCRIPTION), &blind_attrs, &schema_claims)
                .map_err(|e| convert_to_crypto_library_error("AC2C", "create_signer_data", e)))?;
        let (issuer_public, issuer_secret) = Issuer::<S>::new(&cred_schema);
        Ok((to_api(issuer_public)?,
            to_api(issuer_secret)?
        ))
    })
}

pub fn sign<S: ShortGroupSignatureScheme>() -> SpecificSign {
    Arc::new(|_rng_seed, vals, sd| {
        let SignerData {
            signer_public_data,
            signer_secret_data,
        } = sd;
        // TODO: - make sign take schema from General, like sign_with_blinded_attributes
        //       - also refactor with sign_with_blinded_attributes
        let (_s, sdcts, _) : (IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>) = from_api(signer_public_data)?;
        let mut claim_data = vals_to_claim_data(&sdcts, vals)?;
        let rev_claim_data = RevocationClaim::from(UNUSED_REVOCATION_LABEL).into();
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

pub fn specific_create_blind_signing_info<S: ShortGroupSignatureScheme>()
-> SpecificCreateBlindSigningInfo {
    Arc::new(|_rng_seed, spsd, schema, blind_attrs| {
        let issuer_public: IssuerPublic<S> = from_api(spsd)?;
        // TODO: DRY fail, refactor
        let blind_claims: BTreeMap<String,ClaimData> = blind_attrs
            .iter()
            .map(|idx_val_pair| create_label_claim_pair("create_blind_signing_info, AC2C", schema, idx_val_pair))
            .collect::<VCPResult<BTreeMap<_,_>>>()?;
        let (blind_credential_request, blinder) =
            BlindCredentialRequest::new(&issuer_public, &blind_claims)
            .map_err(|e| Error::General(ic_semi(&str_vec_from!("specific_create_blind_signing_info",
                                                               "BlindCredentialRequest::new",
                                                               format!("{e:?}")))))?;
        Ok(BlindSigningInfo {blind_info_for_signer: to_api(blind_credential_request)?,
                             blinded_attributes: blind_attrs.to_vec(),
                             info_for_unblinding: to_api(blinder)?})
    })
}

pub fn specific_sign_with_blinded_attributes<S: ShortGroupSignatureScheme>(
) -> SpecificSignWithBlindedAttributes {
    Arc::new(|_rng_seed, schema, non_blinded_attrs, bifs, _, signer_secret_data| {
        // TODO: refactor, DRY fail with sign
        let mut claims: BTreeMap<String,ClaimData> = non_blinded_attrs
            .iter()
            .map(|idx_val_pair| create_label_claim_pair("sign_with_blinded_attributes, AC2C", schema, idx_val_pair))
            .collect::<VCPResult<BTreeMap<_,_>>>()?;
        let rev_claim_data: ClaimData = RevocationClaim::from(UNUSED_REVOCATION_LABEL).into();
        let rev_claim_label = UNUSED_REVOCATION_LABEL.to_string();
        insert_throw_if_present(rev_claim_label, rev_claim_data, &mut claims, Error::General,
                                &str_vec_from!("sign_with_blinded_attributes", "AC2C", "UNEXPECTED"));
        let mut issuer : Issuer<S> = from_api(signer_secret_data)?;
        // cannot use get_location_and_backtrace_on_panic! (in its current form) here because
        // the type `&mut issuer::Issuer` may not be safely transferred across an unwind boundary
        let sig = issuer.blind_sign_credential(&from_api(bifs)?, &claims)
            .map_err(|e| convert_to_crypto_library_error("AC2C", "sign_with_blinded_attributes", e))?;
        to_api(sig)
    })
}

pub fn specific_unblind_blinded_signature<S: ShortGroupSignatureScheme>(
) -> SpecificUnblindBlindedSignature {
    Arc::new(|schema, blinded_attrs, blinded_sig, blinder| {
        let mut claims: BTreeMap<String,ClaimData> = blinded_attrs
            .iter()
            .map(|idx_val_pair|
                 create_label_claim_pair("sign_with_blinded_attributes, AC2C",
                                         schema, idx_val_pair))
            .collect::<VCPResult<BTreeMap<_,_>>>()?;
        let blinded_sig: BlindCredentialBundle<S> = from_api(blinded_sig)?;
        let sig = blinded_sig.to_unblinded(&claims, from_api(blinder)?)
            .map_err(|e| convert_to_crypto_library_error("AC2C", "unblind_blinded_signature", e))?;
        to_api(sig)
    })
}

// ------------------------------------------------------------------------------

fn create_label_claim_pair(
    s      : &str,
    schema : &[ClaimType],
    CredAttrIndexAndDataValue { index, value } : &CredAttrIndexAndDataValue,
) -> VCPResult<(String, ClaimData)> {
    let ct = lookup_throw_if_out_of_bounds(
        schema, *index as usize, Error::General,
        &str_vec_from!(s, "createLabelClaimPair"))?;
    Ok((attr_label_for_idx(*index),val_to_claim_data((ct,value))?))
}

static LABEL       : &str = "Label needed to satisfy AC2C interface";
static DESCRIPTION : &str = "Description needed to satisfy AC2C interface";

fn create_schema_claim(
    (idx,ct) : (usize, &ClaimType)
) -> VCPResult<ClaimSchema>
{
    let aix = attr_label_for_idx(idx as u64);
    match ct {
        // For AC2C, we have to pick a ClaimSchema when creating an Issuer, so we default to Hashed.
        // This means that we will not be able to support range proofs for CTTextOrInt attributes
        ClaimType::CTText | ClaimType::CTTextOrInt =>
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Hashed,
                label          : aix,
                print_friendly : true,
                validators     : vec![],
            }),
        ClaimType::CTEncryptableText =>
            Ok(ClaimSchema {
                claim_type     : prelude::ClaimType::Scalar,
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
        label          : UNUSED_REVOCATION_LABEL.to_string(),
        print_friendly : false,
        validators     : vec![],
    };
    cts.iter()
        .enumerate()
        .map(create_schema_claim)
        .chain([Ok(rev_clm)])
        .collect::<VCPResult<Vec<_>>>()
}

pub fn val_to_claim_data(
    ct_dv : (&ClaimType, &DataValue)
) -> VCPResult<ClaimData>
{
    match ct_dv
    {
        (ClaimType::CTText             , DataValue::DVText(t)) => Ok(HashedClaim::from(t).into()),
        (ClaimType::CTTextOrInt        , DataValue::DVText(t)) => Ok(HashedClaim::from(t).into()),
        // Turn Int into Text so we can still sign; will cause an error if/when range proof requested
        (ClaimType::CTTextOrInt        , DataValue::DVInt(i))  => Ok(HashedClaim::from(i.to_string()).into()),
        (ClaimType::CTEncryptableText  , DataValue::DVText(t)) =>
            Ok(ScalarClaim::encode_str(t)
               .map_err(|e| Error::General(
                   format!("val_claim_to_data: CTEncryptableText encoding error {e:?}")))?.into()),
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
