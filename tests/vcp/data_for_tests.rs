// -----------------------------------------------------------------------------
use credx::vcp::interfaces::types::*;
// -----------------------------------------------------------------------------
use crate::vcp::test_framework as tf;
// -----------------------------------------------------------------------------
use lazy_static::lazy_static;
use maplit::hashmap;
use std::collections::HashMap;
// -----------------------------------------------------------------------------

lazy_static! {
    pub static ref D_ISSUER_LABEL: tf::IssuerLabel = "DMV".to_string();
    pub static ref S_ISSUER_LABEL: tf::IssuerLabel = "SubscriptionCorp".to_string();
    pub static ref POLICE_AUTHORITY_LABEL: AuthorityLabel = "Police".to_string();
}

lazy_static! {
    pub static ref HOLDER_1: tf::HolderLabel = "Holder1".to_string();
}

lazy_static! {
    pub static ref DEFAULT_ISSUERS: HashMap<tf::IssuerLabel, Vec<ClaimType>> = hashmap!(
        D_SPD_KEY.to_owned() => D_CTS.to_owned(),
        S_SPD_KEY.to_owned() => S_CTS.to_owned(),
    );
}

lazy_static! {
    pub static ref DEFAULT_CREDS: HashMap<CredentialLabel, (tf::IssuerLabel, Vec<DataValue>)> = hashmap!(
        D_CRED_LABEL.to_owned() => (D_SPD_KEY.to_owned(), D_VALS.to_owned()),
        S_CRED_LABEL.to_owned() => (S_SPD_KEY.to_owned(), S_VALS.to_owned()),
    );
}

lazy_static! {
    pub static ref D_VALS: Vec<DataValue> = vec![
      DataValue::DVText("CredentialMetadata (fromList [(\"purpose\",DVText \"DriverLicense\"),(\"version\",DVText \"1.0\")])".to_string()),
      DataValue::DVInt(37852),
      DataValue::DVText("123-45-6789".to_string()),
      DataValue::DVInt(180),
      DataValue::DVText("abcdef0123456789abcdef0123456789".to_string()),
    ];
}

lazy_static! {
    pub static ref D_VALS2: Vec<DataValue> = vec![
      DataValue::DVText("CredentialMetadata (fromList [(\"purpose\",DVText \"DriverLicense\"),(\"version\",DVText \"1.0\")])".to_string()),
      DataValue::DVInt(37852),
      DataValue::DVText("xxx-xx-xxxx".to_string()),
      DataValue::DVInt(180),
      DataValue::DVText("ABCDEF0123456789ABCDEF0123456789".to_string())
    ];
}

pub const D_META_IDX: u64 = 0;
#[allow(dead_code)]
pub const D_DOB_IDX: u64 = 1;
pub const D_SSN_IDX: u64 = 2;
pub const D_ACCUM_IDX: u64 = 4;

lazy_static! {
  pub static ref S_VALS: Vec<DataValue> = vec![
    DataValue::DVText("CredentialMetadata (fromList [(\"purpose\",DVText \"MonthlySubscription\"),(\"version\",DVText \"1.0t\")])".to_string()),
    DataValue::DVText("aaaabcdef0123456789abcdef0123456t".to_string()),
    DataValue::DVInt(49997),
    DataValue::DVText("123-45-6789".to_string()),
  ];
}

pub const S_META_IDX: u64 = 0;
pub const S_ACCUM_IDX: u64 = 1;
#[allow(dead_code)]
pub const S_VALID_DAYS_IDX: u64 = 2;
pub const S_SSN_IDX: u64 = 3;

lazy_static! {
    pub static ref MULTI_ACCUM_VALS: Vec<DataValue> = [
        vec![DataValue::DVText(
            "bbbbbbdef0123456789abcdef0123456".to_string()
        ),],
        S_VALS.clone()
    ]
    .concat();
}

// -----------------------------------------------------------------------------

lazy_static! {
  pub static ref D_CTS: Vec<ClaimType> = vec![
    ClaimType::CTText,
    ClaimType::CTInt,
    ClaimType::CTText, // CTEncryptableText
    ClaimType::CTInt,
    ClaimType::CTAccumulatorMember
  ];
}

lazy_static! {
  pub static ref D_CTS_WITH_VE: Vec<ClaimType> = vec![
    ClaimType::CTText,
    ClaimType::CTInt,
    ClaimType::CTEncryptableText,
    ClaimType::CTInt,
    ClaimType::CTAccumulatorMember
  ];
}

lazy_static! {
    pub static ref S_CTS: Vec<ClaimType> = vec![
      ClaimType::CTText,
      ClaimType::CTAccumulatorMember,
      ClaimType::CTInt,
      ClaimType::CTText, // CTEncryptableText
    ];
}

lazy_static! {
    pub static ref MULTI_ACCUM_CTS: Vec<ClaimType> = vec![
        ClaimType::CTText,
        ClaimType::CTInt,
        ClaimType::CTAccumulatorMember,
        ClaimType::CTInt,
        ClaimType::CTAccumulatorMember,
    ];
}

// -----------------------------------------------------------------------------

lazy_static! {
    pub static ref D_CRED_LABEL: String = "dlCred".to_string();
    pub static ref S_CRED_LABEL: String = "subCred".to_string();
}

lazy_static! {
    pub static ref D_SPD_KEY: String = "dSignerPublicData".to_string();
    pub static ref S_SPD_KEY: String = "sSignerPublicData".to_string();
}

#[allow(dead_code)]
pub fn proof_reqs_with(
    (d0, d1): (Vec<RawIndex>, Vec<RawIndex>),
    (ia0, ia1): (Vec<InAccumInfo>, Vec<InAccumInfo>),
    (iri0, iri1): (Vec<InRangeInfo>, Vec<InRangeInfo>),
    (eq0, eq1): (Vec<EqInfo>, Vec<EqInfo>),
    (ef0, ef1): (Vec<IndexAndLabel>, Vec<IndexAndLabel>),
) -> HashMap<CredentialLabel, CredentialReqs> {
    hashmap!(
      D_CRED_LABEL.to_string() => CredentialReqs {
        signer_label: D_SPD_KEY.to_string(),
        disclosed: Disclosed(d0),
        in_accum: InAccum(ia0),
        not_in_accum: NotInAccum(vec![]),
        in_range: InRange(iri0),
        encrypted_for: EncryptedFor(ef0),
        equal_to: EqualTo(eq0)
      },
      S_CRED_LABEL.to_string() => CredentialReqs {
        signer_label: S_SPD_KEY.to_string(),
        disclosed: Disclosed(d1),
        in_accum: InAccum(ia1),
        not_in_accum: NotInAccum(vec![]),
        in_range: InRange(iri1),
        encrypted_for: EncryptedFor(ef1),
        equal_to: EqualTo(eq1)
      }
    )
}
