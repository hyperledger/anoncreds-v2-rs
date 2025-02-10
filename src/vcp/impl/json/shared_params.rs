// -----------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
use crate::vcp::types::{DataValue, SharedParamKey, SharedParamValue, SharedParamValue::*};
// -----------------------------------------------------------------------------
use std::collections::HashMap;
// -----------------------------------------------------------------------------

pub type SharedParams = HashMap<SharedParamKey, SharedParamValue>;

pub fn lookup_one_text<'a>(k: &SharedParamKey, params: &'a SharedParams) -> VCPResult<&'a String> {
    let v = params
        .get(k)
        .ok_or(Error::General(format!("SharedParams; missing key; {k}")))?;
    let e = || {
        Error::General(format!(
            "SharedParams; {k} should be SPVOne DVText, but was {v:?}"
        ))
    };
    match v {
        SharedParamValue::SPVOne(DataValue::DVText(x)) => Ok(x),
        // This has to be a nested pattern match since I can't match on
        // `&Vec<DataValue>` inline.
        SharedParamValue::SPVList(vs) => match &vs[..] {
            [DataValue::DVText(x)] => Ok(x), // TODO: temporary workaround, or reasonable semantic change?
            x => Err(e()),
        },
        _ => Err(e()),
    }
}

pub fn lookup_one_int<'a>(k: &SharedParamKey, params: &'a SharedParams) -> VCPResult<&'a u64> {
    let v = params
        .get(k)
        .ok_or(Error::General(format!("SharedParams; missing key; {k}")))?;
    match v {
        SharedParamValue::SPVOne(DataValue::DVInt(x)) => Ok(x),
        _ => Err({
            Error::General(format!(
                "SharedParams; {k} should be SPVOne DVInt, but was {v:?}"
            ))
        }),
    }
}

pub fn put_shared_one(
    k: SharedParamKey,
    v: DataValue,
    m: &mut HashMap<SharedParamKey,SharedParamValue>) {
    let _ = m.insert(k,SPVOne(v));
}
