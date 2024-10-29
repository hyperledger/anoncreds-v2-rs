// -----------------------------------------------------------------------------
use crate::vcp::{Error, SerdeJsonError, VCPResult};
// -----------------------------------------------------------------------------
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
// -----------------------------------------------------------------------------

pub fn decode_from_text<'de, T: Deserialize<'de> + Debug>(
    error_message: &str,
    input: &'de str,
) -> VCPResult<T> {
    // println!("decode_from_text: input: {:?}", input);
    let x = serde_json::from_str(input)
        .map_err(|err| Error::General(format!("{error_message}; error decoding; {input}; {err}")))?;
    // println!("decode_from_text: x: {:?}", x);
    Ok(x)
}

pub fn encode_to_text<T: Serialize + Debug>(t: &T) -> VCPResult<String> {
    serde_json::to_string(t).map_err(|err| Error::SerdeError(SerdeJsonError(err)))
}
