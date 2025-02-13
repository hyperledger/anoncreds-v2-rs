// ------------------------------------------------------------------------------
use crate::vcp::{Error, VCPResult};
// ------------------------------------------------------------------------------
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::str::from_utf8;
use zeroize::Zeroize;
// ------------------------------------------------------------------------------

// ===========================================================================
// Functions modeled on docknetwork/crypto*
// initially done in c_api and haskell-docknetwork-crypto-bindings
//
// see crypto-wasm-ts/src/encoder.ts d6205c4d09cba94ea24fe8ae2cae426564ff4729

// see crypto-wasm/src/common.rs 56f4723103ab83b1cae23df3d013573c5c0ffb5d
fn field_element_as_bytes(x : &mut Vec<u8>)
    -> VCPResult<ark_ff::Fp<ark_ff::MontBackend<ark_bls12_381::FrConfig, 4>, 4>>
{
    let f = fr_from_uint8_array(x)?; // TODO true as argument
    let mut bytes = vec![];
    f.serialize_compressed(&mut bytes)
        .map_err(|e| Error::General(format!("field_element_as_bytes {:?}", e)))?;
    Ok(f)
}

fn fr_from_uint8_array(bytes : &mut Vec<u8>) -> VCPResult<Fr>
{
    let elem = Fr::deserialize_compressed(&bytes[..])
        .map_err(|e| Error::General(format!("fr_from_uint8_array {:?}", e)))?;
    (*bytes).zeroize(); // NOTE: this does NOT happen if deserialize throws an error
    Ok(elem)
}

fn fr_to_uint8_array(fr : Fr) -> VCPResult<Vec<u8>>
{
    let mut bytes = vec![];
    fr.serialize_compressed(&mut bytes)
        .map_err(|e| Error::General(format!("fr_to_uint8_array {:?}", e)))?;
    Ok(bytes)
}

// crypto-wasm-ts/src/encoder.ts d6205c4d09cba94ea24fe8ae2cae426564ff4729
const MAX_ENCODED_LENGTH : usize = 32;

// ------------------------------------------------------------------------------
// ease-of-use functions

pub fn text_to_field_element(t : String) -> VCPResult<Fr>
{
    let bs = &mut t.as_bytes().to_vec();
    text_to_reversibly_encoded_bytestring(bs)?;
    field_element_as_bytes(bs)
}

fn text_to_reversibly_encoded_bytestring(t : &mut Vec<u8>) -> VCPResult<&mut Vec<u8>>
{
    let orig_len = t.len();
    if (orig_len > MAX_ENCODED_LENGTH) {
        Err(Error::General(format!(
            "text_to_reversibly_encoded_bytestring, can't pad String of length {:?} bytes to {:?}",
            orig_len, MAX_ENCODED_LENGTH)))
    } else {
        for i in orig_len .. MAX_ENCODED_LENGTH { t.push(0); }
        Ok(t)
    }
}

pub fn field_element_to_string(fr : Fr) -> VCPResult<String>
{
    let x = fr_to_uint8_array(fr)?;
    let mut v : Vec<u8> = vec!();
    for b in x { if b != 0 { v.push(b); } else { break; } }
    let vp = from_utf8(&v)
        .map_err(|e| Error::General(format!("field_element_to_bytestring {:?}", e)))?;
    Ok(vp.to_string())
}
