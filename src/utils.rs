use crate::error::Error;
use crate::CredxResult;
use group::{Group, GroupEncoding};
use serde::{
    de::{DeserializeOwned, Error as DError, Unexpected, Visitor},
    Deserializer, Serialize, Serializer,
};
use std::fmt::{self, Formatter};
use std::marker::PhantomData;
use yeti::knox::bls12_381_plus::{G1Affine, G1Projective, Scalar};

pub const TOP_BIT: u64 = i64::MIN as u64;

pub fn get_num_scalar(num: isize) -> Scalar {
    Scalar::from(zero_center(num))
}

pub fn zero_center(num: isize) -> u64 {
    num as u64 ^ TOP_BIT
}

pub fn serialize_point<P: Group + GroupEncoding + Serialize + DeserializeOwned, S: Serializer>(
    point: &P,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = point.to_bytes().as_ref().to_vec();
    s.serialize_bytes(bytes.as_slice())
}

pub fn deserialize_point<
    'de,
    P: Group + GroupEncoding + Serialize + DeserializeOwned,
    D: Deserializer<'de>,
>(
    d: D,
) -> Result<P, D::Error> {
    struct PointVisitor<PP: Group + GroupEncoding + Serialize + DeserializeOwned> {
        _marker: PhantomData<PP>,
    }

    impl<'de, PP: Group + GroupEncoding + Serialize + DeserializeOwned> Visitor<'de>
        for PointVisitor<PP>
    {
        type Value = PP;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "a byte sequence")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: DError,
        {
            let mut repr = PP::Repr::default();
            if repr.as_ref().len() != v.len() {
                return Err(DError::invalid_type(Unexpected::Bytes(v), &self));
            }
            repr.as_mut().copy_from_slice(v);
            let point = PP::from_bytes(&repr);
            if point.is_none().unwrap_u8() == 1u8 {
                return Err(DError::invalid_type(Unexpected::Bytes(v), &self));
            }
            Ok(point.unwrap())
        }
    }

    d.deserialize_bytes(PointVisitor::<P> {
        _marker: PhantomData,
    })
}

pub fn scalar_from_hex_str(sc: &str, e: Error) -> CredxResult<Scalar> {
    let bytes = hex::decode(sc).map_err(|_| e)?;
    let buf = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| e)?;
    let sr = Scalar::from_bytes(&buf);
    if sr.is_some().unwrap_u8() == 1 {
        Ok(sr.unwrap())
    } else {
        Err(Error::DeserializationError)
    }
}

pub fn g1_from_hex_str(g1: &str, e: Error) -> CredxResult<G1Projective> {
    let bytes = hex::decode(g1).map_err(|_| e)?;

    let buf = <[u8; 48]>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidClaimData)?;
    let pt = G1Affine::from_compressed(&buf).map(G1Projective::from);
    if pt.is_some().unwrap_u8() == 1 {
        Ok(pt.unwrap())
    } else {
        Err(Error::DeserializationError)
    }
}
