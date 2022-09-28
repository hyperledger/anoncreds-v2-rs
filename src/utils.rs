use bls12_381_plus::Scalar;
use group::{Group, GroupEncoding};
use serde::{
    de::{DeserializeOwned, Error as DError, Unexpected, Visitor},
    Deserializer, Serialize, Serializer,
};
use std::fmt::{self, Formatter};
use std::marker::PhantomData;
use yeti::knox::bls12_381_plus;

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
