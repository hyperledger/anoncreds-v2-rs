use serde::{Deserialize, Deserializer, Serializer, Serialize, de::{Visitor, Error as DError}};
use std::fmt;

/// The maximum number of bytes a uint will consume
pub const MAX_UINT_BYTES: usize = 10;

/// Uint implements zig-zag encoding to represent integers as binary sequences
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Uint(pub u64);

macro_rules! impl_from {
    ($($tt:ty),+) => {
        $(
        impl From<$tt> for Uint {
            fn from(v: $tt) -> Self {
                Uint(v as u64)
            }
        }
        )+
    };
}

impl From<u64> for Uint {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl_from!(u8, u16, u32, usize, i8, i16, i32, i64, isize);

impl TryFrom<&[u8]> for Uint {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut x = 0u64;
        let mut s = 0;
        let mut i = 0;
        let mut u = 0u64;

        while i < MAX_UINT_BYTES {
            if i > value.len() {
                return Err(String::from("invalid byte sequence"));
            }

            if value[i] < 0x80 {
                u = x | (value[i] as u64) << s;
                return Ok(Self(u));
            }
            x |= ((value[i]&0x7f) as u64) << s;
            s += 7;
            i += 1;
        }
        Err(String::from("invalid byte sequence"))
    }
}

impl Serialize for Uint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.bytes();
        serializer.serialize_bytes(bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for Uint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UintVisitor;

        impl<'de> Visitor<'de> for UintVisitor {
            type Value = Uint;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a byte sequence")
            }

            fn visit_bytes<E: DError>(self, v: &[u8]) -> Result<Self::Value, E> {
                match Uint::try_from(v) {
                    Err(_) => Err(DError::invalid_length(v.len(), &self)),
                    Ok(u) => Ok(u)
                }
            }
        }

        deserializer.deserialize_bytes(UintVisitor)
    }
}

impl Uint {
    /// Peek returns the number of bytes that would be read
    /// or None if no an Uint cannot be read
    pub fn peek(value: &[u8]) -> Option<usize> {
        let mut i = 0;

        while i < MAX_UINT_BYTES {
            if i > value.len() {
                return None;
            }
            if value[i] < 0x80 {
                return Some(i + 1)
            }

            i += 1;
        }
        return None;
    }

    /// Zig-zag encoding, any length from 1 to 9
    pub fn bytes(&self) -> Vec<u8> {
        let mut output = [0u8; MAX_UINT_BYTES];
        let mut i = 0;

        let mut x = self.0;

        while x >= 0x80 {
            output[i] = (x as u8) | 0x80;
            x >>= 7;
            i += 1;
        }

        output[i] = x as u8;
        i += 1;
        output[..i].to_vec()
    }
}