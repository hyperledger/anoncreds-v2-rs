use crate::claim::{Claim, ClaimType};
use crate::knox::Knox;
use blsful::bls12_381_plus::Scalar;
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Serialize};
use sha3;

/// A claim where there there is a list of values
/// but can't use simple number like 0, 1, 2
#[derive(Clone, Debug, Eq, Deserialize, Serialize)]
pub struct EnumerationClaim {
    /// The domain separation tag for this enumeration
    pub dst: String,
    /// The index value to be hashed
    pub value: u8,
    /// The size of the enumeration
    pub total_values: usize,
}

impl PartialEq for EnumerationClaim {
    fn eq(&self, other: &Self) -> bool {
        self.dst == other.dst
            && self.value == other.value
            && self.total_values == other.total_values
    }
}

impl Hash for EnumerationClaim {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dst.hash(state);
        self.value.hash(state);
        self.total_values.hash(state);
    }
}

impl Display for EnumerationClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "EnumerationClaim {{ {} }}", self.value)
    }
}

impl Claim for EnumerationClaim {
    type Value = u8;

    fn get_type(&self) -> ClaimType {
        ClaimType::Enumeration
    }

    fn to_scalar(&self) -> Scalar {
        let mut data = self.dst.as_bytes().to_vec();
        data.push(self.dst.len() as u8);
        data.extend_from_slice((self.total_values as u16).to_le_bytes().as_ref());
        data.push(self.value);
        let mut buffer = [0u8; 64];
        Knox::xof_digest::<sha3::Shake256>(data.as_slice(), &mut buffer);
        Scalar::from_bytes_wide(&buffer)
    }

    fn get_value(&self) -> Self::Value {
        self.value
    }
}

#[test]
fn serialize() {
    let e = EnumerationClaim {
        dst: String::from("phone_number_type"),
        total_values: 3,
        value: 0,
    };
    let res = serde_bare::to_vec(&e);
    assert!(res.is_ok());
    let bytes = res.unwrap();
    let res = serde_bare::from_slice::<EnumerationClaim>(bytes.as_slice());
    assert!(res.is_ok());
    let ee = res.unwrap();

    assert_eq!(e, ee);
}
