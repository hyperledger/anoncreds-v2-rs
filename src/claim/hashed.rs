use super::{Claim, ClaimType};
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::Shake256;
use signature_bls::bls12_381_plus::Scalar;
use crate::knox::Knox;

/// Claims that are hashed to a scalar
#[derive(Clone, Debug, Eq)]
pub struct HashedClaim {
    /// The value to be hashed
    pub value: Vec<u8>,
    /// Whether the claim can be printed
    pub print_friendly: bool,
}

#[derive(Deserialize, Serialize)]
struct HashedClaimSerdesFriendly {
    pub value: String,
    pub print_friendly: bool,
}

#[derive(Deserialize, Serialize)]
struct HashedClaimSerdes {
    pub value: Vec<u8>,
    pub print_friendly: bool,
}

impl Serialize for HashedClaim {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let ss = if self.print_friendly {
                String::from_utf8(self.value.clone()).unwrap()
            } else {
                hex::encode(&self.value)
            };
            HashedClaimSerdesFriendly {
                value: ss,
                print_friendly: self.print_friendly,
            }
            .serialize(s)
        } else {
            HashedClaimSerdes {
                value: self.value.clone(),
                print_friendly: self.print_friendly,
            }
            .serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for HashedClaim {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let hc = HashedClaimSerdesFriendly::deserialize(d)?;
            let value = if hc.print_friendly {
                hc.value.as_bytes().to_vec()
            } else {
                hex::decode(hc.value).map_err(|e| serde::de::Error::custom(e.to_string()))?
            };
            Ok(HashedClaim {
                value,
                print_friendly: hc.print_friendly,
            })
        } else {
            let hc = HashedClaimSerdes::deserialize(d)?;
            Ok(HashedClaim {
                value: hc.value,
                print_friendly: hc.print_friendly,
            })
        }
    }
}

impl PartialEq for HashedClaim {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.print_friendly == other.print_friendly
    }
}

impl Hash for HashedClaim {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
        self.print_friendly.hash(state);
    }
}

impl Display for HashedClaim {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.print_friendly {
            write!(f, "HashedClaim {{ ")?;
            write!(f, "{}", String::from_utf8(self.value.clone()).unwrap())?;
            write!(f, "}}")
        } else {
            write!(f, "HashedClaim {{ [")?;
            let mut sep = "";
            for b in &self.value {
                write!(f, "{}{}", sep, b)?;
                sep = ", ";
            }
            write!(f, "] }}")
        }
    }
}

impl<'a> From<&'a [u8]> for HashedClaim {
    fn from(value: &'a [u8]) -> Self {
        Self {
            value: value.to_vec(),
            print_friendly: false,
        }
    }
}

impl From<&Vec<u8>> for HashedClaim {
    fn from(v: &Vec<u8>) -> Self {
        Self {
            value: v.clone(),
            print_friendly: false,
        }
    }
}

impl From<Vec<u8>> for HashedClaim {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value,
            print_friendly: false,
        }
    }
}

impl From<&str> for HashedClaim {
    fn from(v: &str) -> Self {
        Self {
            value: v.to_string().into_bytes(),
            print_friendly: true,
        }
    }
}

impl From<&String> for HashedClaim {
    fn from(v: &String) -> Self {
        Self {
            value: v.to_string().into_bytes(),
            print_friendly: true,
        }
    }
}

impl From<String> for HashedClaim {
    fn from(v: String) -> Self {
        Self {
            value: v.into_bytes(),
            print_friendly: true,
        }
    }
}

impl AsRef<[u8]> for HashedClaim {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl Claim for HashedClaim {
    type Value = Vec<u8>;

    fn get_type(&self) -> ClaimType {
        ClaimType::Hashed
    }

    fn to_scalar(&self) -> Scalar {
        let mut buffer = [0u8; 64];
        Knox::xof_digest::<Shake256>(&self.value, &mut buffer);
        Scalar::from_bytes_wide(&buffer)
    }

    fn get_value(&self) -> Self::Value {
        self.value.clone()
    }
}
