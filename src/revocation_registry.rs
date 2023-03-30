use crate::error::Error;
use crate::knox::accumulator::vb20::{Accumulator, Element, SecretKey};
use crate::{utils::*, CredxResult};
use indexmap::IndexSet;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A revocation registry for credentials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    /// The registry value
    pub value: Accumulator,
    /// All the elements ever included in the revocation registry
    /// Includes the index to help with ordering
    #[serde(
        serialize_with = "serialize_indexset",
        deserialize_with = "deserialize_indexset"
    )]
    pub elements: IndexSet<String>,
    /// The current active set
    #[serde(
        serialize_with = "serialize_indexset",
        deserialize_with = "deserialize_indexset"
    )]
    pub active: IndexSet<String>,
}

impl RevocationRegistry {
    /// Create a new revocation registry with an initial set of elements to `count`
    pub fn new(rng: impl RngCore + CryptoRng) -> Self {
        let value = Accumulator::random(rng);
        Self {
            active: IndexSet::new(),
            elements: IndexSet::new(),
            value,
        }
    }

    /// Remove the specified elements from the registry
    pub fn revoke(&mut self, sk: &SecretKey, elements: &[String]) -> CredxResult<()> {
        let mut removals = Vec::new();
        for e in elements {
            if !self.active.remove(e) {
                return Err(Error::InvalidRevocationRegistryRevokeOperation);
            }
            removals.push(Element::hash(e.as_bytes()));
        }

        self.value.remove_elements_assign(sk, removals.as_slice());

        Ok(())
    }

    /// Add the elements to the registry
    pub fn add(&mut self, elements: &[String]) {
        for e in elements {
            if self.elements.insert(e.clone()) {
                self.active.insert(e.clone());
            }
        }
    }
}
