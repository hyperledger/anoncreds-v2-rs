use crate::error::Error;
use crate::CredxResult;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use yeti::knox::accumulator::vb20::{Accumulator, Element, SecretKey};

/// A revocation registry for credentials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    /// The registry value
    pub value: Accumulator,
    /// All the elements ever included in the revocation registry
    /// Includes the index to help with ordering
    pub elements: BTreeMap<usize, String>,
    /// The current active set
    pub active: HashSet<String>,
}

impl RevocationRegistry {
    /// Create a new revocation registry with an initial set of elements to `count`
    pub fn new(rng: impl RngCore + CryptoRng) -> Self {
        let value = Accumulator::random(rng);
        Self {
            active: HashSet::new(),
            elements: BTreeMap::new(),
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
            if self.elements.insert(self.elements.len(), e.clone()).is_none() {
                self.active.insert(e.clone());
            }
        }
    }
}
