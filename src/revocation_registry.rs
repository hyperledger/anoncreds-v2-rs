use crate::error::Error;
use crate::{random_string, CredxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use yeti::knox::accumulator::vb20;

/// A revocation registry for credentials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRegistry {
    /// The registry value
    pub value: vb20::Accumulator,
    /// The elements in the revocation registry
    pub elements: HashSet<String>,
}

impl RevocationRegistry {
    /// Create a new revocation registry with an initial set of elements to `count`
    pub fn new(sk: &vb20::SecretKey, count: NonZeroUsize) -> Self {
        let ids: Vec<String> = (0..count.get())
            .map(|_| random_string(16, rand::thread_rng()))
            .collect();
        let elems: Vec<vb20::Element> = ids
            .iter()
            .map(|i| vb20::Element::hash(i.as_bytes()))
            .collect();
        let value = vb20::Accumulator::with_elements(sk, elems.as_slice());
        Self {
            elements: HashSet::from_iter(ids.into_iter()),
            value,
        }
    }

    /// Remove the specified elements from the registry
    pub fn revoke(&mut self, sk: &vb20::SecretKey, elements: &[String]) -> CredxResult<()> {
        let mut updated_elements = self.elements.clone();
        let mut removals = Vec::new();
        for e in elements {
            if !updated_elements.remove(e) {
                return Err(Error::InvalidRevocationRegistryRevokeOperation);
            }
            removals.push(vb20::Element::hash(e.as_bytes()));
        }

        self.elements = updated_elements;
        self.value.remove_elements_assign(sk, removals.as_slice());

        Ok(())
    }

    /// Add and return more elements to the registry
    pub fn add(&mut self, sk: &vb20::SecretKey, count: NonZeroUsize) -> Vec<String> {
        let new_ids: Vec<String> = (0..count.get())
            .map(|_| random_string(16, rand::thread_rng()))
            .collect();
        let elems: Vec<vb20::Element> = new_ids
            .iter()
            .map(|i| vb20::Element::hash(i.as_bytes()))
            .collect();
        self.value.add_elements_assign(sk, elems.as_slice());
        new_ids
    }
}
