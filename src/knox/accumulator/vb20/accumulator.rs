use super::{error::Error, generate_fr, hash_to_g1, key::SecretKey, SALT};
use blsful::inner_types::*;
use core::convert::TryFrom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// An element in the accumulator
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Element(pub Scalar);

impl core::fmt::Display for Element {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Element {{ {} }}", self.0)
    }
}

impl From<Element> for Scalar {
    fn from(e: Element) -> Self {
        e.0
    }
}

impl From<Scalar> for Element {
    fn from(s: Scalar) -> Self {
        Self(s)
    }
}

impl TryFrom<&[u8; 32]> for Element {
    type Error = Error;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        let s = Scalar::from_be_bytes(value);
        if s.is_some().unwrap_u8() == 1u8 {
            Ok(Self(s.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

impl Element {
    const BYTES: usize = 32;

    /// Return the multiplicative identity element
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    /// Return the byte representation
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }

    /// Construct an element by hashing the specified bytes
    pub fn hash(d: &[u8]) -> Self {
        Self(generate_fr(SALT, Some(d), rand_core::OsRng))
    }

    /// Compute an element from a Merlin Transcript
    pub fn from_transcript(label: &'static [u8], transcript: &mut merlin::Transcript) -> Self {
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(label, &mut okm);
        Self::hash(&okm)
    }

    /// Construct a random element
    pub fn random() -> Self {
        Self(generate_fr(SALT, None, rand_core::OsRng))
    }
}

/// A coefficent for updating witnesses
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coefficient(pub G1Projective);

impl core::fmt::Display for Coefficient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Coefficient {{ {} }}", self.0)
    }
}

impl From<Coefficient> for G1Projective {
    fn from(c: Coefficient) -> Self {
        c.0
    }
}

impl From<G1Projective> for Coefficient {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Coefficient {
    type Error = Error;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        let pt = G1Affine::from_compressed(value).map(G1Projective::from);
        if pt.is_some().unwrap_u8() == 1 {
            Ok(Self(pt.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

impl Coefficient {
    const BYTES: usize = 48;

    /// The byte representation of this coefficient
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

/// Represents a Universal Bilinear Accumulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Accumulator(pub G1Projective);

impl core::fmt::Display for Accumulator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Accumulator {{ {} }}", self.0)
    }
}

impl From<Accumulator> for G1Projective {
    fn from(a: Accumulator) -> Self {
        a.0
    }
}

impl From<G1Projective> for Accumulator {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Accumulator {
    type Error = Error;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        let pt = G1Affine::from_compressed(value).map(G1Projective::from);
        if pt.is_some().unwrap_u8() == 1 {
            Ok(Self(pt.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self(G1Projective::GENERATOR)
    }
}

impl Accumulator {
    /// The number of bytes in an accumulator
    pub const BYTES: usize = 48;

    /// Create a new random accumulator where the set elements are not known
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        Self(hash_to_g1(buffer))
    }

    /// Initialize a new accumulator prefilled with entries
    /// Each member is assumed to be hashed
    pub fn with_elements(key: &SecretKey, m: &[Element]) -> Self {
        let y = key.batch_additions(m.as_ref());
        Self(G1Projective::GENERATOR * y.0)
    }

    /// Add many members
    pub fn add_elements(&self, key: &SecretKey, m: &[Element]) -> Self {
        let y = key.batch_additions(m.as_ref());
        Self(self.0 * y.0)
    }

    /// Add many members
    pub fn add_elements_assign(&mut self, key: &SecretKey, m: &[Element]) {
        self.0 *= key.batch_additions(m).0;
    }

    /// Add a value to the accumulator, the value will be hashed to a prime number first
    pub fn add(&self, key: &SecretKey, value: Element) -> Self {
        Self(self.0 * (key.0 + value.0))
    }

    /// Add a value an update this accumulator
    pub fn add_assign(&mut self, key: &SecretKey, value: Element) {
        self.0 *= key.0 + value.0;
    }

    /// Remove a value from the accumulator and return
    /// a new accumulator without `value`
    pub fn remove(&self, key: &SecretKey, value: Element) -> Self {
        let v = (key.0 + value.0).invert().unwrap();
        Self(self.0 * v)
    }

    /// Remove a value from the accumulator if it exists
    pub fn remove_assign(&mut self, key: &SecretKey, value: Element) {
        let v = (key.0 + value.0).invert().unwrap();
        self.0 *= v;
    }

    /// Remove multiple values and return
    /// a new accumulator
    pub fn remove_elements(&self, key: &SecretKey, deletions: &[Element]) -> Self {
        let v = key.batch_deletions(deletions);
        Self(self.0 * v.0)
    }

    /// Remove multiple values
    pub fn remove_elements_assign(&mut self, key: &SecretKey, deletions: &[Element]) {
        self.0 *= key.batch_deletions(deletions).0;
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update(
        &self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> (Self, Vec<Coefficient>) {
        let mut a = *self;
        let c = a.update_assign(key, additions, deletions);
        (a, c)
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update_assign(
        &mut self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Coefficient> {
        let mut a = key.batch_additions(additions);
        let d = key.batch_deletions(deletions);

        a.0 *= d.0;
        let coefficients = key
            .create_coefficients(additions, deletions)
            .iter()
            .map(|c| Coefficient(self.0 * c.0))
            .collect();
        self.0 *= a.0;
        coefficients
    }

    /// Convert accumulator to bytes
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    #[test]
    fn new_accmulator_100() {
        let key = SecretKey::new(None);
        let elems = (0..100)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[cfg(feature = "std")]
    #[allow(non_snake_case)]
    #[test]
    fn new_accumulator_10K() {
        let key = SecretKey::new(None);
        let elems = (0..10_000)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[cfg(feature = "std")]
    #[allow(non_snake_case)]
    #[ignore = "this takes a looooog time"]
    #[test]
    fn new_accumulator_10M() {
        let key = SecretKey::new(None);
        let elems = (0..10_000_000)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[cfg(feature = "std")]
    #[ignore]
    #[test]
    fn one_year_updates() {
        use std::time::SystemTime;

        const DAYS: usize = 90;

        let key = SecretKey::new(None);
        let pk = PublicKey::from(&key);
        let mut items: Vec<Element> = (0..10_000_000).map(|_| Element::random()).collect();
        let mut acc = Accumulator::with_elements(&key, items.as_slice());

        let y = items.last().unwrap().clone();
        let mut witness = MembershipWitness::new(y, acc, &key);
        let params = ProofParams::new(pk, None);
        let proof_message = ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(y.0));
        let committing = MembershipProofCommitting::new(proof_message, witness, params, pk);

        let mut transcript = merlin::Transcript::new(b"one_year_updates");
        committing.get_bytes_for_challenge(&mut transcript);

        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        let proof = committing.gen_proof(challenge);
        let finalized = proof.finalize(acc, params, pk, challenge);
        let mut transcript = merlin::Transcript::new(b"one_year_updates");
        finalized.get_bytes_for_challenge(&mut transcript);
        let challenge2 = Element::from_transcript(b"challenge", &mut transcript);
        assert_eq!(challenge2, challenge);

        let mut deltas = alloc::vec::Vec::with_capacity(DAYS);
        for i in 0..DAYS {
            let additions: Vec<Element> = (0..1000).map(|_| Element::random()).collect();
            let (deletions, titems) = items.split_at(600);
            let t = titems.to_vec();
            let deletions = deletions.to_vec();
            items = t;
            println!("Update for single day: {}", i + 1);
            let before = SystemTime::now();
            let coefficients = acc.update_assign(&key, additions.as_slice(), deletions.as_slice());
            let time = SystemTime::now().duration_since(before).unwrap();
            println!("Time to complete: {:?}", time);
            deltas.push((additions, deletions, coefficients));
        }

        println!("Update witness");
        let before = SystemTime::now();
        witness.multi_batch_update_assign(y, deltas.as_slice());
        let time = SystemTime::now().duration_since(before).unwrap();
        println!("Time to complete: {:?}", time);
        let mut transcript = merlin::Transcript::new(b"one_year_updates");
        let committing = MembershipProofCommitting::new(proof_message, witness, params, pk);
        committing.get_bytes_for_challenge(&mut transcript);
        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        let proof = committing.gen_proof(challenge);
        let finalized = proof.finalize(acc, params, pk, challenge);
        let mut transcript = merlin::Transcript::new(b"one_year_updates");
        finalized.get_bytes_for_challenge(&mut transcript);
        let challenge2 = Element::from_transcript(b"challenge", &mut transcript);
        assert_eq!(challenge2, challenge);
    }

    #[test]
    fn add_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        acc.add_assign(&key, Element::hash(b"value1"));
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn sub_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        assert_eq!(acc.0, G1Projective::GENERATOR);
        acc.add_assign(&key, Element::hash(b"value1"));
        assert_ne!(acc.0, G1Projective::GENERATOR);
        acc.remove_assign(&key, Element::hash(b"value1"));
        assert_eq!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn batch_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        let values = &[Element::hash(b"value1"), Element::hash(b"value2")];
        acc.update_assign(&key, values, &[]);
        assert_ne!(acc.0, G1Projective::GENERATOR);
        acc.update_assign(&key, &[], values);
        assert_eq!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn false_witness() {
        let key = SecretKey::new(None);
        let pk = PublicKey::from(&key);
        let elems = (0..100)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, &elems);
        let wit = MembershipWitness::new(elems[1], acc, &key);
        let y = elems[1];
        assert!(wit.verify(y, pk, acc));
    }
}
