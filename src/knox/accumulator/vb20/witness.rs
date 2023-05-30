use super::{
    accumulator::{Accumulator, Coefficient, Element},
    dad,
    error::Error,
    key::{PublicKey, SecretKey},
    PolynomialG1,
};
use blsful::inner_types::*;
use core::{convert::TryFrom, fmt};
use serde::{Deserialize, Serialize};

/// A membership witness that can be used for membership proof generation
/// as described in section 4 in
/// <https://eprint.iacr.org/2020/777>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipWitness(pub G1Projective);

impl fmt::Display for MembershipWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MembershipWitness {{ {} }}", self.0)
    }
}

impl From<MembershipWitness> for G1Projective {
    fn from(m: MembershipWitness) -> Self {
        m.0
    }
}

impl From<G1Projective> for MembershipWitness {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for MembershipWitness {
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

impl MembershipWitness {
    const BYTES: usize = 48;

    /// Compute the witness using a prehashed element
    pub fn new(element: Element, accumulator: Accumulator, secret_key: &SecretKey) -> Self {
        Self(accumulator.remove(secret_key, element).0)
    }

    /// Verify this is a valid witness as per section 4 in
    /// <https://eprint.iacr.org/2020/777>
    pub fn verify(&self, y: Element, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        let mut p = G2Projective::GENERATOR;
        p *= y.0;
        p += pubkey.0;

        let g2 = G2Projective::GENERATOR;

        // e(C, yP~ + Q~) == e(V, P)
        multi_miller_loop(&[
            (&self.0.to_affine(), &G2Prepared::from(p.to_affine())),
            (
                &accumulator.0.to_affine(),
                &G2Prepared::from(-g2.to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1
    }

    /// Apply the specified delta to this witness and return an updated witness
    pub fn apply_delta(&self, delta: Delta) -> Self {
        let mut t = *self;
        t.apply_delta_assign(delta);
        t
    }

    /// Apply the specified delta to this witness
    pub fn apply_delta_assign(&mut self, delta: Delta) {
        // C * dA(x) / dD(x)
        self.0 *= delta.d;
        // C + 1 / dD *〈Υy,Ω〉
        self.0 += delta.p;
    }

    /// Membership witness update as defined in section 2, return a new witness
    pub fn update(
        &self,
        y: Element,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) -> Self {
        let mut clone = *self;
        clone.update_assign(y, old_accumulator, new_accumulator, additions, deletions);
        clone
    }

    /// Perform in place the membership witness update as defined in section 2
    pub fn update_assign(
        &mut self,
        y: Element,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) {
        // C' = 1/(y' - y) (C - V')
        for d in deletions {
            let mut diff = d.0;
            diff -= y.0;
            // If this fails, then this value was removed
            let t = diff.invert();
            if t.is_none().unwrap_u8() == 1 {
                return;
            }
            diff = t.unwrap();
            self.0 -= new_accumulator.0;
            self.0 *= diff;
        }
        // C' = (y' - y)C + V
        for a in additions {
            let mut diff = a.0;
            diff -= y.0;
            self.0 *= diff;
            self.0 += old_accumulator.0;
        }
    }

    /// Batch update
    pub fn batch_update(
        &self,
        y: Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) -> Self {
        let mut cn = *self;
        cn.batch_update_assign(y, additions, deletions, coefficients);
        cn
    }

    /// Batch update this witness
    pub fn batch_update_assign(
        &mut self,
        y: Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) {
        if let Ok(delta) = evaluate_delta(y, additions, deletions, coefficients) {
            self.apply_delta_assign(delta);
        }
    }

    /// Multiple batch update
    pub fn multi_batch_update<A, D, C>(&mut self, y: Element, deltas: &[(A, D, C)]) -> Self
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        let mut cn = *self;
        cn.multi_batch_update_assign(y, deltas);
        cn
    }

    /// Multiple batch update and assign to this witness
    pub fn multi_batch_update_assign<A, D, C>(&mut self, y: Element, deltas: &[(A, D, C)])
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        if let Ok(delta) = evaluate_deltas(y, deltas) {
            self.apply_delta_assign(delta);
        }
    }

    /// Return the byte sequence for this witness
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        res.copy_from_slice(self.0.to_bytes().as_ref());
        res
    }
}

/// A non-membership witness that can be used for non-membership proof generation
/// as described in section 4 in
/// <https://eprint.iacr.org/2020/777>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NonMembershipWitness {
    /// The membership witness
    pub c: G1Projective,
    /// the nonmembership scalar component
    pub d: Scalar,
}

impl From<(G1Projective, Scalar)> for NonMembershipWitness {
    fn from(p: (G1Projective, Scalar)) -> Self {
        Self { c: p.0, d: p.1 }
    }
}

impl From<NonMembershipWitness> for (G1Projective, Scalar) {
    fn from(n: NonMembershipWitness) -> Self {
        (n.c, n.d)
    }
}

impl fmt::Display for NonMembershipWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NonMembershipWitness {{ c: {}, d: {} }}", self.c, self.d)
    }
}

impl NonMembershipWitness {
    const BYTES: usize = 80;

    /// Compute the witness using a prehashed element
    pub fn new(value: Element, elements: &[Element], secret_key: &SecretKey) -> Option<Self> {
        if elements.contains(&value) {
            return None;
        }
        // f_V(x) = \prod_{y U Y_v U Y_v0}{y_i + x)
        // d = f_V(-y)
        let (mut fv_alpha, d) = elements
            .iter()
            .map(|e| (e.0 + secret_key.0, e.0 - value.0))
            .fold((Scalar::ONE, Scalar::ONE), |mut a, y| {
                a.0 *= y.0;
                a.1 *= y.1;
                a
            });
        let mut denom = value.0;
        denom += secret_key.0;
        fv_alpha -= d;
        fv_alpha *= denom.invert().unwrap();
        let mut c = G1Projective::GENERATOR;
        c *= fv_alpha;

        Some(Self { c, d })
    }

    /// Verify this is a valid witness as per section 4 in
    /// <https://eprint.iacr.org/2020/777>
    pub fn verify(&self, y: Element, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        let mut p = G2Projective::GENERATOR;
        p *= y.0;
        p += pubkey.0;

        let mut pd = G1Projective::GENERATOR;
        pd *= self.d;

        let g2 = -G2Projective::GENERATOR;

        // e(C, yP~ + Q~)e(P, P~)^d == e(V, P)
        multi_miller_loop(&[
            (&self.c.to_affine(), &G2Prepared::from(p.to_affine())),
            (
                &pd.to_affine(),
                &G2Prepared::from(G2Projective::GENERATOR.to_affine()),
            ),
            (
                &accumulator.0.to_affine(),
                &G2Prepared::from(g2.to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1
    }

    /// Update the witness according to the delta
    pub fn apply_delta(&self, delta: Delta) -> Self {
        let mut t = *self;
        t.apply_delta_assign(delta);
        t
    }

    /// Update the witness according to the delta
    pub fn apply_delta_assign(&mut self, delta: Delta) {
        // C * dA(x) / dD(x)
        self.c *= delta.d;
        // d * dA(x) / dD(x)
        self.d *= delta.d;
        // C + 1 / dD *〈Υy,Ω〉
        self.c += delta.p;
    }

    /// Non-membership witness update as defined in section 4, return a new witness
    pub fn update(
        &self,
        y: Element,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) -> Self {
        let mut clone = *self;
        clone.update_assign(y, old_accumulator, new_accumulator, additions, deletions);
        clone
    }

    /// Perform in place the non-membership witness update as defined in section 4
    pub fn update_assign(
        &mut self,
        y: Element,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) {
        // C' = 1/(y' - y) (C - V')
        // d' = d * 1 / (y' - y)
        for d in deletions {
            let mut diff = d.0;
            diff -= y.0;

            // If this fails, then this value was removed
            let t = diff.invert();
            if t.is_none().unwrap_u8() == 1 {
                return;
            }
            diff = t.unwrap();
            self.c -= new_accumulator.0;
            self.c *= diff;
            self.d *= diff;
        }
        // C' = (y' - y)C + V
        // d' = d (y' - y)
        for a in additions {
            let mut diff = a.0;
            diff -= y.0;
            self.c *= diff;
            self.c += old_accumulator.0;
            self.d *= diff;
        }
    }

    /// Batch update
    pub fn batch_update(
        &self,
        y: Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) -> Self {
        let mut cn = *self;
        cn.batch_update_assign(y, additions, deletions, coefficients);
        cn
    }

    /// Batch update and assign to this witness
    pub fn batch_update_assign(
        &mut self,
        y: Element,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) {
        if let Ok(delta) = evaluate_delta(y, additions, deletions, coefficients) {
            self.apply_delta_assign(delta);
        }
    }

    /// Multiple batch update
    pub fn multi_batch_update<A, D, C>(&mut self, y: Element, deltas: &[(A, D, C)]) -> Self
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        let mut cn = *self;
        cn.multi_batch_update_assign(y, deltas);
        cn
    }

    /// Multiple batch update and assign to this witness
    pub fn multi_batch_update_assign<A, D, C>(&mut self, y: Element, deltas: &[(A, D, C)])
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        if let Ok(delta) = evaluate_deltas(y, deltas) {
            self.apply_delta_assign(delta);
        }
    }

    /// Return the byte representation for this witness
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        res[..48].copy_from_slice(self.c.to_bytes().as_ref());
        res[48..].copy_from_slice(&self.d.to_be_bytes());
        res
    }
}

/// A compressed delta after evaluating the polynomials w.r.t an element
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Delta {
    d: Scalar,
    p: G1Projective,
}

/// Compress the deltas for the specified element and return the single delta
pub fn evaluate_deltas<A, D, C>(y: Element, deltas: &[(A, D, C)]) -> Result<Delta, Error>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    let one = Scalar::ONE;

    // dA(x) =  ∏ 1..n (yA_i - x)
    let mut aa = Vec::new();
    // dD(x) = ∏ 1..m (yD_i - x)
    let mut dd = Vec::new();

    let mut acc_a = one;
    let mut acc_d = one;

    // dA = ∏ a..b dA
    // dD = ∏ a..b dD
    for (adds, dels, _) in deltas {
        let ta = dad(adds.as_ref(), y.0);
        let td = dad(dels.as_ref(), y.0);

        acc_a *= ta;
        acc_d *= td;

        aa.push(ta);
        dd.push(td);
    }

    let tv = acc_d.invert();
    // If this fails, then this value was removed
    if tv.is_none().unwrap_u8() == 1 {
        return Err(Error::from_msg(1, "no inverse exists"));
    }
    acc_d = tv.unwrap();

    //〈Υy,Ω〉
    let mut poly = PolynomialG1::with_capacity(deltas.len());

    // Ωi->j+1 = ∑ 1..t (dAt * dDt-1) · Ω
    for i in 0..deltas.len() {
        // t = i+1
        // ∏^(t-1)_(h=i+1)
        let mut ddh = one;
        for h in dd.iter().take(i) {
            ddh *= h;
        }

        let mut dak = one;
        // ∏^(j+1)_(k=t+1)
        for k in aa.iter().take(deltas.len()).skip(i + 1) {
            dak *= k;
        }

        dak *= ddh;
        let mut pp = PolynomialG1(deltas[i].2.as_ref().iter().map(|c| c.0).collect());
        pp *= dak;
        poly += pp;
    }

    acc_a *= acc_d;

    if let Some(mut v) = poly.evaluate(y.0) {
        // 1 / dD *〈Υy,Ω〉
        v *= acc_d;
        Ok(Delta { d: acc_a, p: v })
    } else {
        Err(Error::from_msg(2, "polynomial could not be evaluated"))
    }
}

/// Computes the compressed delta needed to update a witness
pub fn evaluate_delta<A, D, C>(
    y: Element,
    additions: A,
    deletions: D,
    coefficients: C,
) -> Result<Delta, Error>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    // dD(x) = ∏ 1..m (yD_i - x)
    let mut d_d = dad(deletions.as_ref(), y.0);

    let t = d_d.invert();
    // If this fails, then this value was removed
    if t.is_none().unwrap_u8() == 1 {
        return Err(Error::from_msg(1, "no inverse exists"));
    }
    d_d = t.unwrap();

    //dA(x) =  ∏ 1..n (yA_i - x)
    let mut d_a = dad(additions.as_ref(), y.0);
    d_a *= d_d;

    let poly = PolynomialG1(
        coefficients
            .as_ref()
            .iter()
            .map(|c| c.0)
            .collect::<Vec<G1Projective>>(),
    );
    //〈Υy,Ω〉
    if let Some(mut v) = poly.evaluate(y.0) {
        // C + 1 / dD *〈Υy,Ω〉
        v *= d_d;
        Ok(Delta { d: d_a, p: v })
    } else {
        Err(Error::from_msg(2, "polynomial could not be evaluated"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn update_test() {
        let key = SecretKey::new(Some(b"1234567890"));
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
        ];
        let y = elements[4];
        let acc = Accumulator::with_elements(&key, &elements[1..]);
        let wit = MembershipWitness::new(elements[3], acc, &key);

        let new_acc = acc.add(&key, elements[0]);
        let wit_t1 = wit.update(y, acc, new_acc, &elements[0..1], &[]);
        let wit_t2 = MembershipWitness::new(elements[4], new_acc, &key);
        assert_eq!(wit_t1.0, wit_t2.0);

        let new_acc = acc.remove(&key, elements[1]);
        let wit_t1 = wit.update(y, acc, new_acc, &[], &elements[1..2]);
        let wit_t2 = MembershipWitness::new(elements[3], new_acc, &key);
        assert_eq!(wit_t1.0, wit_t2.0);
    }

    #[test]
    fn membership_batch_update() {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
        ];
        let y = elements[3];
        let mut acc = Accumulator::with_elements(&key, &elements);
        let mut wit = MembershipWitness::new(elements[3], acc, &key);
        assert!(wit.verify(y, pubkey, acc));

        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let additions = &data[0..2];
        let deletions = &data[2..5];
        let coefficients = acc.update_assign(&key, additions, deletions);

        wit.batch_update_assign(y, additions, deletions, coefficients.as_slice());
        assert!(wit.verify(y, pubkey, acc));
    }

    #[test]
    fn membership_multi_batch_update() {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
            Element::hash(b"10"),
            Element::hash(b"11"),
            Element::hash(b"12"),
            Element::hash(b"13"),
            Element::hash(b"14"),
            Element::hash(b"15"),
            Element::hash(b"16"),
            Element::hash(b"17"),
            Element::hash(b"18"),
            Element::hash(b"19"),
            Element::hash(b"20"),
        ];

        let y = elements[3];
        let mut acc = Accumulator::with_elements(&key, &elements);
        let mut wit = MembershipWitness::new(elements[3], acc, &key);

        assert!(wit.verify(y, pubkey, acc));

        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let adds1 = &data[0..2];
        let dels1 = &data[2..5];
        let coeffs1 = acc.update_assign(&key, adds1, dels1);

        let dels2 = &elements[8..10];
        let coeffs2 = acc.update_assign(&key, &[], dels2);

        let dels3 = &elements[11..14];
        let coeffs3 = acc.update_assign(&key, &[], dels3);

        wit.multi_batch_update_assign(
            y,
            &[
                (adds1, dels1, coeffs1.as_slice()),
                (&[], dels2, coeffs2.as_slice()),
                (&[], dels3, coeffs3.as_slice()),
            ],
        );
        assert!(wit.verify(y, pubkey, acc));
    }
}
