// ----------------------------------------------------------------------------
use crate::check_errors_in;
use crate::vcp::*;
use crate::vcp::r#impl::*;
use crate::vcp::types::DataValue;
use crate::vcp::{Error, VCPResult};
// ----------------------------------------------------------------------------
use lazy_static::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap,BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Extract text from DataValue expected to be DVText

pub fn get_text_from_value(dv: &DataValue) -> VCPResult<String> {
    match dv {
        DataValue::DVInt(_) => Err(Error::General(format!(
            "get_text_from_value; unexpected type; {dv:?}"
        ))),
        DataValue::DVText(t) => Ok(t.clone()),
    }
}

// ----------------------------------------------------------------------------

pub fn disjoint_vec_of_vecs<T: Eq + Clone>(xss: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let mut yss: Vec<Vec<T>> = vec![];
    xss.into_iter().for_each(|xs| {
        let mut overlapping_idxs = vec![];
        for (idx, ys) in yss.iter().enumerate() {
            if xs.iter().any(|x| ys.iter().any(|y| *x == *y)) {
                overlapping_idxs.push(idx);
            }
        }
        overlapping_idxs.sort_unstable();

        if !overlapping_idxs.is_empty() {
            let first_overlapping_idx = overlapping_idxs
                .first()
                .expect("overlapping_idxs isn't empty");

            // remove the overlapping_idxs in reverse order so that removing
            // an index doesn't affect the rest of the indices to remove
            let mut rev_removed_yss = vec![];
            overlapping_idxs.iter().rev().for_each(|i| {
                rev_removed_yss.push(yss.remove(*i));
            });

            let mut new_first_overlapping_ys = vec![];
            rev_removed_yss.into_iter().rev().for_each(|ys| {
                new_first_overlapping_ys.extend(ys);
            });
            extend_nub(&mut new_first_overlapping_ys, xs);

            yss.insert(*first_overlapping_idx, new_first_overlapping_ys);
        } else {
            yss.push(xs)
        }
    });
    yss
}

/// Merge maps, requiring same keys
pub fn merge_maps<K: Clone + Eq + Hash + Debug, V1: Clone, V2: Clone>(
    m1: HashMap<K, V1>,
    m2: HashMap<K, V2>,
) -> VCPResult<HashMap<K, (V1, V2)>> {
    let make_error = || {
        let ks1: Vec<_> = m1.keys().collect();
        let ks2: Vec<_> = m2.keys().collect();
        Error::General(format!(
            "Unequal keys for maps to be merged; {ks1:?} != {ks2:?}"
        ))
    };
    let mut m: HashMap<K, (V1, V2)> = HashMap::new();
    let mut ks2: HashSet<&K> = m2.keys().collect();
    m1.iter().try_for_each(|(k, v1)| {
        let v2 = m2.get(k).ok_or_else(make_error)?;
        m.insert(k.clone(), (v1.clone(), v2.clone()));
        ks2.remove(k);
        Ok(())
    })?;
    (!ks2.is_empty()).assert_or_else(make_error);
    Ok(m)
}

#[cfg(not(feature = "verbose"))]
pub fn pp<A>(_m: &str, _v: A) {}

#[cfg(feature = "verbose")]
pub fn pp<A: std::fmt::Debug>(m: &str, v: A) {
    println!("---------- {m}");
    println!("{v:?}");
}

#[cfg(not(feature = "verbose"))]
pub fn pprintln(_m: &str, _s: &str) {}

#[cfg(feature = "verbose")]
pub fn pprintln(m: &str, s: &str) {
    println!("=============[{m}]==================================\n{s}");
}

// ----------------------------------------------------------------------------
// Miscellaneous
//
// These are Rust-specific, so they don't correspond to Haskell functions.

pub fn extend_nub<T: Eq>(ys: &mut Vec<T>, xs: Vec<T>) {
    xs.into_iter().for_each(|x| {
        if !ys.iter().any(|y| x == *y) {
            ys.push(x);
        }
    })
}

pub fn ord_nub<T>(xs: &[T]) -> BTreeSet<&T>
where
    T: Ord,
{
    let mut ys: BTreeSet<&T> = BTreeSet::new();
    xs.iter().for_each(|x| {
        ys.insert(x);
    });
    ys
}

/// An "assertable" type has a canonical "accept" form, which
/// [`Assert::assert_or_else`] checks for. The canonical case
/// of this is `bool`, which has the canonical accept form
/// `true`.
pub trait Assert {
    fn assert_or_else<R, F: FnOnce() -> R>(&self, f: F) -> Result<(), R>;

    fn assert_or<R>(&self, r: R) -> Result<(), R> {
        self.assert_or_else(move || r)
    }

    fn assert(&self) -> Option<()> {
        self.assert_or(()).ok()
    }
}

impl Assert for bool {
    fn assert_or_else<R, F: FnOnce() -> R>(&self, f: F) -> Result<(), R> {
        if *self {
            Ok(())
        } else {
            Err(f())
        }
    }
}

/// Collect an [`Iterator<Result<Ts1, E>>`] into a [`Result<Ts2, E>`], where a
/// collection of `Ts1`s be concatenated into `Ts2`. For example, can collect
/// an [`Iterator<Result<Vec<T>, E>>`] into a [`Result<Vec<T>, E>`]. This is
/// a convenient and efficient way to rewrite something like
/// ```rust,ignore
/// Ok(
///     xs
///         .iter()
///         .map(f_may_err)
///         .collect::<Result<Vec<_>, _>>()?
///         .concat()
/// )
/// ```
/// as
/// ```rust,ignore
/// xs
///     .iter()
///     .map(f_may_err)
///     .try_collect_concat()
/// ```
pub fn try_collect_concat<T, E, Ts1, Ts2, I>(i: &mut I) -> Result<Ts2, E>
where
    I: Iterator<Item = Result<Ts1, E>>,
    Ts1: IntoIterator<Item = T>,
    Ts2: Default + Extend<T>,
{
    let mut v: Ts2 = Ts2::default();
    i.try_for_each(|xs| -> Result<(), E> {
        v.extend(xs?);
        Ok(())
    })?;
    Ok(v)
}

/// This is a wrapper trait around [`try_collect_concat`] in order to enable it
/// to use postfix application syntax.
pub trait TryCollectConcat<T, E, Ts1>
where
    Self: Iterator<Item = Result<Ts1, E>> + Sized,
    Ts1: IntoIterator<Item = T>,
{
    fn try_collect_concat<Ts2>(&mut self) -> Result<Ts2, E>
    where
        Ts2: Default + Extend<T>,
    {
        try_collect_concat(self)
    }
}

/// This is the _only_ implementation -- [`TryCollectConcat`] is a wrapper
/// trait around [`try_collect_concat`].
impl<T, E, Ts1, I> TryCollectConcat<T, E, Ts1> for I
where
    I: Iterator<Item = Result<Ts1, E>> + Sized,
    Ts1: IntoIterator<Item = T>,
{
}

pub fn collect_concat<T, Ts1, Ts2, I>(i: &mut I) -> Ts2
where
    I: Iterator<Item = Ts1>,
    Ts1: IntoIterator<Item = T>,
    Ts2: Default + Extend<T>,
{
    let mut v: Ts2 = Ts2::default();
    i.for_each(|xs| v.extend(xs));
    v
}

/// This is a wrapper trait around [`collect_concat`] in order to enable it
/// to use postfix application syntax.
pub trait CollectConcat<T, Ts1>
where
    Self: Iterator<Item = Ts1> + Sized,
    Ts1: IntoIterator<Item = T>,
{
    fn collect_concat<Ts2>(&mut self) -> Ts2
    where
        Ts2: Default + Extend<T>,
    {
        collect_concat(self)
    }
}

/// This is the _only_ implementation -- [`CollectConcat`] is a wrapper
/// trait around [`collect_concat`].
impl<T, Ts1, I> CollectConcat<T, Ts1> for I
where
    I: Iterator<Item = Ts1> + Sized,
    Ts1: IntoIterator<Item = T>,
{
}

pub fn try_partition<I, A, B, As, Bs, E, F>(iter: &mut I, f: F) -> Result<(As, Bs), E>
where
    I: Iterator,
    As: Default + Extend<A>,
    Bs: Default + Extend<B>,
    F: Fn(I::Item) -> Result<PartitionItem<A, B>, E>,
{
    let mut as_ = As::default();
    let mut bs = Bs::default();
    iter.try_for_each(|x| {
        let r = f(x)?;
        match r {
            PartitionItem::Left(a) => as_.extend([a]),
            PartitionItem::Right(b) => bs.extend([b]),
        }
        Ok(())
    })?;
    Ok((as_, bs))
}

#[derive(Debug, Clone)]
pub enum PartitionItem<A, B> {
    Left(A),
    Right(B),
}

pub trait TryPartition<A, As, B, Bs, E, F>
where
    Self: Iterator + Sized,
    As: Default + Extend<A>,
    Bs: Default + Extend<B>,
    F: Fn(Self::Item) -> Result<PartitionItem<A, B>, E>,
{
    fn try_partition(&mut self, f: F) -> Result<(As, Bs), E> {
        try_partition(self, f)
    }
}

impl<A, As, B, Bs, E, F, I> TryPartition<A, As, B, Bs, E, F> for I
where
    I: Iterator + Sized,
    As: Default + Extend<A>,
    Bs: Default + Extend<B>,
    F: Fn(I::Item) -> Result<PartitionItem<A, B>, E>,
{
}

pub fn keys_vec_sorted<K: Ord, V>(m: &HashMap<K, V>) -> Vec<&K> {
    sort(m.keys().collect())
}

pub fn sort_by<T, F: FnMut(&T, &T) -> Ordering>(mut xs: Vec<T>, compare: F) -> Vec<T> {
    xs.sort_by(compare);
    xs
}

pub fn sort<T: Ord>(mut xs: Vec<T>) -> Vec<T> {
    xs.sort();
    xs
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use maplit::hashmap;

    use crate::vcp::r#impl::util::merge_maps;

    use super::disjoint_vec_of_vecs;

    fn sort_vec_of_vecs<T: Ord>(xss: &mut [Vec<T>]) {
        xss.iter_mut().for_each(|xs| xs.sort_unstable());
        xss.sort_unstable();
    }

    #[test]
    fn test_disjoint_vec_of_vecs() {
        // only care for equality up to reordering
        fn test(input: Vec<Vec<u8>>, mut expected_output: Vec<Vec<u8>>) {
            sort_vec_of_vecs(&mut expected_output);
            let mut actual_output: Vec<Vec<u8>> = disjoint_vec_of_vecs(input);
            sort_vec_of_vecs(&mut actual_output);
            assert_eq!(actual_output, expected_output);
        }

        test(vec![vec![1]], vec![vec![1]]);
        test(vec![vec![1], vec![2]], vec![vec![1], vec![2]]);
        test(vec![vec![1], vec![1, 2]], vec![vec![1, 2]]);
        test(
            vec![vec![1], vec![1, 2], vec![3], vec![3, 4]],
            vec![vec![1, 2], vec![3, 4]],
        );
        test(
            vec![vec![1], vec![1, 2], vec![3], vec![2, 3, 4]],
            vec![vec![1, 2, 3, 4]],
        );
        test(
            vec![
                vec![10],
                vec![1, 2],
                vec![11],
                vec![2, 3],
                vec![12],
                vec![3, 4],
                vec![13],
            ],
            vec![vec![10], vec![1, 2, 3, 4], vec![11], vec![12], vec![13]],
        );
        // This is a modified version of the test that used to fail in
        // DockNetwork crypto: https://github.com/docknetwork/crypto/issues/18
        // The irrelevant tuples in that test have been "collapsed" to integers,
        // with leading zeroes removed to avoid warnings.
        test(
            vec![
                vec![1, 20],
                vec![5, 12],
                vec![5, 30],
                vec![13, 50],
                vec![12, 40],
            ],
            vec![vec![1, 20], vec![5, 12, 30, 40], vec![13, 50]],
        );
    }

    #[test]
    fn test_merge_maps() {
        fn test(
            input1: HashMap<u8, u8>,
            input2: HashMap<u8, u8>,
            expected_output: Option<HashMap<u8, (u8, u8)>>,
        ) {
            let actual_output = merge_maps(input1, input2).ok();
            assert_eq!(actual_output, expected_output);
        }

        // ok
        test(hashmap! {}, hashmap! {}, Some(hashmap! {}));
        test(
            hashmap! {1 => 1, 2 => 2, 3 => 3, 4 => 4},
            hashmap! {1 => 10, 2 => 20, 3 => 30, 4 => 40},
            Some(hashmap! {
                1 => (1, 10),
                2 => (2, 20),
                3 => (3, 30),
                4 => (4, 40),
            }),
        );
        test(
            hashmap! {1 => 1, 2 => 2},
            hashmap! {1 => 20, 2 => 10},
            Some(hashmap! {1 => (1, 20), 2 => (2, 10)}),
        );
        test(hashmap! {}, hashmap! {}, Some(hashmap! {}));

        // err
        test(hashmap! {1 => 1}, hashmap! {}, None);
        test(hashmap! {1 => 1}, hashmap! {2 => 2}, None);
        test(hashmap! {1 => 1, 2 => 2}, hashmap! {1 => 10, 3 => 30}, None);
    }
}

// Match on a comma-separated list of expressions
// that evaluate to types that implement trait Display, and
// produce a Vec<String> containing them
// Example in test below
#[macro_export]
macro_rules! str_vec_from {
    ( $( $fmt:expr ),* $(,)? ) => {
        {
            let mut vec = Vec::new();
            $(
                vec.push(format!("{}", $fmt));
            )*
            vec
        }
    };
}

#[cfg(test)]
mod str_vec_from_examples {
    #[test]
    fn test_str_vec_from() {
        let s: Vec<String> = str_vec_from!(2*3,"abc".to_string() + "def");
        assert_eq!(s,vec!("6","abcdef"));
    }
}

// Equivalent of Haskell's intercalate.  Takes a separator string and
// a list of T, and produces a String by inserting the separator between
// adjacent pairs of Strings converted from T
fn intercalate<T: ToString>(separator: &str, items: &[T]) -> String {
    items
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
        .join(separator)
}

pub fn ic_semi(s: &[String]) -> String {
    intercalate("; ",s)
}

pub fn make_adjective_error<E>(
    err_str: String,
    mk_e: fn(String) -> E,
    s: &[String])
    -> E {
    let mut result = Vec::with_capacity(1 + s.len() + 1);
    result.extend_from_slice(s);
    result.push(err_str);
    mk_e(ic_semi(&result))
}

pub fn make_absent_error<K: Eq+Debug+Hash, E>(
    k: &K,
    l: usize,
    mk_e: fn(String) -> E,
    s: &[String])
    -> E {
    make_adjective_error(format!("key {:?} not found among {} key(s)", k, l),mk_e,s)
}

pub fn make_present_error<K: Debug, V: Debug, E: Debug>(
    k: &K,
    v: &V,
    mk_e: fn(String) -> E,
    s: &[String])
    -> E {
    make_adjective_error(format!("key {:?} already present with value {:?}", k, v),mk_e,s)
}

pub fn make_out_of_bounds_error<E>(
    i: usize,
    l: usize,
    mk_e: fn(String) -> E,
    s: &[String])
    -> E {
    make_adjective_error(format!("index {:?} out of range for Vec of length {:?}", i, l),mk_e,s)
}

pub trait KeyValueContainer<'a, K, V> {
    fn get(&'a self, key: &'a K) -> Option<&'a V>;
    fn get_mut(&'a mut self, key: &'a K) -> Option<&'a mut V>;
    fn insert(&'a mut self, key: K, val: V) -> Option<V>;
    fn len (& self) -> usize;
    fn is_empty (& self) -> bool;
}

impl<'a, K, V> KeyValueContainer<'a, K, V> for HashMap<K, V>
where
    K: std::hash::Hash + Eq,
{
    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key)
    }
    fn insert(& mut self, key: K, val: V) -> Option< V> {
        self.insert(key,val)
    }
    fn len(&self)-> usize {
        self.len()
    }
    fn is_empty(&self)-> bool {
        self.is_empty()
    }
}

impl<'a, K, V> KeyValueContainer<'a, K, V> for BTreeMap<K, V>
where
    K: std::hash::Hash + Eq + std::cmp::Ord,
{
    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key)
    }
    fn insert(& mut self, key: K, val: V) -> Option< V> {
        self.insert(key,val)
    }
    fn len(&self)-> usize {
        self.len()
    }
    fn is_empty(&self)-> bool {
        self.is_empty()
    }
}

// The first "verb, throw if adjective" function.  This one looks up
// a key in a hash map and produces an error containing the input
// strings in s and additional information about the lookup failure.
pub fn lookup_throw_if_absent<'a, K: Eq+Debug+Hash,V, M: KeyValueContainer<'a, K,V>, E>(
    k: &'a K,
    m: &'a M,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<&'a V,E> {
    m.get(k).ok_or_else(|| make_absent_error(k,m.len(),mk_e,s))
}

pub fn lookup_throw_if_absent_mut<'a, K: Eq+Debug+Hash,V, M: KeyValueContainer<'a, K,V>, E>(
    k: &'a K,
    m: &'a mut M,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<&'a mut V,E> {
    let l = m.len();
    m.get_mut(k).ok_or_else(|| make_absent_error(k,l,mk_e,s))
}

pub fn lookup_throw_if_absent_2_lvl<'a,
                                    K1: Eq+Debug+Hash,
                                    K2: Eq+Debug+Hash, V,
                                    M2: KeyValueContainer<'a, K2, V> + 'a,
                                    M1: KeyValueContainer<'a, K1, M2>, E> (
    k1: &'a K1,
    k2: &'a K2,
    m: &'a M1,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<&'a V,E> {
    let m2 = m.get(k1).ok_or_else(|| make_absent_error(k1,m.len(),mk_e,s))?;
    lookup_throw_if_absent(k2,m2,mk_e,s)
}

pub fn lookup_throw_if_absent_2_lvl_mut<'a,
                                    K1: Eq+Debug+Hash,
                                    K2: Eq+Debug+Hash, V,
                                    M2: KeyValueContainer<'a, K2, V> + 'a,
                                    M1: KeyValueContainer<'a, K1, M2>, E> (
    k1: &'a K1,
    k2: &'a K2,
    m: &'a mut M1,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<&'a mut V,E> {
    let l = m.len();
    let m2 = m.get_mut(k1).ok_or_else(|| make_absent_error(k1,l,mk_e,s))?;
    lookup_throw_if_absent_mut(k2,m2,mk_e,s)
}

pub fn lookup_throw_if_out_of_bounds<'a, V, E>(
    l: &'a [V],
    i: usize,
    mk_e: fn(String) -> E,
    s: &[String]) -> Result<&'a V,E> {
    match l.get(i) {
        Some(v) => Ok(v),
        None => Err(make_out_of_bounds_error(i,l.len(),mk_e,s))
    }
}

pub fn insert_throw_if_present<'a, K: Eq+Debug+Hash+Clone, V: Clone+Debug+'a, M: KeyValueContainer<'a, K,V>, E: Debug>(
    k: K,
    v: V,
    m: &'a mut M,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<(),E> {
    match m.insert(k.clone(),v) {
        Some(v1)=> Err(make_present_error(&k,&v1,mk_e,s)),
        None => Ok(())
    }
}

pub fn update_throw_if_absent<'a, K: Eq+Debug+Hash, V: Clone+'a, F: Fn(&mut V), M: KeyValueContainer<'a, K,V>, E: Debug>(
    k: &'a K,
    f: F,
    m: &'a mut M,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<(),E> {
    let l = m.len();
    let v = m.get_mut(k).ok_or_else(|| make_absent_error(k,l,mk_e,s))?;
    f(v);
    Ok(())
}

pub fn update_throw_if_absent_2_lvl<'a,
                                    K1: Eq+Debug+Hash,
                                    K2: Eq+Debug+Hash,
                                    V:  Clone + 'a,
                                    F:  Fn(&mut V),
                                    M2: KeyValueContainer<'a, K2, V> + 'a + Clone,
                                    M1: KeyValueContainer<'a, K1, M2> + 'a + Clone,
                                    E: Debug> (
    k1: &'a K1,
    k2: &'a K2,
    f: F,
    m: &'a mut M1,
    mk_e: fn(String) -> E,
    s: &[String])
    -> Result<(),E> {
    let l = m.len();
    let m2 = m.get_mut(k1).ok_or_else(|| make_absent_error(k1,l,mk_e,s))?;
    update_throw_if_absent(k2,f,m2,mk_e,s)
}

mod verb_throw_if_adjective_tests {
    use super::*;

    // Make sure it works for any type satisfying Debug
    fn make_strings<T: Debug>(t: T) -> Vec<String> {
        str_vec_from!("abc", format!("cde: {:?}", t))
    }

    lazy_static! {
        static ref STR_VEC: Vec<String> = make_strings(42);
    }

    macro_rules! check_errors_in_s {
        ($exp1:expr, $($arg:expr),*) => {
            let res = ($exp1);
            check_errors_in!(res,"abc","cde:","42",$($arg),*);
            println!("DONE");
        }
    }

    macro_rules! test_lookup_throw_if_absent_with_tree_type {
        ($tree_type:ident) => {
            let mut m = $tree_type::<String,u32>::new();
            m.insert("key0".to_string(),0);
            let k1 = "key1".to_string();
            check_errors_in_s!(lookup_throw_if_absent(&k1,&m,Error::General,&STR_VEC),
                               &k1, "not found among 1 key(s)");
            match lookup_throw_if_absent(&"key0".to_string(),&m,Error::General,&STR_VEC) {
                Err(e) =>
                    assert_eq!(format!("expected Ok(0), but got Err({:?})", e),""),
                Ok(r) => {}
            }
        };
    }

    #[test]
    fn test_lookup_throw_if_absent_hash_map() {
        test_lookup_throw_if_absent_with_tree_type!(HashMap);
    }

    #[test]
    fn test_lookup_throw_if_absent_btree_map() {
        test_lookup_throw_if_absent_with_tree_type!(BTreeMap);
    }

    macro_rules! test_lookup_throw_if_absent_with_2lvl_tree_type {
        ($tree_type_0:ident, $tree_type_1: ident) => {
            let k1_0 = "key1_0".to_string();
            let k1_1 = "key1_1".to_string();
            let k2_0 = "key2_0".to_string();
            let k2_1 = "key2_1".to_string();
            let mut m1 = $tree_type_0::<String,$tree_type_1::<String,u32>>::new();
            let mut m2 = $tree_type_1::<String,u32>::new();
            m2.insert(k2_0.clone(),17);
            m1.insert(k1_0.clone(),m2);
            // Happy path
            assert_eq!(lookup_throw_if_absent_2_lvl(&k1_0,&k2_0,&m1,Error::General,&STR_VEC),Ok(&17));
            // Failure paths
            check_errors_in!(lookup_throw_if_absent_2_lvl(&k1_1,&k2_0,&m1,Error::General,&STR_VEC),
                             &k1_1,"not found among 1 key(s)");
            check_errors_in!(lookup_throw_if_absent_2_lvl(&k1_0,&k2_1,&m1,Error::General,&STR_VEC),
                             &k2_1,"not found among 1 key(s)");
        }
    }

    #[test]
    fn test_lookup_throw_if_absent_2_lvl_hashmap_btree() {
        test_lookup_throw_if_absent_with_2lvl_tree_type!(HashMap,BTreeMap);
    }

    #[test]
    fn test_lookup_throw_if_absent_2_lvl_btree_hashmap() {
        test_lookup_throw_if_absent_with_2lvl_tree_type!(BTreeMap,HashMap);
    }

    #[test]
    fn test_insert_throw_if_present_btree_map() {
        let k0 = "key0".to_string();
        let k1 = "key1".to_string();
        let mut m = BTreeMap::<String,u32>::new();
        m.insert(k0.clone(),12345);
        // Happy path
        assert_eq!(insert_throw_if_present(k1.clone(),54321,&mut m,Error::General,&STR_VEC),Ok(()));
        assert_eq!(lookup_throw_if_absent(&k1,&m,Error::General,&STR_VEC), Ok(&54321));
        // Failure path
        check_errors_in_s!((insert_throw_if_present(k0.clone(),42,&mut m,Error::General,&STR_VEC)),
                           &k0,"12345");
    }

    // Functions for testing update_throw_if_absent variants
    fn double(x: u32) -> u32 { x*2 }
    fn double_mut(x: &mut u32) {*x = double(*x)}

    #[test]
    fn test_update_throw_if_absent_hash_map () {
        let mut m = HashMap::<String,u32>::new();
        let k0 = "key0".to_string();
        let k1 = "key1".to_string();
        m.insert(k0.clone(),2);

        check_errors_in!(update_throw_if_absent(&k1,double_mut,&mut m,Error::General,&STR_VEC),
                         &k1, "not found among 1 key(s)");
        match update_throw_if_absent(&k0,double_mut,&mut m,Error::General,&STR_VEC) {
            Err(e) =>
                assert_eq!(format!("expected Ok(0), but got Err({:?})", e),""),
            Ok(_) => assert_eq!(*m.get(&k0).unwrap(),double(2))
        }
    }

    #[test]
    fn test_update_throw_if_absent_2_lvl_hash_btree() {
        let k1_0 = "key1_0".to_string();
        let k1_1 = "key1_1".to_string();
        let k2_0 = "key2_0".to_string();
        let k2_1 = "key2_1".to_string();
        let mut m1 = HashMap::<String,BTreeMap::<String,u32>>::new();
        let mut m2 = BTreeMap::<String,u32>::new();
        m2.insert(k2_0.clone(),17);
        m1.insert(k1_0.clone(),m2);
        // Happy path
        assert_eq!(update_throw_if_absent_2_lvl(&k1_0,&k2_0,double_mut,&mut m1,Error::General,&STR_VEC),Ok(()));
        assert_eq!(lookup_throw_if_absent_2_lvl(&k1_0,&k2_0,&m1,Error::General,&STR_VEC),Ok(&double(17)));
        // Failure paths
        check_errors_in!(lookup_throw_if_absent_2_lvl(&k1_1,&k2_0,&m1,Error::General,&STR_VEC),
                         &k1_1,"not found among 1 key(s)");
        check_errors_in!(lookup_throw_if_absent_2_lvl(&k1_0,&k2_1,&m1,Error::General,&STR_VEC),
                         &k2_1,"not found among 1 key(s)");
    }
}

pub fn two_lvl_map_to_vec_of_tuples<T0,T1,T2>(m0:&HashMap<T0,HashMap<T1,T2>>) ->
    Vec<(&T0,&T1,&T2)>
where
    T0: std::hash::Hash + Eq,
    T1: std::hash::Hash + Eq,
{
    m0.iter()
        .map(|(k0,m1)| m1.iter()
             .map(move |(k1,v)| (k0,k1,v))
             .collect::<Vec<_>>())
        .collect_concat::<Vec<_>>()
}

pub fn three_lvl_map_to_vec_of_tuples<T0,T1,T2,T3>(m0:&HashMap<T0,HashMap<T1,HashMap<T2,T3>>>) ->
    Vec<(&T0,&T1,&T2,&T3)>
where
    T0: std::hash::Hash + Eq,
    T1: std::hash::Hash + Eq,
    T2: std::hash::Hash + Eq,
{
    m0.iter()
        .map(|(k0,m1)| m1.iter()
             .map(move |(k1,m2)| m2.iter()
                  .map(move |(k2,v)| (k0,k1,k2,v))
                  .collect::<Vec<_>>())
             .collect_concat::<Vec<_>>())
        .collect_concat::<Vec<_>>()
}

pub fn count_leaves_in_3_lvl_map<T0,T1,T2,T3>(
    m0:&HashMap<T0,HashMap<T1,HashMap<T2,T3>>>) -> usize
where
    T0: std::hash::Hash + Eq,
    T1: std::hash::Hash + Eq,
    T2: std::hash::Hash + Eq,
{
    three_lvl_map_to_vec_of_tuples(m0).len()
}

pub fn map_1_lvl<K0,V0,V1>(
    f:fn(V0) -> V1,
    m: &HashMap<K0,V0>
) -> HashMap<K0,V1>
where
    K0: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .map(|(k,v)| (k.clone(),f(v.clone())))
        .collect::<HashMap<K0,V1>>()
}

pub fn filter_map_1_lvl<K0,V0,V1>(
    f1:fn(V0) -> bool,
    f2:fn(V0) -> V1,
    m: &HashMap<K0,V0>
) -> HashMap<K0,V1>
where
    K0: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .filter(|(k,v)| f1((*v).clone()))
        .map(|(k,v)| (k.clone(),f2(v.clone())))
        .collect::<HashMap<K0,V1>>()
}

pub fn map_1_lvl_with_err<K0,V0,V1,E>(
    f:fn(V0) -> Result<V1,E>,
    m: &HashMap<K0,V0>
) -> Result<HashMap<K0,V1>,E>
where
    K0: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .map(|(k,v)| {
            let r = f(v.clone())?;
            Ok((k.clone(), r))
        })
        .collect::<Result<HashMap<K0,V1>,E>>()
}

pub fn filter_map_2_lvl<K0,K1,V0,V1>(
    f1:fn(V0) -> bool,
    f2:fn(V0) -> V1,
    m: &HashMap<K0,HashMap<K1,V0>>
) -> HashMap<K0,HashMap<K1,V1>>
where
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .map(|(k0,m1)| (k0.clone(),filter_map_1_lvl(f1,f2,m1)))
        .collect()
}

pub fn map_2_lvl<K0,K1,V0,V1>(
    f:fn(V0) -> V1,
    m: &HashMap<K0,HashMap<K1,V0>>
) -> HashMap<K0,HashMap<K1,V1>>
where
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .map(|(k0,m1)| (k0.clone(),map_1_lvl(f,m1)))
        .collect()
}

pub fn map_2_lvl_with_err<K0,K1,V0,V1,E>(
    f:fn(V0) -> Result<V1,E>,
    m: &HashMap<K0,HashMap<K1,V0>>
) -> Result<HashMap<K0,HashMap<K1,V1>>,E>
where
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    V0: Clone
{
    m.iter()
        .map(|(k0,m1)| {
            let r = map_1_lvl_with_err(f,m1)?;
            Ok((k0.clone(),r))
        })
        .collect()
}

pub fn map_3_lvl<K0,K1,K2,V0,V1>(
    f: fn(V0) -> V1,
    m: &HashMap<K0,HashMap<K1,HashMap<K2,V0>>>
) -> HashMap<K0,HashMap<K1,HashMap<K2,V1>>>
where
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    K2: Clone+Eq+Hash,
    V0: Clone
{
  m.iter()
        .map(|(k0,m1)| (k0.clone(),map_2_lvl::<K1,K2,V0,V1>(f,m1)))
        .collect()
}

#[allow(clippy::type_complexity)]
pub fn map_3_lvl_with_error<K0,K1,K2,V0,V1,E>(
    f: fn(V0) -> Result<V1,E>,
    m: &HashMap<K0,HashMap<K1,HashMap<K2,V0>>>
) -> Result<HashMap<K0,HashMap<K1,HashMap<K2,V1>>>,E>
where
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    K2: Clone+Eq+Hash,
    V0: Clone
{
  m.iter()
        .map(|(k0,m1)| {
            let r = map_2_lvl_with_err::<K1,K2,V0,V1,E>(f,m1)?;
            Ok((k0.clone(), r))
        })
        .collect()
}

// This function emulates mapping a partially-applied function over the leaves of a 3-level map,
// because Rust does not support partial application like Haskell does.  It is implemented in a
// somewhat Haskell-y way.  There are a number of clones that are probably unnecessary.

// TODO: rewrite in a more Rust-y style, eliminating unnecessary clones.  NOTE: this function
// is called in only two places, and in both cases, the original map is not required after the
// call to this function.  Thus, it may be reasonable for this function to take a &mut for m,
// which may help to avoid unnecessary clones.
#[allow(clippy::type_complexity)]
pub fn map_3_lvl_with_keys_partially_applied_with_error<A0,K0,K1,K2,V0,V1,E>(
    a0:A0,
    f: fn(A0,K0,K1,K2,V0) -> Result<V1,E>,
    m: &HashMap<K0,HashMap<K1,HashMap<K2,V0>>>
) -> Result<HashMap<K0,HashMap<K1,HashMap<K2,V1>>>,E>
where
    A0: Clone,
    K0: Clone+Eq+Hash,
    K1: Clone+Eq+Hash,
    K2: Clone+Eq+Hash,
    V0: Clone
{
    mod util_fns {
        use super::*;

        // f5 is a function that takes 5 args
        pub fn map_2_lvl_with_key_f5_with_err<A0,A1,K0,K1,V0,V1,E>(
            a0:A0,
            a1:A1,
            f:fn(A0,A1,K0,K1,V0) -> Result<V1,E>,
            m: &HashMap<K0,HashMap<K1,V0>>
        ) -> Result<HashMap<K0,HashMap<K1,V1>>,E>
        where
            A0: Clone,
            A1: Clone+Eq+Hash,
            K0: Clone+Eq+Hash,
            K1: Clone+Eq+Hash,
            V0: Clone
        {
            m.iter()
                .map(|(k0,m1)| {
                    let r = map_1_lvl_with_key_f5_with_err(a0.clone(),a1.clone(),k0.clone(),f,m1)?;
                    Ok((k0.clone(),r))
                })
                .collect()
        }

        // f5 is a function that takes 5 args
        pub fn map_1_lvl_with_key_f5_with_err<A0,A1,A2,K0,V0,V1,E>(
            a0:A0,
            a1:A1,
            a2:A2,
            f:fn(A0, A1, A2, K0, V0) -> Result<V1,E>,
            m: &HashMap<K0,V0>
        ) -> Result<HashMap<K0,V1>,E>
        where
            A0: Clone,
            A1: Clone+Eq+Hash,
            A2: Clone+Eq+Hash,
            K0: Clone+Eq+Hash,
            V0: Clone
        {
            m.iter()
                .map(|(k,v)| {
                    let r = f(a0.clone(),a1.clone(),a2.clone(),k.clone(),v.clone())?;
                    Ok((k.clone(), r))
                })
                .collect::<Result<HashMap<K0,V1>,E>>()
        }
    }

    m.iter()
        .map(|(k0,m1)| {
            let r = util_fns::map_2_lvl_with_key_f5_with_err(a0.clone(), k0.clone(),f,m1)?;
            Ok((k0.clone(), r))
        })
        .collect()
}
