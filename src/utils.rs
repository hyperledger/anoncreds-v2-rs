use blsful::inner_types::Scalar;
use indexmap::{IndexMap, IndexSet};
use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt::{self, Formatter},
    hash::Hash,
    marker::PhantomData,
};

pub const TOP_BIT: u64 = i64::MIN as u64;

pub fn get_num_scalar(num: isize) -> Scalar {
    Scalar::from(zero_center(num))
}

pub fn zero_center(num: isize) -> u64 {
    num as u64 ^ TOP_BIT
}
pub fn serialize_indexset<T: Serialize, S: Serializer>(
    set: &IndexSet<T>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut i = s.serialize_seq(Some(set.len()))?;
    for e in set {
        i.serialize_element(e)?;
    }
    i.end()
}

pub fn deserialize_indexset<'de, T: Eq + Hash + DeserializeOwned, D: Deserializer<'de>>(
    d: D,
) -> Result<IndexSet<T>, D::Error> {
    struct IndexSetVisitor<TT: Eq + DeserializeOwned> {
        _marker: PhantomData<TT>,
    }

    impl<'de, TT: Eq + Hash + DeserializeOwned> Visitor<'de> for IndexSetVisitor<TT> {
        type Value = IndexSet<TT>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "a sequence")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut set = IndexSet::new();
            while let Some(e) = seq.next_element()? {
                set.insert(e);
            }
            Ok(set)
        }
    }

    d.deserialize_seq(IndexSetVisitor::<T> {
        _marker: PhantomData,
    })
}

pub fn serialize_indexmap<K: Serialize, V: Serialize, S: Serializer>(
    map: &IndexMap<K, V>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut i = s.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        i.serialize_entry(k, v)?;
    }
    i.end()
}

pub fn deserialize_indexmap<
    'de,
    K: Eq + Hash + DeserializeOwned,
    V: DeserializeOwned,
    D: Deserializer<'de>,
>(
    d: D,
) -> Result<IndexMap<K, V>, D::Error> {
    struct IndexMapVisitor<KK: Eq + Hash + DeserializeOwned, VV: DeserializeOwned> {
        _key_marker: PhantomData<KK>,
        _value_marker: PhantomData<VV>,
    }

    impl<'de, KK: Eq + Hash + DeserializeOwned, VV: DeserializeOwned> Visitor<'de>
        for IndexMapVisitor<KK, VV>
    {
        type Value = IndexMap<KK, VV>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "a map")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut m = IndexMap::new();
            while let Some((k, v)) = map.next_entry()? {
                m.insert(k, v);
            }
            Ok(m)
        }
    }

    d.deserialize_map(IndexMapVisitor::<K, V> {
        _key_marker: PhantomData,
        _value_marker: PhantomData,
    })
}

pub fn serialize_indexmap_nested<K1: Serialize, K2: Serialize, V: Serialize, S: Serializer>(
    map: &IndexMap<K1, IndexMap<K2, V>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let result: Vec<(&K1, Vec<(&K2, &V)>)> = map
        .iter()
        .map(|(k1, v1)| {
            let values = v1.iter().collect::<Vec<(&K2, &V)>>();
            (k1, values)
        })
        .collect();
    result.serialize(s)
}

pub fn deserialize_indexmap_nested<
    'de,
    K1: Deserialize<'de> + Hash + Eq,
    K2: Deserialize<'de> + Hash + Eq,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
>(
    deserialize: D,
) -> Result<IndexMap<K1, IndexMap<K2, V>>, D::Error> {
    let inner = Vec::<(K1, Vec<(K2, V)>)>::deserialize(deserialize)?;
    let mut result = IndexMap::new();
    for (k1, v) in inner.into_iter() {
        let value: IndexMap<K2, V> = v.into_iter().collect();
        result.insert(k1, value);
    }
    Ok(result)
}
