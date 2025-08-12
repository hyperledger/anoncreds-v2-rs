// ------------------------------------------------------------------------------
use vb_accumulator::persistence::*;
// ------------------------------------------------------------------------------
use ark_std::iter::Iterator;
// ------------------------------------------------------------------------------
use std::fmt::Debug;

// This is put in a 'test' module to indicate it should not be used in production.
pub mod test {
    use super::*;
    use std::{collections::HashSet, hash::Hash};

    // In-memory stores for testing.

    #[derive(Clone, Debug)]
    pub struct InMemoryInitialElements<T: Clone> {
        pub db: HashSet<T>,
    }

    impl<T: Clone> InMemoryInitialElements<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Hash + Eq> InitialElementsStore<T> for InMemoryInitialElements<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InMemoryState<T: Clone + Debug> {
        pub db: HashSet<T>,
    }

    #[cfg(feature="in_memory_state")]
    pub fn print_in_memory_state<T: Clone + Debug>(ims: &InMemoryState::<T>) {
        let mut l: Vec<String> = ims.db.iter().map(|bn| format!("{bn:?}")).collect();
        l.sort();
        println!("IMS with {} elements", l.len());
        for fr in l {
            println!("  {fr:?}");
        }
    }

    impl<T: Clone + Debug> InMemoryState<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Debug + Hash + Eq + Sized> State<T> for InMemoryState<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn remove(&mut self, element: &T) {
            self.db.remove(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }

        fn size(&self) -> u64 {
            self.db.len() as u64
        }
    }

    impl<'a, T: Clone + Debug + Hash + Eq + Sized + 'a> UniversalAccumulatorState<'a, T> for InMemoryState<T> {
        type ElementIterator = std::collections::hash_set::Iter<'a, T>;

        fn elements(&'a self) -> Self::ElementIterator {
            self.db.iter()
        }
    }
}
