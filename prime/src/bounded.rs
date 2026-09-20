//! A map and a set that forget their oldest entry once they are past a capacity.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug)]
pub struct BoundedMap<K, V> {
    entries: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K: Clone + Eq + Hash, V> BoundedMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn order(&self) -> &VecDeque<K> {
        &self.order
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// `get`, with the entry moved to the newest position, so it is the last forgotten.
    pub fn get_renewed(&mut self, key: &K) -> Option<&V> {
        if self.entries.contains_key(key) {
            self.forget_order(key);
            self.order.push_back(key.clone());
        }
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let replaced = self.entries.insert(key.clone(), value);
        if replaced.is_some() {
            self.forget_order(&key);
        }
        self.order.push_back(key);
        while self.entries.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else { break };
            self.entries.remove(&oldest);
        }
        replaced
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.entries.remove(key)?;
        self.forget_order(key);
        Some(removed)
    }

    pub fn retain(&mut self, keep: impl Fn(&K, &V) -> bool) {
        let entries = &mut self.entries;
        entries.retain(|k, v| keep(k, v));
        self.order.retain(|k| entries.contains_key(k));
    }

    fn forget_order(&mut self, key: &K) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
    }
}

#[derive(Debug)]
pub struct BoundedSet<T>(BoundedMap<T, ()>);

impl<T: Clone + Eq + Hash> BoundedSet<T> {
    pub fn new(capacity: usize) -> Self {
        Self(BoundedMap::new(capacity))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, value: &T) -> bool {
        self.0.get(value).is_some()
    }

    pub fn insert(&mut self, value: T) -> bool {
        if self.0.get(&value).is_some() {
            return false;
        }
        self.0.insert(value, ());
        true
    }

    pub fn remove(&mut self, value: &T) -> bool {
        self.0.remove(value).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_reports_what_it_holds_and_forgets_its_oldest_past_the_capacity() {
        let mut s: BoundedSet<u8> = BoundedSet::new(2);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);

        assert!(s.insert(1));
        assert!(!s.is_empty());
        assert!(!s.insert(1), "a value already held is not inserted again");
        assert_eq!(s.len(), 1);

        assert!(s.insert(2));
        assert!(s.insert(3));
        assert_eq!(s.len(), 2, "the capacity");
        assert!(s.insert(1), "1 was the oldest and was forgotten");

        assert!(s.remove(&1));
        assert!(!s.remove(&1), "removed once");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn a_renewed_entry_is_the_last_forgotten() {
        let mut m: BoundedMap<u8, &str> = BoundedMap::new(2);
        m.insert(1, "one");
        m.insert(2, "two");
        assert_eq!(m.get_renewed(&1), Some(&"one"));
        assert_eq!(m.get_renewed(&3), None, "a key not held is not inserted");
        assert_eq!(m.order().iter().copied().collect::<Vec<_>>(), [2, 1]);
        m.insert(3, "three");
        assert_eq!(m.get(&2), None, "2 was the oldest once 1 was renewed");
        assert_eq!(m.get(&1), Some(&"one"));
    }

    #[test]
    fn a_capacity_below_one_still_holds_one_value() {
        let mut s: BoundedSet<u8> = BoundedSet::new(0);
        assert!(s.insert(1));
        assert_eq!(s.len(), 1);
        assert!(!s.insert(1));
    }
}
