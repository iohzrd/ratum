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

    pub fn order(&self) -> &VecDeque<K> {
        &self.order
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
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
