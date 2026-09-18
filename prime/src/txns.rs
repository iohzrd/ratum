//! The transactions the pool holds for the jobs it validates, shared between jobs and between
//! connections. Consecutive templates, and the templates of gateways on one network, carry mostly
//! the same transactions, so each serialization is held once however many jobs name it, and is
//! released when the last job naming it is.

use ratum::lock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// How many new transactions are held between two passes that remove the entries of the
/// transactions no job names any more.
const SWEEP_EVERY: usize = 1 << 16;

/// The transactions held, by SHA-256d of their full serialization (witness included).
#[derive(Debug, Default)]
pub struct TxnCache {
    held: HashMap<[u8; 32], Weak<[u8]>>,
    added_since_sweep: usize,
}

impl TxnCache {
    fn intern(&mut self, key: [u8; 32], raw: Vec<u8>) -> Arc<[u8]> {
        if let Some(held) = self.held.get(&key).and_then(Weak::upgrade) {
            return held;
        }
        let txn: Arc<[u8]> = raw.into();
        self.held.insert(key, Arc::downgrade(&txn));
        self.added_since_sweep += 1;
        if self.added_since_sweep >= SWEEP_EVERY {
            self.held.retain(|_, txn| txn.strong_count() > 0);
            self.added_since_sweep = 0;
        }
        txn
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held.len()
    }
}

/// The job's transactions, each the serialization already held when another job names the
/// same one. The keys are hashed before the cache is locked.
pub fn intern_all(cache: &Mutex<TxnCache>, raws: Vec<Vec<u8>>) -> Arc<[Arc<[u8]>]> {
    let keyed: Vec<([u8; 32], Vec<u8>)> =
        raws.into_iter().map(|raw| (ratum::bitcoin::sha256d(&raw), raw)).collect();
    let mut cache = lock(cache);
    keyed.into_iter().map(|(key, raw)| cache.intern(key, raw)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transaction_named_by_two_jobs_is_held_once_and_released_with_the_last() {
        let cache = Mutex::new(TxnCache::default());
        let first = intern_all(&cache, vec![vec![1, 2, 3], vec![4, 5]]);
        let second = intern_all(&cache, vec![vec![4, 5], vec![6]]);
        assert!(Arc::ptr_eq(&first[1], &second[0]), "one serialization for both jobs");
        assert_eq!(lock(&cache).len(), 3);
        drop(first);
        drop(second);
        let again = intern_all(&cache, vec![vec![4, 5]]);
        assert_eq!(&*again[0], &[4, 5], "a released entry is held anew");
    }
}
