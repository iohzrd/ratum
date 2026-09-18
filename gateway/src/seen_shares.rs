//! The hashes of the shares this gateway has already accepted, so a repeat is refused. A full table
//! first drops the shares of jobs past the stale window, and grows only when that frees too little.

use log::info;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MIN_CAPACITY: usize = 1024;
const MIN_FREED_PERCENT: usize = 5;
const GROWTH_PERCENT: usize = 25;

pub struct SeenShareHashes {
    seen: HashMap<[u8; 32], Instant>,
    capacity: usize,
    window: Duration,
}

impl SeenShareHashes {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self { seen: HashMap::new(), capacity: capacity.max(MIN_CAPACITY), window }
    }

    pub fn insert(&mut self, h: [u8; 32], job_created_at: Instant) -> bool {
        if self.seen.contains_key(&h) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            let held = self.seen.len();
            let window = self.window;
            self.seen.retain(|_, created| created.elapsed() <= window);
            let freed = held - self.seen.len();
            if freed < self.capacity * MIN_FREED_PERCENT / 100 {
                self.capacity += self.capacity * GROWTH_PERCENT / 100;
                info!(
                    "seen-share-hash table grown to {} entries: {freed} of {held} were stale",
                    self.capacity
                );
            }
        }
        self.seen.insert(h, job_created_at);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::hash;

    #[test]
    fn a_repeated_share_is_refused() {
        let mut d = SeenShareHashes::new(1024, Duration::from_secs(160));
        let now = Instant::now();
        assert!(d.insert(hash(1), now));
        assert!(!d.insert(hash(1), now));
        assert!(d.insert(hash(2), now));
    }

    #[test]
    fn a_full_table_prunes_shares_of_jobs_outside_the_window_and_keeps_the_rest() {
        let mut d = SeenShareHashes::new(1024, Duration::from_secs(160));
        let old = Instant::now() - Duration::from_secs(200);
        let fresh = Instant::now();
        for i in 0..512 {
            assert!(d.insert(hash(i), old));
        }
        for i in 512..1024 {
            assert!(d.insert(hash(i), fresh));
        }
        assert_eq!(d.seen.len(), 1024);
        assert!(d.insert(hash(5000), fresh));
        assert_eq!(d.seen.len(), 513, "the 512 stale entries were pruned");
        assert_eq!(d.capacity, 1024, "enough was freed; no growth");
        assert!(d.insert(hash(3), fresh), "a pruned share is no longer a duplicate");
        assert!(!d.insert(hash(600), fresh), "a fresh one still is");
    }

    #[test]
    fn a_full_table_of_fresh_shares_grows_and_forgets_nothing() {
        let mut d = SeenShareHashes::new(1024, Duration::from_secs(160));
        let fresh = Instant::now();
        for i in 0..1024 {
            assert!(d.insert(hash(i), fresh));
        }
        assert!(d.insert(hash(9999), fresh));
        assert_eq!(d.capacity, 1280);
        assert_eq!(d.seen.len(), 1025);
        for i in 0..1024 {
            assert!(!d.insert(hash(i), fresh), "share {i} is still remembered");
        }
    }
}
