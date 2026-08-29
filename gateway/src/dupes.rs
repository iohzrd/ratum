//! Duplicate shares (`datum_stratum_dupes.c`). A share is identified by its hash, which
//! commits to every field a miner sets and to the job, and is remembered until its job is
//! older than the window in which a share is still accepted. When the table is full, the
//! entries whose jobs have left that window are pruned; if that frees under five percent,
//! the table grows by a quarter instead of forgetting shares that could still be replayed.

use log::info;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

pub struct Dupes {
    seen: HashSet<[u8; 32]>,
    /// Every remembered hash with the creation time of its job, in insertion order.
    order: VecDeque<([u8; 32], Instant)>,
    capacity: usize,
    /// How long after a job's creation a share on it is still accepted
    /// (`share_stale_seconds + work_update_seconds`).
    window: Duration,
}

impl Dupes {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Dupes { seen: HashSet::new(), order: VecDeque::new(), capacity: capacity.max(1024), window }
    }

    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Record a share of a job created at `job_created`; `false` if it was already recorded.
    pub fn insert(&mut self, h: [u8; 32], job_created: Instant) -> bool {
        if self.seen.contains(&h) {
            return false;
        }
        if self.order.len() >= self.capacity {
            let freed = self.prune();
            if freed < self.capacity / 20 {
                self.capacity += self.capacity / 4;
                info!(
                    "duplicate-share table grown to {} entries: {freed} of {} were stale",
                    self.capacity,
                    self.order.len() + freed
                );
            }
        }
        self.seen.insert(h);
        self.order.push_back((h, job_created));
        true
    }

    /// Remove every share whose job is outside the acceptance window; returns how many.
    fn prune(&mut self) -> usize {
        let before = self.order.len();
        let window = self.window;
        let seen = &mut self.seen;
        self.order.retain(|(h, created)| {
            let keep = created.elapsed() <= window;
            if !keep {
                seen.remove(h);
            }
            keep
        });
        before - self.order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h
    }

    #[test]
    fn a_repeated_share_is_refused() {
        let mut d = Dupes::new(1024, Duration::from_secs(160));
        let now = Instant::now();
        assert!(d.insert(hash(1), now));
        assert!(!d.insert(hash(1), now));
        assert!(d.insert(hash(2), now));
    }

    #[test]
    fn a_full_table_prunes_shares_of_jobs_outside_the_window_and_keeps_the_rest() {
        let mut d = Dupes::new(1024, Duration::from_secs(160));
        let old = Instant::now() - Duration::from_secs(200);
        let fresh = Instant::now();
        for i in 0..512 {
            assert!(d.insert(hash(i), old));
        }
        for i in 512..1024 {
            assert!(d.insert(hash(i), fresh));
        }
        assert_eq!(d.len(), 1024);
        assert!(d.insert(hash(5000), fresh));
        assert_eq!(d.len(), 513, "the 512 stale entries were pruned");
        assert_eq!(d.capacity(), 1024, "enough was freed; no growth");
        assert!(d.insert(hash(3), fresh), "a pruned share is no longer a duplicate");
        assert!(!d.insert(hash(600), fresh), "a fresh one still is");
    }

    #[test]
    fn a_full_table_of_fresh_shares_grows_and_forgets_nothing() {
        let mut d = Dupes::new(1024, Duration::from_secs(160));
        let fresh = Instant::now();
        for i in 0..1024 {
            assert!(d.insert(hash(i), fresh));
        }
        assert!(d.insert(hash(9999), fresh));
        assert_eq!(d.capacity(), 1280);
        assert_eq!(d.len(), 1025);
        for i in 0..1024 {
            assert!(!d.insert(hash(i), fresh), "share {i} is still remembered");
        }
    }
}
