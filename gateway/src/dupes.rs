use log::info;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MIN_CAPACITY: usize = 1024;
const MIN_FREED_PERCENT: usize = 5;
const GROWTH_PERCENT: usize = 25;

pub struct Dupes {
    seen: HashMap<[u8; 32], Instant>,
    capacity: usize,
    window: Duration,
}

impl Dupes {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self { seen: HashMap::new(), capacity: capacity.max(MIN_CAPACITY), window }
    }

    /// Records `h` against the time its job was built and returns false when the table
    /// already holds it. At capacity, entries whose job is older than the stale window are
    /// removed first; when that frees too little the capacity is raised instead.
    pub fn insert(&mut self, h: [u8; 32], job_created: Instant) -> bool {
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
                    "duplicate-share table grown to {} entries: {freed} of {held} were stale",
                    self.capacity
                );
            }
        }
        self.seen.insert(h, job_created);
        true
    }
}
