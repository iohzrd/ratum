use log::info;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

const MIN_CAPACITY: usize = 1024;
const MIN_FREED_PERCENT: usize = 5;
const GROWTH_PERCENT: usize = 25;

pub struct Dupes {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<([u8; 32], Instant)>,
    capacity: usize,
    window: Duration,
}

impl Dupes {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Dupes {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(MIN_CAPACITY),
            window,
        }
    }

    pub fn insert(&mut self, h: [u8; 32], job_created: Instant) -> bool {
        if self.seen.contains(&h) {
            return false;
        }
        if self.order.len() >= self.capacity {
            let freed = self.prune();
            if freed < self.capacity * MIN_FREED_PERCENT / 100 {
                self.capacity += self.capacity * GROWTH_PERCENT / 100;
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
