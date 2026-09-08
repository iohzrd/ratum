use crate::target::{self, Target};
use std::sync::atomic::{AtomicU64, Ordering};

const CHECK_INTERVAL: u64 = 1 << 22;
const FALLBACK_THREADS: u64 = 4;
const NONCE_SIZE: usize = size_of::<u32>();

pub fn search(
    input: &[u8],
    splice_at: usize,
    hash: impl Fn(&[u8]) -> [u8; 32] + Sync,
    target: &Target,
    abort: impl Fn() -> bool + Sync,
) -> Option<u32> {
    let found = AtomicU64::new(u64::MAX);
    let threads = std::thread::available_parallelism().map_or(FALLBACK_THREADS, |n| n.get() as u64);
    std::thread::scope(|scope| {
        for t in 0..threads {
            let (found, hash, abort) = (&found, &hash, &abort);
            scope.spawn(move || {
                let mut buf = input.to_vec();
                let mut nonce = t;
                while nonce <= u32::MAX as u64 {
                    buf[splice_at..splice_at + NONCE_SIZE]
                        .copy_from_slice(&(nonce as u32).to_le_bytes());
                    if target::meets_target(&hash(&buf), target) {
                        found.fetch_min(nonce, Ordering::Relaxed);
                        return;
                    }
                    if nonce % CHECK_INTERVAL < threads
                        && (found.load(Ordering::Relaxed) != u64::MAX || abort())
                    {
                        return;
                    }
                    nonce += threads;
                }
            });
        }
    });
    match found.load(Ordering::Relaxed) {
        u64::MAX => None,
        nonce => Some(nonce as u32),
    }
}
