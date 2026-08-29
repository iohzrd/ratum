//! The multi-threaded nonce search the test miners and test fixtures share. Real mining
//! hardware does this; the pool binary never searches for a nonce and does not call it.

use crate::target::{self, Target};
use std::sync::atomic::{AtomicU64, Ordering};

/// How many nonces a thread tests between checks of the shared stop conditions.
const CHECK_INTERVAL: u64 = 1 << 22;

/// Search the 32-bit nonce space for a hash meeting `target`.
///
/// `input` is the buffer the hardware would hash, with the nonce written little-endian at
/// `splice_at`. Threads stride the space and stop at the next check once any of them has
/// found a nonce or `abort` returns true; the result is the lowest nonce found by then.
pub fn search(
    input: &[u8],
    splice_at: usize,
    hash: impl Fn(&[u8]) -> [u8; 32] + Sync,
    target: &Target,
    abort: impl Fn() -> bool + Sync,
) -> Option<u32> {
    let found = AtomicU64::new(u64::MAX);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    std::thread::scope(|scope| {
        for t in 0..threads {
            let (found, hash, abort) = (&found, &hash, &abort);
            scope.spawn(move || {
                let mut buf = input.to_vec();
                let mut nonce = t;
                while nonce <= u32::MAX as u64 {
                    buf[splice_at..splice_at + 4].copy_from_slice(&(nonce as u32).to_le_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A substitute hash function that meets the target only at the listed nonces, so the search
    /// mechanics can be tested without hashing 2^32 times.
    fn passing_at(solutions: &'static [u32]) -> impl Fn(&[u8]) -> [u8; 32] + Sync {
        move |buf: &[u8]| {
            let nonce = u32::from_le_bytes(buf[2..6].try_into().unwrap());
            if solutions.contains(&nonce) { [0u8; 32] } else { [0xff; 32] }
        }
    }

    #[test]
    fn finds_a_nonce_meeting_the_target_and_splices_at_the_offset() {
        let input = [0xaa; 8];
        let nonce = search(&input, 2, passing_at(&[7_777_777]), &[0x7f; 32], || false);
        assert_eq!(nonce, Some(7_777_777));
    }

    #[test]
    fn returns_none_on_exhaustion_and_stops_on_abort() {
        // Aborted at the first check, so the full space is never searched.
        let input = [0u8; 8];
        assert_eq!(search(&input, 2, passing_at(&[]), &[0x7f; 32], || true), None);
    }
}
