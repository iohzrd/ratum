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
                while nonce <= u64::from(u32::MAX) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let input = [0u8; 8];
        assert_eq!(search(&input, 2, passing_at(&[]), &[0x7f; 32], || true), None);
    }
}
