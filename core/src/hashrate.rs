use std::collections::VecDeque;

pub const INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
const CAP: usize = (crate::SECS_PER_DAY / INTERVAL_SECS) as usize;

/// (unix second, hashes per second) samples, oldest first, over at most a day.
pub type History = VecDeque<(u64, f64)>;

pub fn push_sample(history: &mut History, at: u64, hashes_per_second: f64) {
    history.push_back((at, hashes_per_second));
    while history.len() > CAP {
        history.pop_front();
    }
}

/// Samples once now, then every `INTERVAL_SECS` on a thread named `name`.
pub fn sample_periodically(name: &str, sample: impl Fn() + Send + 'static) {
    sample();
    crate::thread::spawn(name, move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(INTERVAL_SECS));
            sample();
        }
    });
}
