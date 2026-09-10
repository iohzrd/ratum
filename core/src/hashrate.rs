use std::collections::VecDeque;

pub const INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
const CAP: usize = (crate::SECS_PER_DAY / INTERVAL_SECS) as usize;

pub type History = VecDeque<(u64, f64)>;

pub fn push_sample(history: &mut History, at: u64, hashes_per_second: f64) {
    history.push_back((at, hashes_per_second));
    while history.len() > CAP {
        history.pop_front();
    }
}

pub fn sample_periodically(name: &str, sample: impl Fn() + Send + 'static) {
    sample();
    crate::thread::spawn(name, move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(INTERVAL_SECS));
            sample();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_keeps_the_newest_cap_samples() {
        let mut h = History::new();
        for i in 0..(CAP as u64 + 5) {
            push_sample(&mut h, i, 1.0);
        }
        assert_eq!(h.len(), CAP);
        assert_eq!(h.front().copied(), Some((5, 1.0)), "the oldest five were discarded");
    }
}
