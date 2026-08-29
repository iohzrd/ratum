//! Variable difficulty per connection (`stratum_update_vardiff` in `datum_stratum.c`).
//!
//! A snapshot counts the shares accepted since it began. On every accepted share and before
//! every non-quick job notification the rate is compared with `vardiff_target_shares_min`:
//! a rate far above the target after `vardiff_quickdiff_count` shares raises the difficulty
//! at once by up to the measured factor (a "quick" raise, which the caller announces with a
//! `Q` job); a rate under half the target halves it; a rate over twice the target after 16
//! shares doubles it; a minute without a share halves it. Every value is a power of two and
//! never under `vardiff_min` or the floor a fingerprinted miner forces.

use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub min: u64,
    pub target_shares_min: u64,
    pub quickdiff_count: u64,
    pub quickdiff_delta: u64,
}

pub struct Vardiff {
    params: Params,
    /// The difficulty the next job is served at.
    current: u64,
    /// The difficulty last sent to the miner (`mining.set_difficulty`); 0 before the first.
    last_sent: u64,
    /// A floor above `min` set for a fingerprinted miner (NiceHash) or by the pool.
    forced_floor: u64,
    /// Whether the job in force is a quick-raise (`Q`) job, and the difficulty it carries.
    quickdiff_active: bool,
    quickdiff_value: u64,
    snap_count: u64,
    snap_at: Instant,
}

impl Vardiff {
    pub fn new(params: Params, now: Instant) -> Self {
        Vardiff {
            params,
            current: params.min,
            last_sent: 0,
            forced_floor: 0,
            quickdiff_active: false,
            quickdiff_value: 0,
            snap_count: 0,
            snap_at: now,
        }
    }

    pub fn reset_snapshot(&mut self, now: Instant) {
        self.snap_count = 0;
        self.snap_at = now;
    }

    /// The difficulty last sent to the miner; 0 before the first.
    pub fn last_sent(&self) -> u64 {
        self.last_sent
    }

    /// Hold the difficulty at `floor` or above from now on.
    pub fn raise_floor(&mut self, floor: u64) {
        self.forced_floor = self.forced_floor.max(floor);
        self.current = self.current.max(floor);
    }

    /// Serve the next job at `min` or above; the pool's minimum, which applies while its
    /// jobs are served and is not a floor of the connection's own.
    pub fn hold_at_least(&mut self, min: u64) {
        self.current = self.current.max(min);
    }

    /// A job was sent at `last_sent`: a quick-raise (`Q`) job keeps its difficulty apart,
    /// any other ends the quick raise. Returns the difficulty the job carries.
    pub fn job_sent(&mut self, quickdiff: bool) -> u64 {
        self.quickdiff_active = quickdiff;
        if quickdiff {
            self.quickdiff_value = self.last_sent;
        }
        self.last_sent
    }

    #[cfg(test)]
    pub fn set_current(&mut self, d: u64) {
        self.current = d;
    }

    #[cfg(test)]
    pub fn end_quickdiff(&mut self) {
        self.quickdiff_active = false;
    }

    /// The difficulty a share on a `Q` job is checked against.
    pub fn quickdiff_value(&self) -> u64 {
        self.quickdiff_value
    }

    /// Whether a difficulty change is waiting to be sent.
    pub fn change_pending(&self) -> bool {
        self.last_sent != self.current
    }

    /// An accepted share.
    pub fn count_share(&mut self) {
        self.snap_count += 1;
    }

    /// The difficulty `mining.set_difficulty` sent (`current`, or `min` if that was 0).
    pub fn mark_sent(&mut self) -> u64 {
        if self.current == 0 {
            self.current = self.params.min;
        }
        self.last_sent = self.current;
        self.current
    }

    fn floor(&self) -> u64 {
        self.forced_floor.max(self.params.min)
    }

    /// Re-evaluate the difficulty. `no_quick` (before a job notification) forbids the quick
    /// raise. Returns `true` when a quick raise was applied, which the caller announces with
    /// a `Q` job at once.
    pub fn update(&mut self, no_quick: bool, now: Instant) -> bool {
        let p = self.params;
        // A change not yet sent to the miner is left to reach it first.
        if self.current != self.last_sent {
            return false;
        }
        if !no_quick && self.snap_count < p.quickdiff_count {
            return false;
        }
        let delta = now.saturating_duration_since(self.snap_at).as_millis() as u64;
        let n = self.snap_count;
        let target_ms = 60_000 / p.target_shares_min.max(1);
        if n == 0 {
            if delta > 60_000 {
                self.current = (self.current >> 1).max(self.floor());
                self.reset_snapshot(now);
            }
            return false;
        }
        if delta < 1000 {
            return false;
        }
        let ms_per_share = (delta / n).max(1);
        if !self.quickdiff_active
            && !no_quick
            && ms_per_share < target_ms / p.quickdiff_delta.max(1)
        {
            let factor = target_ms / ms_per_share;
            let raw = factor.saturating_mul(self.current);
            self.current = ratum::target::pow2_floor(raw).max(1).max(self.current << 2);
            self.reset_snapshot(now);
            return true;
        }
        if ms_per_share > target_ms * 2 {
            self.current = (self.current >> 1).max(self.floor());
            self.reset_snapshot(now);
            return false;
        }
        if n < 16 {
            return false;
        }
        if ms_per_share < target_ms / 2 {
            self.current <<= 1;
            self.reset_snapshot(now);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PARAMS: Params =
        Params { min: 16384, target_shares_min: 8, quickdiff_count: 8, quickdiff_delta: 8 };

    fn started() -> (Vardiff, Instant) {
        let now = Instant::now();
        let mut v = Vardiff::new(PARAMS, now);
        v.mark_sent();
        (v, now)
    }

    fn shares(v: &mut Vardiff, n: u64) {
        for _ in 0..n {
            v.count_share();
        }
    }

    #[test]
    fn a_minute_without_a_share_halves_down_to_the_floor() {
        let (mut v, now) = started();
        v.set_current(65536);
        v.mark_sent();
        assert!(!v.update(true, now + Duration::from_secs(61)));
        assert_eq!(v.current, 32768);
        v.mark_sent();
        assert!(!v.update(true, now + Duration::from_secs(122)));
        assert_eq!(v.current, 16384);
        v.mark_sent();
        assert!(!v.update(true, now + Duration::from_secs(183)));
        assert_eq!(v.current, 16384, "never under vardiff_min");
    }

    #[test]
    fn a_forced_floor_holds_above_the_minimum() {
        let (mut v, now) = started();
        v.raise_floor(524_288);
        v.mark_sent();
        assert!(!v.update(true, now + Duration::from_secs(61)));
        assert_eq!(v.current, 524_288);
    }

    #[test]
    fn eight_shares_in_two_seconds_quick_raise_by_the_measured_factor() {
        let (mut v, now) = started();
        shares(&mut v, 8);
        // 250 ms per share against a 7500 ms target: factor 30, rounded down to 16.
        assert!(v.update(false, now + Duration::from_secs(2)));
        assert_eq!(v.current, 16384 * 16);
        assert!(v.change_pending(), "the caller must announce it");
    }

    #[test]
    fn a_quick_raise_is_at_least_four_times_and_never_before_the_count_or_from_a_notify() {
        let (mut v, now) = started();
        shares(&mut v, 7);
        assert!(!v.update(false, now + Duration::from_secs(1)), "seven shares are too few");
        v.count_share();
        assert!(!v.update(true, now + Duration::from_secs(1)), "a notify never quick-raises");
        assert_eq!(v.current, 16384);
        // 8 shares in 1 s is 125 ms per share, factor 60 -> 32 -> min 4x holds anyway.
        assert!(v.update(false, now + Duration::from_secs(1)));
        assert!(v.current >= 16384 * 4);
    }

    #[test]
    fn slow_shares_halve_and_fast_ones_double_after_sixteen() {
        let (mut v, now) = started();
        v.set_current(65536);
        v.mark_sent();
        shares(&mut v, 2);
        // Two shares in 40 s: 20 s per share, over twice the 7.5 s target.
        assert!(!v.update(true, now + Duration::from_secs(40)));
        assert_eq!(v.current, 32768);
        v.mark_sent();
        let t = now + Duration::from_secs(40);
        v.reset_snapshot(t);
        shares(&mut v, 16);
        // Sixteen shares in 48 s: 3 s per share, under half the target, but not a quick
        // raise (over a delta-th of the target), so a plain doubling.
        v.end_quickdiff();
        assert!(!v.update(false, t + Duration::from_secs(48)));
        assert_eq!(v.current, 65536);
    }

    #[test]
    fn a_pending_change_is_left_alone() {
        let (mut v, now) = started();
        v.set_current(32768);
        shares(&mut v, 16);
        assert!(!v.update(false, now + Duration::from_secs(2)));
        assert_eq!(v.current, 32768, "unchanged until the change is sent to the miner");
    }
}
