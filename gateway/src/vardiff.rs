//! Variable difficulty per connection: the share rate over the window decides whether the
//! difficulty halves, doubles, or is raised at once by the measured factor, the raise a quickdiff
//! notify announces.

use std::time::Instant;

const MS_PER_SECOND: u64 = 1000;
const MS_PER_MINUTE: u64 = MS_PER_SECOND * ratum::SECS_PER_MINUTE;
const MIN_SAMPLE_MS: u64 = MS_PER_SECOND;
const RATE_TOLERANCE: u64 = 2;
const MIN_QUICKDIFF_SHIFT: u32 = 2;
const MIN_SHARES_TO_DOUBLE: u64 = 16;

/// What a mining.notify is served at: the difficulty to announce with a
/// mining.set_difficulty first, when it changed, and the difficulty the job is recorded at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyDifficulty {
    pub announce: Option<u64>,
    pub diff: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct VardiffParams {
    pub min: u64,
    pub target_shares_min: u64,
    pub quickdiff_count: u64,
    pub quickdiff_delta: u64,
}

pub struct Vardiff {
    params: VardiffParams,
    current: u64,
    last_sent: u64,
    forced_floor: u64,
    quickdiff_active: bool,
    quickdiff_value: u64,
    shares_since_snapshot: u64,
    snapshot_at: Instant,
}

impl Vardiff {
    pub fn new(params: VardiffParams, now: Instant) -> Self {
        Self {
            params,
            current: params.min,
            last_sent: 0,
            forced_floor: 0,
            quickdiff_active: false,
            quickdiff_value: 0,
            shares_since_snapshot: 0,
            snapshot_at: now,
        }
    }

    pub fn reset_snapshot(&mut self, now: Instant) {
        self.shares_since_snapshot = 0;
        self.snapshot_at = now;
    }

    pub fn last_sent(&self) -> u64 {
        self.last_sent
    }

    pub fn raise_floor(&mut self, floor: u64) {
        self.forced_floor = self.forced_floor.max(floor);
        self.current = self.current.max(floor);
    }

    /// The difficulty for a mining.notify: adjusts for the job sent (a quickdiff resend
    /// adjusts nothing), holds the difficulty at `floor` or above (the pool's minimum for
    /// pooled work, 0 for none), and marks a changed difficulty as announced.
    pub fn on_notify(&mut self, floor: u64, quickdiff: bool, now: Instant) -> NotifyDifficulty {
        if !quickdiff {
            self.adjust_on_notify(now);
        }
        self.current = self.current.max(floor);
        let announce = (self.last_sent != self.current).then(|| self.mark_sent());
        self.quickdiff_active = quickdiff;
        if quickdiff {
            self.quickdiff_value = self.last_sent;
        }
        NotifyDifficulty { announce, diff: self.last_sent }
    }

    pub fn quickdiff_value(&self) -> u64 {
        self.quickdiff_value
    }

    /// Counts the share and adjusts the difficulty for it; true when the raise is a
    /// quickdiff, which the caller announces at once (every other change waits for the
    /// next notify).
    pub fn on_share_accepted(&mut self, now: Instant) -> bool {
        self.shares_since_snapshot += 1;
        self.adjust_on_share(now)
    }

    #[cfg(test)]
    fn count_share(&mut self) {
        self.shares_since_snapshot += 1;
    }

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

    /// The milliseconds a share should take at `vardiff_target_shares_min` shares a minute.
    fn target_ms(&self) -> u64 {
        MS_PER_MINUTE / self.params.target_shares_min.max(1)
    }

    /// Whether a difficulty change is waiting to be announced. Nothing adjusts until the
    /// miner has been sent the change already decided.
    fn change_pending(&self) -> bool {
        self.current != self.last_sent
    }

    fn elapsed_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.snapshot_at).as_millis() as u64
    }

    /// The milliseconds per share over the snapshot window; none while the window holds no
    /// share or is shorter than `MIN_SAMPLE_MS`, from which no rate is measured.
    fn ms_per_share(&self, now: Instant) -> Option<u64> {
        let n = self.shares_since_snapshot;
        let delta = self.elapsed_ms(now);
        if n == 0 || delta < MIN_SAMPLE_MS {
            return None;
        }
        Some((delta / n).max(1))
    }

    fn halve(&mut self, now: Instant) {
        self.current = (self.current >> 1).max(self.floor());
        self.reset_snapshot(now);
    }

    /// Halves the difficulty on a rate over `RATE_TOLERANCE` times slower than the target,
    /// doubles it on one that much faster once the window holds `MIN_SHARES_TO_DOUBLE`
    /// shares, and leaves it alone between the two. Both directions are reached from a
    /// notify and from an accepted share.
    fn adjust_to_rate(&mut self, ms_per_share: u64, now: Instant) {
        let target_ms = self.target_ms();
        if ms_per_share > target_ms * RATE_TOLERANCE {
            self.halve(now);
        } else if self.shares_since_snapshot >= MIN_SHARES_TO_DOUBLE
            && ms_per_share < target_ms / RATE_TOLERANCE
        {
            self.current <<= 1;
            self.reset_snapshot(now);
        }
    }

    /// The adjustment a mining.notify makes: a window that took a share halves or doubles by
    /// its rate, and one that took none for over a minute halves. A notify never raises by
    /// the measured factor, which is why it reports nothing back.
    fn adjust_on_notify(&mut self, now: Instant) {
        if self.change_pending() {
            return;
        }
        if self.shares_since_snapshot == 0 {
            if self.elapsed_ms(now) > MS_PER_MINUTE {
                self.halve(now);
            }
            return;
        }
        if let Some(ms_per_share) = self.ms_per_share(now) {
            self.adjust_to_rate(ms_per_share, now);
        }
    }

    /// The adjustment an accepted share makes, once `vardiff_quickdiff_count` of them have
    /// been counted: a rate `vardiff_quickdiff_delta` times over the target raises the
    /// difficulty at once by the measured factor, which returns true for the caller to
    /// announce; otherwise the rate halves or doubles as on a notify. The window is never
    /// empty here, since the caller counts the share first.
    fn adjust_on_share(&mut self, now: Instant) -> bool {
        if self.change_pending() || self.shares_since_snapshot < self.params.quickdiff_count {
            return false;
        }
        let Some(ms_per_share) = self.ms_per_share(now) else { return false };
        if !self.quickdiff_active
            && ms_per_share < self.target_ms() / self.params.quickdiff_delta.max(1)
        {
            self.quick_raise(ms_per_share, now);
            return true;
        }
        self.adjust_to_rate(ms_per_share, now);
        false
    }

    /// Raises the difficulty by the factor the measured rate runs over the target, rounded
    /// down to a power of two and never by less than a shift of `MIN_QUICKDIFF_SHIFT` bits.
    fn quick_raise(&mut self, ms_per_share: u64, now: Instant) {
        let factor = self.target_ms() / ms_per_share;
        let raw = factor.saturating_mul(self.current);
        self.current =
            ratum::target::pow2_floor(raw).max(1).max(self.current << MIN_QUICKDIFF_SHIFT);
        self.reset_snapshot(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PARAMS: VardiffParams =
        VardiffParams { min: 16384, target_shares_min: 8, quickdiff_count: 8, quickdiff_delta: 8 };

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
        v.current = 65536;
        v.mark_sent();
        v.on_notify(0, false, now + Duration::from_secs(61));
        assert_eq!(v.current, 32768);
        v.on_notify(0, false, now + Duration::from_secs(122));
        assert_eq!(v.current, 16384);
        v.on_notify(0, false, now + Duration::from_secs(183));
        assert_eq!(v.current, 16384, "never under vardiff_min");
    }

    #[test]
    fn a_forced_floor_holds_above_the_minimum() {
        let (mut v, now) = started();
        v.raise_floor(524_288);
        v.mark_sent();
        v.on_notify(0, false, now + Duration::from_secs(61));
        assert_eq!(v.current, 524_288);
    }

    #[test]
    fn eight_shares_in_two_seconds_quick_raise_by_the_measured_factor() {
        let (mut v, now) = started();
        shares(&mut v, 7);
        assert!(v.on_share_accepted(now + Duration::from_secs(2)));
        assert_eq!(v.current, 16384 * 16);
        assert_eq!(
            v.on_notify(0, false, now + Duration::from_secs(2)),
            NotifyDifficulty { announce: Some(16384 * 16), diff: 16384 * 16 },
            "the next notify announces it"
        );
    }

    #[test]
    fn a_quick_raise_is_at_least_four_times_and_never_before_the_count_or_from_a_notify() {
        let (mut v, now) = started();
        shares(&mut v, 6);
        assert!(!v.on_share_accepted(now + Duration::from_secs(1)), "seven shares are too few");
        v.count_share();
        assert_eq!(
            v.on_notify(0, false, now + Duration::from_secs(1)),
            NotifyDifficulty { announce: None, diff: 16384 },
            "a notify never quick-raises"
        );
        assert!(v.on_share_accepted(now + Duration::from_secs(1)));
        assert!(v.current >= 16384 * 4);
    }

    #[test]
    fn slow_shares_halve_and_fast_ones_double_after_sixteen() {
        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        shares(&mut v, 2);
        let t = now + Duration::from_secs(40);
        assert_eq!(
            v.on_notify(0, false, t),
            NotifyDifficulty { announce: Some(32768), diff: 32768 }
        );
        v.reset_snapshot(t);
        shares(&mut v, 15);
        assert!(!v.on_share_accepted(t + Duration::from_secs(48)));
        assert_eq!(v.current, 65536);
    }

    #[test]
    fn the_halve_and_double_thresholds_are_exact() {
        let target_ms = MS_PER_MINUTE / PARAMS.target_shares_min;

        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        v.reset_snapshot(now);
        shares(&mut v, 4);
        let at_tolerance = Duration::from_millis(4 * target_ms * RATE_TOLERANCE);
        v.on_notify(0, false, now + at_tolerance);
        assert_eq!(v.current, 65536, "exactly at the tolerance does not halve");
        v.on_notify(0, false, now + at_tolerance + Duration::from_millis(4));
        assert_eq!(v.current, 32768, "one millisecond per share slower halves");

        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        v.reset_snapshot(now);
        let short = MIN_SHARES_TO_DOUBLE - 1;
        shares(&mut v, short - 1);
        assert!(!v.on_share_accepted(now + Duration::from_millis(short * target_ms / 4)));
        assert_eq!(v.current, 65536, "one share short of the count does not double");
    }

    #[test]
    fn a_pending_change_is_left_alone() {
        let (mut v, now) = started();
        v.current = 32768;
        shares(&mut v, 15);
        assert!(!v.on_share_accepted(now + Duration::from_secs(2)));
        assert_eq!(v.current, 32768, "unchanged until the change is sent to the miner");
        assert_eq!(
            v.on_notify(0, false, now + Duration::from_secs(2)),
            NotifyDifficulty { announce: Some(32768), diff: 32768 }
        );
    }

    #[test]
    fn a_notify_holds_the_pool_minimum_and_a_quickdiff_resend_records_its_own_value() {
        let (mut v, now) = started();
        assert_eq!(
            v.on_notify(65536, false, now),
            NotifyDifficulty { announce: Some(65536), diff: 65536 }
        );
        assert_eq!(
            v.on_notify(65536, false, now),
            NotifyDifficulty { announce: None, diff: 65536 }
        );
        v.on_notify(65536, false, now + Duration::from_secs(61));
        assert_eq!(
            v.current, 65536,
            "a minute without a share does not halve under the pool minimum"
        );
        assert_eq!(
            v.on_notify(0, false, now + Duration::from_secs(61)),
            NotifyDifficulty { announce: None, diff: 65536 },
            "the pending halving waits for the notify after the hold is lifted"
        );
        v.on_notify(0, false, now + Duration::from_secs(122));
        assert_eq!(v.current, 32768);

        let (mut v, now) = started();
        shares(&mut v, 7);
        assert!(v.on_share_accepted(now + Duration::from_secs(2)));
        let raised = v.current;
        let quick = v.on_notify(0, true, now + Duration::from_secs(2));
        assert_eq!(quick, NotifyDifficulty { announce: Some(raised), diff: raised });
        assert_eq!(v.quickdiff_value(), raised);
    }
}
