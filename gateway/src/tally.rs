use serde_json::json;

#[derive(Clone, Copy, Debug, Default)]
pub struct Tally {
    pub count: u64,
    pub diff: u64,
}

impl Tally {
    pub fn add(&mut self, diff: u64) {
        self.count += 1;
        self.diff = self.diff.saturating_add(diff);
    }

    pub fn merge(&mut self, other: &Self) {
        self.count = self.count.saturating_add(other.count);
        self.diff = self.diff.saturating_add(other.diff);
    }

    pub fn json(&self) -> serde_json::Value {
        json!({"count": self.count, "diff": self.diff})
    }
}

#[derive(Default)]
pub struct FeeMeter {
    owed: u64,
    started: bool,
}

impl FeeMeter {
    pub fn charge(&mut self, diff: u64, bps: u64) -> bool {
        if bps == 0 {
            return false;
        }
        let share_work = diff.saturating_mul(ratum::BASIS_POINTS_PER_UNIT);
        if !self.started {
            self.started = true;
            self.owed = ratum::rand::u64() % share_work.max(1);
        }
        self.owed = self.owed.saturating_add(diff.saturating_mul(bps));
        if self.owed >= share_work {
            self.owed -= share_work;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fee_takes_its_share_of_the_work_to_within_one_share() {
        for bps in [1u64, 500, 2000, 5000, 9999] {
            let mut meter = FeeMeter::default();
            let mut charged = 0u64;
            let shares = 10_000u64;
            for _ in 0..shares {
                if meter.charge(4096, bps) {
                    charged += 1;
                }
            }
            let expected = shares * bps / 10_000;
            assert!(
                charged.abs_diff(expected) <= 1,
                "{bps} bps: charged {charged}, expected {expected}"
            );
        }
    }
    #[test]
    fn no_fee_and_the_whole_fee() {
        let mut none = FeeMeter::default();
        assert!(!none.charge(4096, 0));
        let mut all = FeeMeter::default();
        for _ in 0..10 {
            assert!(all.charge(4096, 10_000));
        }
    }
}
