//! A share count with the difficulty it sums to: what every accepted, rejected and fee
//! counter in the gateway is.

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

    pub fn json(&self) -> serde_json::Value {
        json!({"count": self.count, "diff": self.diff})
    }
}
