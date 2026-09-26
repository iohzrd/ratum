//! Dividing a block's value over the window: the operator fee taken first, and the amounts the
//! weights give, subject to a minimum and an output count.

use super::{Ledger, most_work_first};
use ratum::datum::messages::coinbaser::MAX_COINBASER_OUTPUTS;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// Shared with the window's entry for the identity, so a split allocates no name.
    pub identity: Arc<str>,
    pub sats: u64,
}

/// The smallest output written, the P2PKH dust threshold: an identity whose amount would fall
/// under it leaves the split.
pub const MIN_PAYOUT: u64 = 546;

/// What a block's value is split by: the operator fee paid to the pool's script before the
/// split.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitPolicy {
    pub fee_bps: u16,
}

impl SplitPolicy {
    pub fn fee_on(&self, value: u64) -> u64 {
        basis_points_of(u128::from(value), self.fee_bps) as u64
    }

    pub fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

fn basis_points_of(work: u128, bps: u16) -> u128 {
    work.saturating_mul(u128::from(bps)) / u128::from(ratum::BASIS_POINTS_PER_UNIT)
}

/// Each identity's weight in the split, its work in the window, copied out under the ledger
/// lock so that the split (a sort and the amounts) runs without it. The weights total the
/// window's work, which `split` divides by; `weights_total_the_window` pins it.
#[derive(Clone, Debug, Default)]
pub struct Weights {
    /// Each identity with work in the window and its weight, in the window's order.
    pub(super) entries: Vec<(Arc<str>, u128)>,
}

impl Weights {
    /// The split of `value`, already less the operator fee, among at most
    /// `MAX_COINBASER_OUTPUTS` identities of at least `MIN_PAYOUT`, most work first.
    pub fn split(self, value: u64) -> Vec<Payout> {
        self.split_with(value, MIN_PAYOUT, MAX_COINBASER_OUTPUTS)
    }

    fn split_with(self, value: u64, min_payout: u64, max_outputs: usize) -> Vec<Payout> {
        let Self { mut entries } = self;
        let total: u128 = entries.iter().map(|(_, w)| w).sum();
        if total == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        entries.sort_by(|(a, x), (b, y)| most_work_first((a, *x), (b, *y)));
        entries.truncate(max_outputs);
        let mut work: u128 = entries.iter().map(|(_, w)| w).sum();

        while let Some(w) = entries.last().map(|(_, w)| *w) {
            if work == 0 {
                entries.clear();
                break;
            }
            if u128::from(value).saturating_mul(w) / work >= u128::from(min_payout) {
                break;
            }
            work -= w;
            entries.pop();
        }

        let mut left = value;
        let mut out = Vec::with_capacity(entries.len());
        for (identity, w) in entries {
            if work == 0 {
                break;
            }
            let amount = (u128::from(left).saturating_mul(w) / work) as u64;
            left -= amount;
            work -= w;
            if amount != 0 {
                out.push(Payout { identity, sats: amount });
            }
        }
        out
    }
}

impl Ledger {
    /// Each identity's weight in the split, its work. One pass over the window, taken under
    /// the ledger lock; `Weights::split` then runs without it.
    pub fn weights(&self) -> Weights {
        let entries =
            self.identities.iter().map(|(identity, state)| (Arc::clone(identity), state.work));
        Weights { entries: entries.collect() }
    }

    /// What the split of `value` is computed from: the weights, and `value` less the
    /// operator fee. A caller holding the ledger lock takes these and releases it before
    /// `Weights::split`.
    pub fn weights_for(&self, value: u64) -> (Weights, u64) {
        (self.weights(), self.split_policy.miners_share(value))
    }

    /// The split of `value`: `weights_for` and `Weights::split` in one call.
    #[cfg(test)]
    pub fn split(&self, value: u64) -> Vec<Payout> {
        let (weights, value) = self.weights_for(value);
        weights.split(value)
    }

    #[cfg(test)]
    pub(super) fn split_value(
        &self,
        value: u64,
        min_payout: u64,
        max_outputs: usize,
    ) -> Vec<Payout> {
        self.weights().split_with(value, min_payout, max_outputs)
    }
}
