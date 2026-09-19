//! Dividing a block's value over the window: the operator fee taken first, the public gateway fee
//! charged on the work of shares carrying its tag and partly reassigned to the rest, and the
//! amounts the remaining weights give, subject to a minimum and an output count.

use super::{IdentityState, Ledger, most_work_first};
use ratum::datum::messages::coinbaser::MAX_COINBASER_OUTPUTS;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// Shared with the window's entry for the identity, so a split allocates no name.
    pub identity: Arc<str>,
    pub sats: u64,
}

/// The public gateway: the secondary coinbase tag its shares carry, the fee charged on their
/// work at each split, and the portion of that fee reassigned to own-gateway miners. A fee of
/// 0 basis points charges and reassigns nothing; the tag then only separates own-gateway work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGateway {
    pub tag: String,
    pub fee_bps: u16,
    pub subsidy_bps: u16,
}

/// The smallest output written, the P2PKH dust threshold: an identity whose amount would fall
/// under it leaves the split.
pub const MIN_PAYOUT: u64 = 546;

/// What a block's value is split by: the operator fee paid to the pool's script before the
/// split, and the public gateway fee charged on the window's weights.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitPolicy {
    pub fee_bps: u16,
    pub public_gateway: Option<PublicGateway>,
}

impl SplitPolicy {
    pub fn fee_on(&self, value: u64) -> u64 {
        basis_points_of(u128::from(value), self.fee_bps) as u64
    }

    pub fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicGatewayFeeWork {
    pub public_gateway_work: u128,
    pub fee_work: u128,
    pub reassigned_work: u128,
    pub own_gateway_work: u128,
}

fn basis_points_of(work: u128, bps: u16) -> u128 {
    work.saturating_mul(u128::from(bps)) / u128::from(ratum::BASIS_POINTS_PER_UNIT)
}

/// The public gateway fee charged on one identity's work: `fee_bps` of the work its shares
/// carried the public gateway's tag on. This is the one expression of that charge.
/// `public_gateway_fee_work` sums it and `weights` deducts it from the same identity, so the
/// weights and the retained fee work total `total_work` exactly; `weights_total_the_window`
/// pins that.
fn charged_work(state: &IdentityState, fee_bps: u16) -> u128 {
    basis_points_of(state.work - state.own_gateway_work, fee_bps)
}

/// The part of `fee_work` handed back to own-gateway miners: none while no share carried an
/// own-gateway tag, since there is nobody to reassign it to. The one expression of that rule.
fn reassigned_work(gateway: &PublicGateway, fee_work: u128, own_gateway_work: u128) -> u128 {
    if own_gateway_work == 0 { 0 } else { basis_points_of(fee_work, gateway.subsidy_bps) }
}

/// Each identity's weight in the split and the fee work the pool retains, copied out of the
/// window under the ledger lock so that the split (a sort and the amounts) runs without it.
///
/// The weights and the retained fee work total the window's work, because every identity is
/// charged by `charged_work` in `Ledger::weights` and by the same function in
/// `public_gateway_fee_work`, and `given` sums the reassignments handed out. `split` divides
/// by that total, so the two must not drift apart; `weights_total_the_window` pins it.
#[derive(Clone, Debug, Default)]
pub struct Weights {
    /// Each identity with work in the window and its weight, in the window's order.
    pub(super) entries: Vec<(Arc<str>, u128)>,
    /// What the public gateway fee charged less what it reassigned; the denominator includes
    /// it, so it reaches the pool's script as the remainder.
    pub(super) retained_by_pool: u128,
}

impl Weights {
    /// The split of `value`, already less the operator fee, among at most
    /// `MAX_COINBASER_OUTPUTS` identities of at least `MIN_PAYOUT`, most work first.
    pub fn split(self, value: u64) -> Vec<Payout> {
        self.split_with(value, MIN_PAYOUT, MAX_COINBASER_OUTPUTS)
    }

    fn split_with(self, value: u64, min_payout: u64, max_outputs: usize) -> Vec<Payout> {
        let Self { mut entries, retained_by_pool } = self;
        let total: u128 = entries.iter().map(|(_, w)| w).sum::<u128>() + retained_by_pool;
        if total == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        entries.sort_by(|(a, x), (b, y)| most_work_first((a, *x), (b, *y)));
        entries.truncate(max_outputs);
        let mut work: u128 = entries.iter().map(|(_, w)| w).sum::<u128>() + retained_by_pool;

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
    /// The work the public gateway fee charges and reassigns; none without a public gateway.
    pub fn public_gateway_fee_work(&self) -> Option<PublicGatewayFeeWork> {
        let gateway = self.split_policy.public_gateway.as_ref()?;
        let mut public_gateway_work = 0u128;
        let mut fee_work = 0u128;
        let mut own_gateway_work = 0u128;
        for (_, state) in self.identities.iter() {
            public_gateway_work += state.work - state.own_gateway_work;
            fee_work += charged_work(state, gateway.fee_bps);
            own_gateway_work += state.own_gateway_work;
        }
        let reassigned_work = reassigned_work(gateway, fee_work, own_gateway_work);
        Some(PublicGatewayFeeWork {
            public_gateway_work,
            fee_work,
            reassigned_work,
            own_gateway_work,
        })
    }

    /// Each identity's weight in the split and the fee work the pool retains: what the
    /// public gateway fee charged less what it reassigned. One pass over the window, taken
    /// under the ledger lock; `Weights::split` then runs without it.
    pub fn weights(&self) -> Weights {
        let fee_bps = self.split_policy.public_gateway.as_ref().map_or(0, |g| g.fee_bps);
        let PublicGatewayFeeWork { fee_work, reassigned_work, own_gateway_work, .. } =
            self.public_gateway_fee_work().unwrap_or_default();
        let mut given = 0u128;
        let mut entries = Vec::with_capacity(self.identities.len());
        for (identity, state) in self.identities.iter() {
            let own = state.own_gateway_work;
            let extra =
                reassigned_work.saturating_mul(own).checked_div(own_gateway_work).unwrap_or(0);
            given += extra;
            entries.push((Arc::clone(identity), state.work - charged_work(state, fee_bps) + extra));
        }
        Weights { entries, retained_by_pool: fee_work.saturating_sub(given) }
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
