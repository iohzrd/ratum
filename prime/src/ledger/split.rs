//! Dividing a block's value over the window: the operator fee taken first, the public gateway fee
//! charged on the work of shares carrying its tag and partly reassigned to the rest, and the
//! amounts the remaining weights give, subject to a minimum and an output count.

use super::{IdentityState, Ledger, most_work_first};
use ratum::datum::messages::coinbaser::MAX_COINBASER_OUTPUTS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub identity: String,
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

/// What a block's value is split by: the operator fee paid to the pool's script before the
/// split, the smallest amount written as an output, and the public gateway fee charged on the
/// window's weights.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitPolicy {
    pub fee_bps: u16,
    pub min_payout: u64,
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

impl Ledger {
    /// The work the public gateway fee charges and reassigns; none without a public gateway.
    pub fn public_gateway_fee_work(&self) -> Option<PublicGatewayFeeWork> {
        let gateway = self.split_policy.public_gateway.as_ref()?;
        let mut public_gateway_work = 0u128;
        let mut fee_work = 0u128;
        let mut own_gateway_work = 0u128;
        for state in self.identities.values() {
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

    /// Each identity's weight in the split, most work first, and the fee work the pool
    /// retains: what the public gateway fee charged less what it reassigned. The identities
    /// are borrowed from the window: `split_value` keeps at most `MAX_COINBASER_OUTPUTS` of
    /// them and copies only those.
    ///
    /// The weights and the retained fee work total `total_work`, because every identity is
    /// charged by `charged_work` here and by the same function in `public_gateway_fee_work`,
    /// and `given` sums the reassignments this loop hands out. `split_value` divides by that
    /// total, so the two must not drift apart; `weights_total_the_window` pins it.
    pub(super) fn weights(&self) -> (Vec<(&str, u128)>, u128) {
        let fee_bps = self.split_policy.public_gateway.as_ref().map_or(0, |g| g.fee_bps);
        let PublicGatewayFeeWork { fee_work, reassigned_work, own_gateway_work, .. } =
            self.public_gateway_fee_work().unwrap_or_default();
        let mut given = 0u128;
        let mut weights = Vec::with_capacity(self.identities.len());
        for (identity, state) in &self.identities {
            let own = state.own_gateway_work;
            let extra =
                reassigned_work.saturating_mul(own).checked_div(own_gateway_work).unwrap_or(0);
            given += extra;
            weights.push((identity.as_str(), state.work - charged_work(state, fee_bps) + extra));
        }
        weights.sort_by(|(a, x), (b, y)| most_work_first((a, *x), (b, *y)));
        (weights, fee_work.saturating_sub(given))
    }

    /// The split of `value`: the operator fee taken off, and the rest divided over the
    /// window's weights among at most `MAX_COINBASER_OUTPUTS` identities of at least the
    /// minimum payout.
    pub fn split(&self, value: u64) -> Vec<Payout> {
        let p = &self.split_policy;
        self.split_value(p.miners_share(value), p.min_payout, MAX_COINBASER_OUTPUTS)
    }

    pub(super) fn split_value(
        &self,
        value: u64,
        min_payout: u64,
        max_outputs: usize,
    ) -> Vec<Payout> {
        if self.total_work == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        let (mut kept, retained_by_pool) = self.weights();
        kept.truncate(max_outputs);
        let mut work: u128 = kept.iter().map(|(_, w)| w).sum::<u128>() + retained_by_pool;

        while let Some(w) = kept.last().map(|(_, w)| *w) {
            if work == 0 {
                kept.clear();
                break;
            }
            if u128::from(value).saturating_mul(w) / work >= u128::from(min_payout) {
                break;
            }
            work -= w;
            kept.pop();
        }

        let mut left = value;
        let mut out = Vec::with_capacity(kept.len());
        for (identity, w) in kept {
            if work == 0 {
                break;
            }
            let amount = (u128::from(left).saturating_mul(w) / work) as u64;
            left -= amount;
            work -= w;
            if amount != 0 {
                out.push(Payout { identity: identity.to_string(), sats: amount });
            }
        }
        out
    }
}
