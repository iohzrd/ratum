//! What the node last reported through getmininginfo: its network hashrate estimate and its
//! warnings, written by a polling thread and read by the status pages.

use crate::latest::Latest;
use crate::lock;
use crate::rpc;
use std::sync::Mutex;

/// Reads `getmininginfo` and writes it into `into`: the warnings always, and the network
/// hashrate estimate only on main, since `network_share` is reported as a share of the
/// network and the estimate of a test chain names a different network. Returns the chain the
/// node reported and whether the warnings changed, which is what a caller logs on.
///
/// Both binaries poll through this, so the rule above holds for both; they differ only in
/// how they log and how they retry.
pub fn refresh(node: &rpc::Client, into: &LatestMiningInfo) -> Result<Refreshed, rpc::Error> {
    let info = node.mining_info()?;
    if info.chain == rpc::Chain::Main {
        into.set_network_hashps(info.network_hashps);
    }
    let warnings_changed = into.warnings.set(info.warnings.clone());
    Ok(Refreshed { chain: info.chain, warnings: info.warnings, warnings_changed })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refreshed {
    pub chain: rpc::Chain,
    pub warnings: Vec<String>,
    /// Whether these warnings differ from the ones held, so a standing warning is logged once.
    pub warnings_changed: bool,
}

/// The node's last reading. The estimate and the warnings are written by the same poll but
/// held apart: every reader takes one or the other, never the two together.
#[derive(Debug, Default)]
pub struct LatestMiningInfo {
    network_hashps: Mutex<Option<f64>>,
    warnings: Latest<Vec<String>>,
}

impl LatestMiningInfo {
    pub fn network_hashps(&self) -> Option<f64> {
        *lock(&self.network_hashps)
    }

    /// `hashes_per_second` as a fraction of the network's estimate; none while the node has
    /// given no estimate.
    pub fn network_share(&self, hashes_per_second: f64) -> Option<f64> {
        self.network_hashps().map(|network| hashes_per_second / network)
    }

    pub fn set_network_hashps(&self, hashps: f64) {
        if hashps > 0.0 {
            *lock(&self.network_hashps) = Some(hashps);
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.warnings.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_estimate_of_zero_or_less_is_not_recorded() {
        let view = LatestMiningInfo::default();
        view.set_network_hashps(0.0);
        assert_eq!(view.network_hashps(), None, "a chain with no blocks leaves no estimate");
        view.set_network_hashps(-1.0);
        assert_eq!(view.network_hashps(), None, "a negative estimate leaves none");
        assert_eq!(view.network_share(1e14), None, "no share without an estimate");
        view.set_network_hashps(1e18);
        assert_eq!(view.network_hashps(), Some(1e18));
        assert_eq!(view.network_share(5e16), Some(0.05));
        view.set_network_hashps(0.0);
        assert_eq!(view.network_hashps(), Some(1e18), "the last positive estimate is kept");
    }

    #[test]
    fn warnings_report_whether_they_changed() {
        let view = LatestMiningInfo::default();
        assert!(!view.warnings.set(Vec::new()), "no warnings, as at the start");
        assert!(view.warnings.set(vec!["fork".into()]));
        assert!(!view.warnings.set(vec!["fork".into()]));
        assert_eq!(view.warnings(), ["fork"]);
        assert!(view.warnings.set(Vec::new()));
    }
}
