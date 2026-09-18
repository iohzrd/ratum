//! The thread that reads getmininginfo from the node once a minute, which is where the network
//! hashrate estimate and the node's warnings come from.

use crate::gateway::Gateway;
use log::{error, info, warn};
use ratum::rpc;
use std::sync::Arc;
use std::time::Duration;

const INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);
const INFO_RETRY: Duration = Duration::from_secs(10);

pub fn start_info_thread(gateway: Arc<Gateway>) {
    ratum::thread::spawn("node-info", move || {
        let mining_info = &gateway.mining_info;
        let mut announced = false;
        let mut reported = false;
        loop {
            match ratum::mining_info::refresh(&gateway.node, mining_info) {
                Ok(refreshed) => {
                    reported = false;
                    if !announced {
                        announced = true;
                        announce_network_share_limit(
                            gateway.config.max_network_share(),
                            refreshed.chain,
                        );
                    }
                }
                Err(e) if e.is_method_not_found() => {
                    error!(
                        "the node does not serve getmininginfo ({e}), so the network share limit \
                         on new stratum connections is not enforced and the node's warnings are \
                         not shown"
                    );
                    return;
                }
                Err(e) if !reported => {
                    reported = true;
                    warn!(
                        "could not read getmininginfo from the node ({e}); the network share \
                         limit on new stratum connections keeps whatever estimate it has and the \
                         node's warnings are not refreshed"
                    );
                }
                Err(_) => {}
            }
            std::thread::sleep(if announced { INFO_INTERVAL } else { INFO_RETRY });
        }
    });
}

fn announce_network_share_limit(max_network_share: Option<f64>, chain: rpc::Chain) {
    let Some(limit) = max_network_share else { return };
    if chain == rpc::Chain::Main {
        info!(
            "Refusing new stratum connections while this gateway's miners are above {:.2}% of the network hashrate",
            limit * 100.0
        );
    } else {
        info!(
            "The node is on chain {}, not main: new stratum connections are accepted whatever share of that chain's hashrate this gateway holds",
            chain.name()
        );
    }
}
