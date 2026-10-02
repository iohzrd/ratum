//! The thread that reads getmininginfo from the node once a minute, which is where the network
//! hashrate estimate and the node's warnings come from.

use crate::gateway::Gateway;
use log::{error, warn};
use std::sync::Arc;
use std::time::Duration;

const INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);
const INFO_RETRY: Duration = Duration::from_secs(10);

pub fn start_info_thread(gateway: Arc<Gateway>) {
    ratum::thread::spawn("node-info", move || {
        let mining_info = &gateway.mining_info;
        let mut read_once = false;
        let mut reported = false;
        loop {
            match ratum::mining_info::refresh(&gateway.node, mining_info) {
                Ok(_) => {
                    reported = false;
                    read_once = true;
                }
                Err(e) if e.is_method_not_found() => {
                    error!(
                        "the node does not serve getmininginfo ({e}), so the network hashrate \
                         and the node's warnings are not shown"
                    );
                    return;
                }
                Err(e) if !reported => {
                    reported = true;
                    warn!(
                        "could not read getmininginfo from the node ({e}); the network hashrate \
                         and the node's warnings are not refreshed"
                    );
                }
                Err(_) => {}
            }
            std::thread::sleep(if read_once { INFO_INTERVAL } else { INFO_RETRY });
        }
    });
}
