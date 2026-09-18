//! The thread watching the node: it waits for each new block, re-reads the tip and the template on
//! it, resizes the share window to the new difficulty, and wakes every gateway connection when the
//! work they should build on changed.

use crate::server::Server;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::mining_info::LatestMiningInfo;
use ratum::{lock, rpc};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct TipObservation {
    height: u32,
    observed_at: u64,
}

/// The node's tip, the summary of the template on it and the recent tips, written together
/// so a reader never pairs a tip with the template of another.
#[derive(Default)]
struct NodeView {
    tip: Option<rpc::Tip>,
    template: Option<rpc::TemplateSummary>,
    tip_history: VecDeque<TipObservation>,
}

#[derive(Default)]
pub struct NodeState {
    view: Mutex<NodeView>,
    pub mining: LatestMiningInfo,
    wakers: Mutex<Vec<Arc<Waker>>>,
}

const MINING_INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);

pub const TIP_HISTORY_CAP: usize = 64;

impl NodeState {
    pub fn tip(&self) -> Option<rpc::Tip> {
        lock(&self.view).tip
    }

    pub fn coinbase_value(&self) -> Option<u64> {
        lock(&self.view).template.map(|t| t.coinbase_value)
    }

    /// The tip and the template summary on it, read under one lock.
    pub fn tip_and_template(&self) -> (Option<rpc::Tip>, Option<rpc::TemplateSummary>) {
        let v = lock(&self.view);
        (v.tip, v.template)
    }

    pub fn observed_block_seconds(&self) -> Option<f64> {
        let v = lock(&self.view);
        match (v.tip_history.front(), v.tip_history.back()) {
            (Some(first), Some(last))
                if last.height > first.height && last.observed_at > first.observed_at =>
            {
                Some(
                    (last.observed_at - first.observed_at) as f64
                        / f64::from(last.height - first.height),
                )
            }
            _ => None,
        }
    }

    pub fn add_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).push(Arc::clone(waker));
    }

    pub fn remove_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).retain(|w| !Arc::ptr_eq(w, waker));
    }

    /// Whether the node's tip is one other than the tip held. `watch_node` asks before it
    /// reads a template, which it must not do while holding the view, and `update` asks again
    /// when it writes; both read the answer from `is_new_tip` so the two cannot drift.
    pub fn is_new_tip(&self, hash: &[u8; 32]) -> bool {
        is_new_tip(&lock(&self.view), hash)
    }

    /// Writes the tip and, when `template` is given, the template summary read for it;
    /// returns whether the tip or the next block's bits changed.
    fn update(&self, t: rpc::Tip, template: Option<Option<rpc::TemplateSummary>>) -> bool {
        let mut v = lock(&self.view);
        let tip_changed = is_new_tip(&v, &t.hash);
        let previous_bits = v.template.map(|s| s.bits);
        if tip_changed {
            v.tip_history
                .push_back(TipObservation { height: t.height, observed_at: ratum::unix_now() });
            while v.tip_history.len() > TIP_HISTORY_CAP {
                v.tip_history.pop_front();
            }
        }
        if let Some(template) = template {
            v.template = template;
        }
        v.tip = Some(t);
        tip_changed || v.template.map(|s| s.bits) != previous_bits
    }

    fn wake_connections(&self) {
        for w in lock(&self.wakers).iter() {
            if let Err(e) = w.wake() {
                debug!("could not wake a gateway connection thread: {e}");
            }
        }
    }
}

fn is_new_tip(view: &NodeView, hash: &[u8; 32]) -> bool {
    view.tip.map(|held| held.hash).as_ref() != Some(hash)
}

fn exit_on_wrong_chain(t: &rpc::Tip, expected: Option<rpc::Chain>) {
    let Some(expected) = expected else { return };
    if t.chain == expected {
        return;
    }
    error!(
        "the node is on chain {} but this pool started on chain {} and its ledger holds {} \
         shares; exiting rather than credit shares of one chain to the ledger of another",
        t.chain.name(),
        expected.name(),
        expected.name()
    );
    std::process::exit(1);
}

fn refresh_mining_info(node: &rpc::Client, view: &NodeState) {
    let refreshed = match ratum::mining_info::refresh(node, &view.mining) {
        Ok(r) => r,
        Err(e) => {
            warn!("could not read getmininginfo: {e}");
            return;
        }
    };
    if !refreshed.warnings_changed {
        return;
    }
    for warning in &refreshed.warnings {
        warn!("the node reports: {warning}");
    }
    if refreshed.warnings.is_empty() {
        info!("the node reports no warnings");
    }
}

fn read_template_summary(node: &rpc::Client) -> Option<rpc::TemplateSummary> {
    match node.template_summary() {
        Ok(n) => {
            info!(
                "node template: the next coinbase may pay {} sats at bits {:#010x}",
                n.coinbase_value, n.bits
            );
            Some(n)
        }
        Err(e) => {
            warn!("could not read a template: {e}");
            None
        }
    }
}

/// `difficulty_from_bits` measures a target against share difficulty 1, `2^224`; the node's
/// `getblockchaininfo` against the target of bits `0x1d00ffff`, `0xffff × 2^208`. Multiplying
/// by this turns the first into the second.
const NODE_DIFFICULTY_PER_SHARE_DIFFICULTY: f64 = 65_535.0 / 65_536.0;

/// The difficulty the share window is sized to: that of the block being mined, as TIDES
/// specifies, read from the template's bits in the node's unit; the tip's when no template was
/// read. The two differ for the first block after a retarget and for the BLAKE2b activation
/// block.
fn window_difficulty(tip: &rpc::Tip, template: Option<rpc::TemplateSummary>) -> f64 {
    template
        .and_then(|t| ratum::target::difficulty_from_bits(t.bits))
        .map_or(tip.difficulty, |d| d * NODE_DIFFICULTY_PER_SHARE_DIFFICULTY)
}

/// Reads the node's tip, template and mining info into the server's node state, waking
/// the gateway connections on a change and resizing the share window to the difficulty of
/// the block being mined on each new tip or newly read template.
pub fn watch_node(server: &Server, expected_chain: Option<rpc::Chain>) {
    let (node, view, interval) = (&server.node, &server.node_state, server.settings.poll);
    let mut have_template = false;
    let mut wait_for_blocks = true;
    let mut last_mining_info: Option<Instant> = None;
    loop {
        if last_mining_info.is_none_or(|t| t.elapsed() >= MINING_INFO_INTERVAL) {
            last_mining_info = Some(Instant::now());
            refresh_mining_info(node, view);
        }
        let height = match node.tip() {
            Ok(t) => {
                exit_on_wrong_chain(&t, expected_chain);
                let tip_changed = view.is_new_tip(&t.hash);
                if tip_changed {
                    info!(
                        "node tip: height {} difficulty {} {} (chain {})",
                        t.height,
                        t.difficulty,
                        ratum::bitcoin::hash_to_display_hex(&t.hash),
                        t.chain.name()
                    );
                }
                let template = (tip_changed || !have_template).then(|| {
                    let read = read_template_summary(node);
                    have_template = read.is_some();
                    read
                });
                let next = template.flatten();
                if tip_changed || next.is_some() {
                    let difficulty = window_difficulty(&t, next);
                    let re_read = lock(&server.ledger).set_network_difficulty(difficulty);
                    if re_read != 0 {
                        info!(
                            "difficulty rose; the wider window re-read {re_read} share(s) from \
                             the ledger"
                        );
                    }
                }
                if view.update(t, template) {
                    view.wake_connections();
                }
                Some(t.height)
            }
            Err(e) => {
                if e.is_unauthorized() {
                    error!(
                        "the node refused the pool's RPC credential ({e}). A cookie is \
                         generated each time the node starts; with --rpc-cookie the file is \
                         re-read on the next request, with --rpc-user/--rpc-pass the \
                         credential must match the node's configuration. Until a request \
                         is accepted no block this pool verifies can be submitted."
                    );
                } else {
                    warn!("could not read the node tip: {e}");
                }
                None
            }
        };

        match height.filter(|_| wait_for_blocks) {
            Some(h) => match node.wait_for_block_height(h + 1, interval) {
                Ok(_) => {}
                Err(e) if e.is_method_not_found() => {
                    warn!(
                        "this node does not serve waitforblockheight; \
                         polling every {:.3}s instead",
                        interval.as_secs_f64()
                    );
                    wait_for_blocks = false;
                    std::thread::sleep(interval);
                }
                Err(e) => {
                    warn!("could not wait for the next block: {e}");
                    std::thread::sleep(interval);
                }
            },
            None => std::thread::sleep(interval),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_sized_to_the_block_being_mined_and_to_the_tip_without_a_template() {
        let tip =
            rpc::Tip { hash: [0; 32], height: 2_016, difficulty: 5.0, chain: rpc::Chain::Regtest };
        let template = |bits| Some(rpc::TemplateSummary { coinbase_value: 0, bits });
        let next = window_difficulty(&tip, template(0x1d00ffff));
        assert!((next - 1.0).abs() < 1e-12, "the next block's, in the node's unit: {next}");
        assert_eq!(window_difficulty(&tip, None), 5.0, "no template read");
        assert_eq!(window_difficulty(&tip, template(0x1d80ffff)), 5.0, "bits with no difficulty");
    }
}
