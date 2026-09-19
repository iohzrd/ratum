//! The thread that asks the node for a template and decides whether it starts a new block, rebuilds
//! the work already held, or is skipped, passing the templates work is built on to the publisher.

use super::waker::Wake;
use super::{Template, TemplateError, parse};
use crate::gateway::Gateway;
use log::{debug, error, info, warn};
use ratum::bitcoin::hash_to_display_hex;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FALLBACK_NOTIFY_INTERVAL: Duration = Duration::from_secs(1);

pub fn fallback_notifier(gateway: &Gateway) {
    let mut last: Option<String> = None;
    loop {
        if let Some(h) = best_block_hash(gateway) {
            if last.as_deref().is_some_and(|l| l != h) {
                debug!("getbestblockhash changed to {h}");
                gateway.template_waker.raise_for(&h);
            }
            last = Some(h);
        }
        std::thread::sleep(FALLBACK_NOTIFY_INTERVAL);
    }
}

/// The node's best block hash, or none when the call fails (logged at debug).
fn best_block_hash(gateway: &Gateway) -> Option<String> {
    match gateway.node.call("getbestblockhash", serde_json::json!([])) {
        Ok(v) => v.as_str().map(str::to_string),
        Err(e) => {
            debug!("getbestblockhash failed: {e}");
            None
        }
    }
}

/// How long a block notification is waited on for the node's best block to move, and how
/// often the best block hash is read meanwhile. The hash read costs the node nothing beside a
/// template, so a notification for a block the node does not report costs the poller these
/// reads alone.
const NOTIFY_PATIENCE: Duration = Duration::from_secs(4);
const NOTIFY_RETRY_DELAY: Duration = Duration::from_millis(250);
const REPEAT_WINDOW: Duration = Duration::from_millis(2500);
const POLL_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Build { new_block: bool },
    Skip,
}

/// What a wake asks the poller for: a template now, a wait for the node's best block to move
/// (a block notification the template may not show yet), or nothing until the next update.
#[derive(Debug, PartialEq, Eq)]
enum Wanted {
    Fetch,
    AwaitTip,
    Nothing,
}

/// What the poller carries between templates: the tip it last built on, when it last changed,
/// and the rebuild a caller asked for. It holds nothing of the gateway, so `classify` decides
/// from these alone.
struct Poller {
    last_prev_hash: Option<[u8; 32]>,
    no_blake2b_rule_reported: Option<u32>,
    last_block_change_at: Option<Instant>,
    force_clean: bool,
}

impl Poller {
    fn new() -> Self {
        Self {
            last_prev_hash: None,
            no_blake2b_rule_reported: None,
            last_block_change_at: None,
            force_clean: false,
        }
    }

    fn poll(gateway: &Gateway, payout_script: &[u8]) -> Option<Template> {
        let work_error = &gateway.work_error;
        let raw = match gateway.node.block_template() {
            Ok(v) => v,
            Err(e) => {
                work_error.set(Some("Could not fetch new template!".into()));
                error!(
                    "Could not fetch new template from {}! ({e})",
                    ratum::rpc::redact_url(&gateway.config.bitcoind.rpcurl)
                );
                return None;
            }
        };
        match parse(&raw, payout_script) {
            Ok(t) => {
                work_error.set(None);
                Some(t)
            }
            Err(TemplateError::Refused(why)) => {
                if work_error.set(Some(why.clone())) {
                    error!("template refused: {why}");
                } else {
                    debug!("template refused: {why}");
                }
                None
            }
            Err(e) => {
                work_error.set(Some(e.to_string()));
                error!("{e}");
                None
            }
        }
    }

    fn classify(&mut self, template: &Template) -> Action {
        let tip_changed = self.last_prev_hash != Some(template.prev_hash);
        let new_block = tip_changed || self.force_clean;
        self.force_clean = false;
        if !template.blake2b_rule {
            if self.no_blake2b_rule_reported != Some(template.height) {
                self.no_blake2b_rule_reported = Some(template.height);
                warn!(
                    "Node does not list the !blake2b rule for block {}; this gateway builds only version 2 (BLAKE2b) headers, so no work will be served until the rule is active.",
                    template.height
                );
            }
            self.last_prev_hash = Some(template.prev_hash);
            return Action::Skip;
        }
        if tip_changed {
            info!(
                "NEW NETWORK BLOCK: {} ({})",
                hash_to_display_hex(&template.prev_hash),
                template.height
            );
            self.last_prev_hash = Some(template.prev_hash);
            self.last_block_change_at = Some(Instant::now());
        } else if new_block {
            info!("Rebuilding work on block {} with clean jobs", template.height);
        }
        Action::Build { new_block }
    }

    fn on_wake(&mut self, wake: Wake) -> Wanted {
        match wake {
            Wake::Block { hash, rebuild } => {
                if rebuild {
                    self.on_rebuild();
                }
                if self.on_block_notification(hash) {
                    Wanted::AwaitTip
                } else if rebuild {
                    Wanted::Fetch
                } else {
                    Wanted::Nothing
                }
            }
            Wake::Rebuild => {
                self.on_rebuild();
                Wanted::Fetch
            }
            // A refresh asks for the template fetched after this wake and nothing else: the
            // tip it builds on decides whether it is a new block, as after a timeout.
            Wake::Refresh | Wake::Timeout => Wanted::Fetch,
        }
    }

    fn on_rebuild(&mut self) {
        debug!("Urgent work update triggered");
        self.force_clean = true;
    }

    fn served(&self) -> Option<String> {
        self.last_prev_hash.map(|h| hash_to_display_hex(&h))
    }

    /// Whether the notification names a block other than the tip served, or names none and
    /// arrives past `REPEAT_WINDOW` from the last block change: the node's best block is then
    /// awaited. A notification naming the tip served, or naming none within the window (the
    /// same block reported by another route), asks for nothing.
    fn on_block_notification(&mut self, hash: Option<String>) -> bool {
        match hash {
            Some(hash) if self.served().as_deref() == Some(hash.as_str()) => {
                debug!("block notification for the tip already served ({hash}); ignored");
                false
            }
            None if self.last_block_change_at.is_some_and(|t| t.elapsed() < REPEAT_WINDOW) => {
                debug!(
                    "block notification within {:.1} s of the last block change; ignored",
                    REPEAT_WINDOW.as_secs_f64()
                );
                false
            }
            _ => {
                info!("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
                true
            }
        }
    }

    /// Waits for the node's best block, read by `best` every `delay`, to differ from the tip
    /// served, for up to `patience`. Returns whether a template is to be fetched: the best
    /// block moved, or could not be read, or a rebuild is pending; a notification the node
    /// does not bear out within the patience fetches nothing.
    fn await_new_tip(
        &self,
        mut best: impl FnMut() -> Option<String>,
        patience: Duration,
        delay: Duration,
    ) -> bool {
        let served = self.served();
        let started = Instant::now();
        loop {
            match best() {
                Some(hash) if served.as_deref() != Some(hash.as_str()) => return true,
                Some(_) => {}
                None => return true,
            }
            if started.elapsed() >= patience {
                warn!(
                    "We received a new block notification, however after {:.0} seconds we did not see a new block.",
                    patience.as_secs_f64()
                );
                return self.force_clean;
            }
            std::thread::sleep(delay);
        }
    }
}

/// Polls the node for templates and hands each one work is built on to the publisher, with
/// whether it starts a new block and the pool configuration it was checked against. A
/// template is fetched every `bitcoind.work_update_seconds`, and at once on a rebuild, a
/// refresh, or a block notification the node bears out.
pub fn run(gateway: &Arc<Gateway>) {
    let interval = Duration::from_secs(gateway.config.bitcoind.work_update_seconds);
    let mut p = Poller::new();
    // The stratum listener starts once the first template has been built from: until the node
    // has served a template there is nothing to answer a miner with.
    let mut listener_started = false;
    let mut fetch = true;
    let mut next_update = Instant::now();
    loop {
        if fetch || Instant::now() >= next_update {
            let pool_config = gateway.pool.pool_config();
            let payout_script = gateway.config.payout_script(pool_config.as_ref());
            let Some(template) = Poller::poll(gateway, payout_script) else {
                std::thread::sleep(POLL_RETRY_DELAY);
                fetch = true;
                continue;
            };
            if let Action::Build { new_block } = p.classify(&template) {
                // A tip no job was served on (the anti-block-withholding assignment was awaited
                // when it arrived) is announced as a new block when work is first built on it,
                // rather than as a job update of a tip the miners were never sent.
                let unserved_tip = gateway
                    .jobs
                    .current()
                    .is_none_or(|p| p.job.template.prev_hash != template.prev_hash);
                let new_block = new_block || unserved_tip;
                let t = Arc::new(template);
                info!(
                    "Updating {} stratum job for block {}: {:.8} BTC, {} txns, {} bytes",
                    if new_block { "priority" } else { "standard" },
                    t.height,
                    t.coinbase_value as f64 / ratum::SATS_PER_BTC,
                    t.txns.len(),
                    t.totals.size
                );
                crate::publish::on_template(gateway, t, new_block, pool_config);
                if !std::mem::replace(&mut listener_started, true) {
                    crate::stratum::spawn_listener(Arc::clone(gateway));
                }
            }
            next_update = Instant::now() + interval;
        }
        let wake =
            gateway.template_waker.wait(next_update.saturating_duration_since(Instant::now()));
        fetch = match p.on_wake(wake) {
            Wanted::Fetch => true,
            Wanted::AwaitTip => {
                p.await_new_tip(|| best_block_hash(gateway), NOTIFY_PATIENCE, NOTIFY_RETRY_DELAY)
            }
            Wanted::Nothing => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::template;

    const PATIENCE: Duration = Duration::from_millis(20);
    const DELAY: Duration = Duration::from_millis(1);

    fn block(hash: Option<String>) -> Wake {
        Wake::Block { hash, rebuild: false }
    }

    #[test]
    fn a_new_tip_builds_clean_and_the_same_tip_builds_standard() {
        let mut p = Poller::new();
        let t = template();
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        assert_eq!(p.on_wake(Wake::Rebuild), Wanted::Fetch);
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "a rebuild is clean");
        let mut no_rule = template();
        no_rule.blake2b_rule = false;
        assert_eq!(p.classify(&no_rule), Action::Skip);
        assert_eq!(p.on_wake(Wake::Timeout), Wanted::Fetch);
    }

    /// A notification for a block the template has not shown waits for the node's best block
    /// to move, reading its hash rather than a template; one the node does not bear out fetches
    /// nothing, and one naming the tip served, or naming none right after a block change, is
    /// ignored.
    #[test]
    fn a_notification_for_an_unseen_tip_awaits_the_best_block_and_expires_without_a_fetch() {
        let mut p = Poller::new();
        let t = template();
        p.classify(&t);
        let served = hash_to_display_hex(&t.prev_hash);
        assert_eq!(p.on_wake(block(Some(served.clone()))), Wanted::Nothing, "the tip served");
        assert_eq!(p.on_wake(block(None)), Wanted::Nothing, "within 2.5 s of the block change");
        assert_eq!(
            p.on_wake(block(Some("11".repeat(32)))),
            Wanted::AwaitTip,
            "another block named is not ignored, however soon"
        );
        p.last_block_change_at = Some(Instant::now() - Duration::from_secs(10));
        assert_eq!(p.on_wake(block(None)), Wanted::AwaitTip);

        let unchanged = || Some(served.clone());
        let started = Instant::now();
        assert!(!p.await_new_tip(unchanged, PATIENCE, DELAY), "patience ends without a fetch");
        assert!(started.elapsed() >= PATIENCE);
        assert!(p.await_new_tip(|| Some("11".repeat(32)), PATIENCE, DELAY), "the tip moved");
        assert!(p.await_new_tip(|| None, PATIENCE, DELAY), "unreadable: fetched as before");

        let mut next = template();
        next.prev_hash = [0x11; 32];
        assert_eq!(p.classify(&next), Action::Build { new_block: true });
        assert_eq!(p.on_wake(block(None)), Wanted::Nothing, "within 2.5 s: ignored");
    }

    #[test]
    fn a_rebuild_carried_by_a_block_notification_still_builds_clean() {
        let mut p = Poller::new();
        let t = template();
        p.classify(&t);
        let served = hash_to_display_hex(&t.prev_hash);
        assert_eq!(
            p.on_wake(Wake::Block { hash: Some(served.clone()), rebuild: true }),
            Wanted::Fetch,
            "the tip served, with a rebuild"
        );
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
        p.last_block_change_at = Some(Instant::now() - Duration::from_secs(10));
        assert_eq!(p.on_wake(Wake::Block { hash: None, rebuild: true }), Wanted::AwaitTip);
        assert!(
            p.await_new_tip(|| Some(served.clone()), PATIENCE, DELAY),
            "the node bears the notification out no better, but the rebuild is pending"
        );
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
    }

    /// An anti-block-withholding assignment notice refreshes the work: on the tip already
    /// served the template builds standard work, which marks no job stale.
    #[test]
    fn a_refresh_on_the_tip_served_builds_standard_work() {
        let mut p = Poller::new();
        let t = template();
        p.classify(&t);
        let waker = super::super::waker::TemplateWaker::default();
        waker.refresh();
        assert_eq!(p.on_wake(waker.wait(Duration::from_millis(1))), Wanted::Fetch);
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        let mut next = template();
        next.prev_hash = [0x11; 32];
        waker.refresh();
        assert_eq!(p.on_wake(waker.wait(Duration::from_millis(1))), Wanted::Fetch);
        assert_eq!(p.classify(&next), Action::Build { new_block: true }, "a new tip still is one");
    }
}
