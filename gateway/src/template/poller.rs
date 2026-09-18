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
        match gateway.node.call("getbestblockhash", serde_json::json!([])) {
            Ok(v) => {
                if let Some(h) = v.as_str() {
                    if last.as_deref().is_some_and(|l| l != h) {
                        debug!("getbestblockhash changed to {h}");
                        gateway.template_waker.raise_for(h);
                    }
                    last = Some(h.to_string());
                }
            }
            Err(e) => debug!("getbestblockhash failed: {e}"),
        }
        std::thread::sleep(FALLBACK_NOTIFY_INTERVAL);
    }
}

const NOTIFY_PATIENCE: Duration = Duration::from_secs(4);
const NOTIFY_RETRY_DELAY: Duration = Duration::from_millis(250);
const REPEAT_WINDOW: Duration = Duration::from_millis(2500);
const POLL_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Build { new_block: bool },
    Skip,
    Retry,
}

/// What the poller carries between templates: the tip it last built on, the block
/// notification it is waiting to see a template for, and the rebuild a caller asked for. It
/// holds nothing of the gateway, so `classify` decides from these alone.
struct Poller {
    last_prev_hash: Option<[u8; 32]>,
    no_blake2b_rule_reported: Option<u32>,
    was_notified: bool,
    notified_at: Instant,
    last_block_change_at: Option<Instant>,
    force_clean: bool,
}

impl Poller {
    fn new() -> Self {
        Self {
            last_prev_hash: None,
            no_blake2b_rule_reported: None,
            was_notified: false,
            notified_at: Instant::now(),
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
            self.was_notified = false;
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
            self.was_notified = false;
        } else if new_block {
            info!("Rebuilding work on block {} with clean jobs", template.height);
        } else if self.was_notified {
            if self.notified_at.elapsed() > NOTIFY_PATIENCE {
                warn!(
                    "We received a new block notification, however after {:.0} seconds we did not see a new block.",
                    NOTIFY_PATIENCE.as_secs_f64()
                );
                self.was_notified = false;
            }
            return Action::Retry;
        }
        Action::Build { new_block }
    }

    fn on_wake(&mut self, wake: Wake) {
        match wake {
            Wake::Block { hash, rebuild } => {
                if rebuild {
                    self.on_rebuild();
                }
                self.on_block_notification(hash);
            }
            Wake::Rebuild => self.on_rebuild(),
            // A refresh asks for the template fetched after this wake and nothing else: the
            // tip it builds on decides whether it is a new block, as after a timeout.
            Wake::Refresh | Wake::Timeout => {}
        }
    }

    fn on_rebuild(&mut self) {
        debug!("Urgent work update triggered");
        self.force_clean = true;
    }

    fn on_block_notification(&mut self, hash: Option<String>) {
        match hash {
            Some(hash)
                if self.last_prev_hash.map(|h| hash_to_display_hex(&h)).as_deref()
                    == Some(hash.as_str()) =>
            {
                debug!("block notification for the tip already served ({hash}); ignored");
            }
            _ if self.last_block_change_at.is_some_and(|t| t.elapsed() < REPEAT_WINDOW) => {
                debug!(
                    "block notification within {:.1} s of the last block change; ignored",
                    REPEAT_WINDOW.as_secs_f64()
                );
            }
            _ => {
                info!("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
                self.was_notified = true;
                self.notified_at = Instant::now();
            }
        }
    }
}

/// Polls the node for templates and hands each one work is built on to the publisher, with
/// whether it starts a new block and the pool configuration it was checked against.
pub fn run(gateway: &Arc<Gateway>) {
    let interval = Duration::from_secs(gateway.config.bitcoind.work_update_seconds);
    let mut p = Poller::new();
    // The stratum listener starts once the first template has been built from: until the node
    // has served a template there is nothing to answer a miner with.
    let mut listener_started = false;
    loop {
        let pool_config = gateway.pool.pool_config();
        let payout_script = gateway.config.payout_script(pool_config.as_ref());
        let Some(template) = Poller::poll(gateway, payout_script) else {
            std::thread::sleep(POLL_RETRY_DELAY);
            continue;
        };
        match p.classify(&template) {
            Action::Skip => {}
            Action::Retry => {
                std::thread::sleep(NOTIFY_RETRY_DELAY);
                continue;
            }
            Action::Build { new_block } => {
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
        }
        p.on_wake(gateway.template_waker.wait(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::template;

    fn block(hash: Option<String>) -> Wake {
        Wake::Block { hash, rebuild: false }
    }

    #[test]
    fn a_new_tip_builds_clean_and_the_same_tip_builds_standard() {
        let mut p = Poller::new();
        let t = template();
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        p.on_wake(Wake::Rebuild);
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "a rebuild is clean");
        let mut no_rule = template();
        no_rule.blake2b_rule = false;
        assert_eq!(p.classify(&no_rule), Action::Skip);
    }

    #[test]
    fn a_notification_for_an_unseen_tip_retries_until_it_arrives_or_expires() {
        let mut p = Poller::new();
        let t = template();
        p.classify(&t);
        p.on_wake(block(Some(hash_to_display_hex(&t.prev_hash))));
        assert_eq!(p.classify(&t), Action::Build { new_block: false }, "the tip served: ignored");
        p.last_block_change_at = Some(Instant::now() - Duration::from_secs(10));
        p.on_wake(block(None));
        assert_eq!(p.classify(&t), Action::Retry);
        p.notified_at = Instant::now() - NOTIFY_PATIENCE - Duration::from_secs(1);
        assert_eq!(
            p.classify(&t),
            Action::Retry,
            "the attempt at which patience ends still retries"
        );
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        let mut next = template();
        next.prev_hash = [0x11; 32];
        p.on_wake(block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: true });
        p.on_wake(block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: false }, "within 2.5 s: ignored");
    }

    #[test]
    fn a_rebuild_carried_by_an_ignored_block_notification_still_builds_clean() {
        let mut p = Poller::new();
        let t = template();
        p.classify(&t);
        p.on_wake(Wake::Block { hash: Some(hash_to_display_hex(&t.prev_hash)), rebuild: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "the tip served");
        p.on_wake(Wake::Block { hash: None, rebuild: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "within 2.5 s");
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
        p.on_wake(waker.wait(Duration::from_millis(1)));
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        let mut next = template();
        next.prev_hash = [0x11; 32];
        waker.refresh();
        p.on_wake(waker.wait(Duration::from_millis(1)));
        assert_eq!(p.classify(&next), Action::Build { new_block: true }, "a new tip still is one");
    }
}
