//! Building the jobs of one template and serving them. A new tip serves subsidy-only work at once
//! and then the priority job its coinbase pays, and the full job follows once the pool has answered
//! the coinbaser request for it.

use crate::datum::{AbwState, PendingCoinbaser};
use crate::gateway::Gateway;
use crate::job::builder;
use crate::job::{CoinbaseKind, Job};
use crate::template::Template;
use log::{debug, error, info};
use ratum::bitcoin::hash_to_display_hex;
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::config::ClientConfig;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const EMPTY_JOB_HOLD: Duration = Duration::from_millis(50);

/// Which build of a template is being served. A priority build is the work of a new tip
/// served before the pool's split for it is known, so it always announces the tip; a full
/// build carries whatever split the pool dictated, and announces the tip only when no
/// priority build already did. The two differ in nothing else, which is why the name below
/// is what the log reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Build {
    Priority,
    Full { new_block: bool },
}

impl Build {
    fn announces_tip(self) -> bool {
        match self {
            Self::Priority => true,
            Self::Full { new_block } => new_block,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Full { .. } => "full",
        }
    }
}

/// Builds one job for the template. None when the anti-block-withholding assignment has not
/// been received or the job does not build; both are recorded in `work_error`.
fn build(
    gateway: &Gateway,
    t: &Arc<Template>,
    what: Build,
    pool_config: Option<&ClientConfig>,
    coinbaser: Option<CoinbaserResponse>,
) -> Option<Arc<Job>> {
    // Without a pool configuration the job is not pooled, and is built without a commitment
    // whatever the session holds: under one the gateway cannot recognize a block, and a job
    // that is not pooled sends no share to the pool, so a block on it would reach no node. The
    // configuration and an assignment can arrive during the template request.
    let abw = match gateway.pool.abw_state() {
        _ if pool_config.is_none() => None,
        AbwState::NotRequired => None,
        AbwState::Assigned(a) => Some(a),
        AbwState::Awaiting => {
            debug!(
                "waiting for the pool's anti-withholding assignment before building {} work",
                what.name()
            );
            // No work is built on this tip until the assignment arrives, so the work on the
            // tip it replaced ends now rather than at the next job built.
            gateway.jobs.mark_stale_off(t.prev_hash);
            return None;
        }
    };
    let serial = gateway.next_job_serial.fetch_add(1, Ordering::Relaxed);
    let built = builder::build(
        &gateway.config,
        builder::JobInputs {
            pool_config,
            coinbaser,
            abw,
            ..builder::JobInputs::new(serial, Arc::clone(t))
        },
    );
    match built {
        Ok(job) => {
            gateway.work_error.set(None);
            Some(Arc::new(job))
        }
        Err(e) => {
            let reason = format!("could not build the {} job: {e}", what.name());
            if gateway.work_error.set(Some(reason.clone())) {
                error!("{reason}");
            }
            None
        }
    }
}

/// Builds one job for the template and serves it, as the empty work of a new tip first when
/// the build announces the tip. Both publications are the same job under its two coinbases:
/// the hardware is never sent the coinbase, so nothing in the work itself distinguishes them.
/// A job the table refuses, since a newer template moved the tip while it was built, is not
/// served.
fn build_and_publish(
    gateway: &Gateway,
    t: &Arc<Template>,
    what: Build,
    pool_config: Option<&ClientConfig>,
    coinbaser: Option<CoinbaserResponse>,
) {
    let Some(job) = build(gateway, t, what, pool_config, coinbaser) else { return };
    let refused = || {
        debug!(
            "{} job {} on block {} not served: a newer template builds on another previous block",
            what.name(),
            job.stratum_job_id,
            hash_to_display_hex(&t.prev_hash)
        );
    };
    if what.announces_tip() {
        if !gateway.publish(Arc::clone(&job), CoinbaseKind::SubsidyOnly) {
            refused();
            return;
        }
        std::thread::sleep(EMPTY_JOB_HOLD);
    }
    if !gateway.publish(Arc::clone(&job), CoinbaseKind::Pooled) {
        refused();
        return;
    }
    info!(
        "Stratum job {} ready ({}): height {}, {} coinbaser outputs, {}pooled (sent to {} subscribers)",
        job.stratum_job_id,
        what.name(),
        job.template.height,
        job.coinbaser_outputs.len(),
        if job.is_datum_job { "" } else { "not " },
        gateway.stratum.summary().subscribed
    );
}

/// Builds and serves the work for a template. `pool_config` is the pool configuration the
/// template was checked against. Pooled work whose split the pool will dictate is left to
/// `on_coinbaser`, which the session thread reaches when the pool answers or stops answering.
pub fn on_template(
    gateway: &Gateway,
    t: Arc<Template>,
    new_block: bool,
    pool_config: Option<ClientConfig>,
) {
    gateway.jobs.set_tip(t.prev_hash);
    let Some(config) = pool_config else {
        build_and_publish(gateway, &t, Build::Full { new_block }, None, None);
        return;
    };
    if new_block {
        // Serve the tip before its split is known; `on_coinbaser` replaces this job with one
        // paying the split.
        build_and_publish(gateway, &t, Build::Priority, Some(&config), None);
    }
    if !gateway.pool.request_coinbaser(&t, new_block) && !new_block {
        // The pool dictates no split for this value, and no priority job was built above.
        build_and_publish(gateway, &t, Build::Full { new_block: false }, Some(&config), None);
    }
}

/// Serves the job for `pending`'s template with the split the pool dictated for it, or with
/// none when the pool did not answer. On a new tip with no split there is nothing to serve:
/// the priority job `on_template` built already serves that tip. A request whose template
/// builds on a previous block other than the newest template's is discarded: the response
/// is paired with its request by value alone, and the job would build on a replaced tip.
pub fn on_coinbaser(
    gateway: &Gateway,
    pending: &PendingCoinbaser,
    split: Option<CoinbaserResponse>,
) {
    let prev_hash = pending.template.prev_hash;
    if gateway.jobs.tip() != Some(prev_hash) {
        debug!(
            "coinbaser {} for the template on block {} discarded: a newer template builds on \
             another previous block",
            if split.is_some() { "response" } else { "timeout" },
            hash_to_display_hex(&prev_hash)
        );
        return;
    }
    let pool_config = gateway.pool.pool_config();
    if split.is_none() && pending.new_block && pool_config.is_some() {
        return;
    }
    // The tip was announced as empty work when the priority job was built, so this replaces
    // that job rather than announcing the tip again. When no priority job was built (the
    // anti-block-withholding assignment had not arrived), the pooled publication itself
    // marks the jobs on the tip before it stale (`JobTable::publish`).
    let what = Build::Full { new_block: false };
    build_and_publish(gateway, &pending.template, what, pool_config.as_ref(), split);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{template, test_gateway};
    use std::time::Instant;

    fn on_tip(prev_hash: [u8; 32]) -> Arc<Template> {
        Arc::new(Template { prev_hash, ..template() })
    }

    fn served(gateway: &Gateway) -> Arc<Job> {
        gateway.jobs.current().expect("work is served").job
    }

    /// The template an anti-block-withholding refresh fetches on the tip already served is
    /// standard work: it is served as pooled work alone, and the jobs before it stay valid,
    /// so the shares miners are still submitting on them are not refused.
    #[test]
    fn standard_work_on_the_tip_served_leaves_the_jobs_before_it_valid() {
        let gateway = test_gateway(|_| {});
        let t = on_tip([0; 32]);
        on_template(&gateway, Arc::clone(&t), true, None);
        let first = served(&gateway);

        on_template(&gateway, t, false, None);
        let refreshed = served(&gateway);
        assert_ne!(refreshed.serial, first.serial, "a new job");
        assert_eq!(gateway.jobs.current().map(|p| p.kind), Some(CoinbaseKind::Pooled));
        assert!(!first.is_stale_prevblock(), "the job before it is not stale");
        assert!(!refreshed.is_stale_prevblock());
    }

    /// A coinbaser response for a template on the tip a newer template replaced is
    /// discarded before a job is built, so the new tip's work stays the work served.
    #[test]
    fn a_coinbaser_completion_for_a_replaced_tip_is_discarded() {
        let gateway = test_gateway(|_| {});
        let old = on_tip([0; 32]);
        on_template(&gateway, Arc::clone(&old), false, None);
        on_template(&gateway, on_tip([0x11; 32]), true, None);
        let new_tip = served(&gateway);
        let serial = gateway.next_job_serial.load(Ordering::Relaxed);

        let pending = PendingCoinbaser {
            value: old.coinbase_value,
            prev_hash: old.prev_hash,
            template: old,
            new_block: false,
            requested_at: Instant::now(),
        };
        let split = CoinbaserResponse { value: pending.value, coinbaser_id: 3, outputs: vec![] };
        on_coinbaser(&gateway, &pending, Some(split));
        on_coinbaser(&gateway, &pending, None);

        assert_eq!(gateway.next_job_serial.load(Ordering::Relaxed), serial, "no job built");
        assert_eq!(served(&gateway).serial, new_tip.serial);
        assert!(!new_tip.is_stale_prevblock());
    }
}
