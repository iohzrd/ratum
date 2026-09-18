//! Building the jobs of one template and serving them. A new tip serves subsidy-only work at once
//! and then the priority job its coinbase pays, and the full job follows once the pool has answered
//! the coinbaser request for it.

use crate::datum::{AbwState, PendingCoinbaser};
use crate::gateway::Gateway;
use crate::job::builder;
use crate::job::{CoinbaseKind, Job};
use crate::template::Template;
use log::{debug, error, info};
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
    let abw = match gateway.pool.abw_state() {
        AbwState::NotRequired => None,
        AbwState::Assigned(a) => Some(a),
        AbwState::Awaiting if pool_config.is_none() => None,
        AbwState::Awaiting => {
            debug!(
                "waiting for the pool's anti-withholding assignment before building {} work",
                what.name()
            );
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
fn build_and_publish(
    gateway: &Gateway,
    t: &Arc<Template>,
    what: Build,
    pool_config: Option<&ClientConfig>,
    coinbaser: Option<CoinbaserResponse>,
) {
    let Some(job) = build(gateway, t, what, pool_config, coinbaser) else { return };
    if what.announces_tip() {
        gateway.publish(Arc::clone(&job), CoinbaseKind::SubsidyOnly);
        std::thread::sleep(EMPTY_JOB_HOLD);
    }
    gateway.publish(Arc::clone(&job), CoinbaseKind::Pooled);
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
/// the priority job `on_template` built already serves that tip.
pub fn on_coinbaser(
    gateway: &Gateway,
    pending: &PendingCoinbaser,
    split: Option<CoinbaserResponse>,
) {
    let pool_config = gateway.pool.pool_config();
    if split.is_none() && pending.new_block && pool_config.is_some() {
        return;
    }
    // The tip was announced as empty work when the priority job was built, so this replaces
    // that job rather than announcing the tip again.
    let what = Build::Full { new_block: false };
    build_and_publish(gateway, &pending.template, what, pool_config.as_ref(), split);
}
