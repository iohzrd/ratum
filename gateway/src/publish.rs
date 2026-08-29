//! From a template to the jobs the stratum server serves: the new-tip sequence, the
//! coinbaser request on its own thread, and the once-per-reason reporting of a job that
//! could not be built.

use crate::datum::{PoolConfig, Shared};
use crate::job::{BuildError, Builder};
use crate::stratum::Server;
use crate::template::Template;
use log::{error, info};
use ratum::datum::messages::CoinbaserResponse;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Publisher {
    builder: Mutex<Builder>,
    server: Arc<Server>,
    shared: Arc<Shared>,
    /// Counts the templates passed in; a coinbaser response for any but the latest is
    /// discarded.
    template_serial: AtomicU64,
    /// The last build error reported, so a permanent one (a payout script the coinbase
    /// cannot carry) is logged once per reason rather than on every poll.
    last_error: Mutex<Option<BuildError>>,
}

impl Publisher {
    pub fn new(builder: Builder, server: Arc<Server>, shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Publisher {
            builder: Mutex::new(builder),
            server,
            shared,
            template_serial: AtomicU64::new(0),
            last_error: Mutex::new(None),
        })
    }

    /// Build a job for `t` and publish it; `empty` marks new-block empty work. `what` names
    /// the job in the log.
    fn build_and_publish(
        &self,
        t: &Arc<Template>,
        new_block: bool,
        empty: bool,
        pool: Option<&PoolConfig>,
        coinbaser: Option<CoinbaserResponse>,
        what: &str,
    ) {
        let built = ratum::lock(&self.builder).build(Arc::clone(t), new_block, pool, coinbaser);
        let mut last = ratum::lock(&self.last_error);
        match built {
            Ok(job) => {
                *last = None;
                let job = Arc::new(job);
                self.server.publish(Arc::clone(&job), empty);
                if !empty {
                    info!(
                        "Stratum job {} ready ({what}): height {}, {} coinbaser outputs, {}pooled (sent to {} subscribers)",
                        job.job_id,
                        job.template.height,
                        job.coinbaser_outputs.len(),
                        if job.is_datum_job { "" } else { "not " },
                        self.server.subscriber_count()
                    );
                }
            }
            Err(e) => {
                if last.as_ref() != Some(&e) {
                    error!("could not build the {what} job: {e}");
                    *last = Some(e);
                }
            }
        }
    }

    /// The jobs for a template. On a new tip, the C gateway's sequence: empty (subsidy-only)
    /// work at once, then full work with the blank coinbase, then the job with the pool's
    /// payout split once the coinbaser responds. Miners are never left on subsidy-only work
    /// while the request is open.
    pub fn on_template(self: &Arc<Self>, t: Arc<Template>, new_block: bool) {
        let serial = self.template_serial.fetch_add(1, Ordering::SeqCst) + 1;
        let pool = self.shared.pool_config();
        if new_block {
            self.build_and_publish(&t, true, true, pool.as_ref(), None, "new-block");
            std::thread::sleep(Duration::from_millis(50));
            if pool.is_some() {
                self.build_and_publish(&t, false, false, pool.as_ref(), None, "priority");
            }
        }
        if pool.is_none() {
            self.build_and_publish(&t, false, false, None, None, "full");
        } else {
            self.spawn_coinbaser(t, new_block, serial);
        }
    }

    /// The coinbaser wait (up to `COINBASER_WAIT`) runs on its own thread, as the C
    /// gateway's coinbaser thread does, so the template thread keeps polling the node and
    /// answering block notifications meanwhile.
    fn spawn_coinbaser(self: &Arc<Self>, t: Arc<Template>, new_block: bool, serial: u64) {
        let this = Arc::clone(self);
        let spawned = std::thread::Builder::new().name("coinbaser".into()).spawn(move || {
            let coinbaser = this.shared.fetch_coinbaser(t.coinbase_value, t.prev_hash);
            if this.template_serial.load(Ordering::SeqCst) != serial {
                info!("coinbaser response for a superseded template; not used");
                return;
            }
            let pool = this.shared.pool_config();
            // On a new tip the blank full job is already out; without a coinbaser there is
            // nothing to replace it with.
            if new_block && pool.is_some() && coinbaser.is_none() {
                return;
            }
            this.build_and_publish(&t, false, false, pool.as_ref(), coinbaser, "full");
        });
        if let Err(e) = spawned {
            error!("could not start the coinbaser thread: {e}");
        }
    }
}
