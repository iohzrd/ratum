use crate::datum::Pool;
use crate::job::{BuildError, Builder, PoolConfig};
use crate::stratum::Server;
use crate::template::Template;
use log::{debug, error, info};
use ratum::datum::messages::CoinbaserResponse;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const EMPTY_JOB_HOLD: Duration = Duration::from_millis(50);

pub struct Publisher {
    builder: Mutex<Builder>,
    server: Arc<Server>,
    pool: Arc<Pool>,
    template_serial: AtomicU64,
    last_error: Mutex<Option<BuildError>>,
}

impl Publisher {
    pub fn new(builder: Builder, server: Arc<Server>, pool: Arc<Pool>) -> Arc<Self> {
        Arc::new(Self {
            builder: Mutex::new(builder),
            server,
            pool,
            template_serial: AtomicU64::new(0),
            last_error: Mutex::new(None),
        })
    }

    fn build_and_publish(
        &self,
        t: &Arc<Template>,
        new_block: bool,
        pool_config: Option<&PoolConfig>,
        coinbaser: Option<CoinbaserResponse>,
        what: &str,
    ) {
        let require_abw = self.pool.require_abw();
        let abw = if require_abw { self.pool.abw_assignment() } else { None };
        if pool_config.is_some() && require_abw && abw.is_none() {
            debug!(
                "waiting for the pool's anti-withholding assignment before building {what} work"
            );
            return;
        }
        let built =
            ratum::lock(&self.builder).build(Arc::clone(t), new_block, pool_config, coinbaser, abw);
        let mut last = ratum::lock(&self.last_error);
        match built {
            Ok(job) => {
                *last = None;
                let job = Arc::new(job);
                self.server.publish(Arc::clone(&job), new_block);
                if !new_block {
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

    pub fn on_template(self: &Arc<Self>, t: Arc<Template>, new_block: bool) {
        let serial = self.template_serial.fetch_add(1, Ordering::SeqCst) + 1;
        let pool_config = self.pool.pool_config();
        if new_block {
            self.build_and_publish(&t, true, pool_config.as_ref(), None, "new-block");
            std::thread::sleep(EMPTY_JOB_HOLD);
            if pool_config.is_some() {
                self.build_and_publish(&t, false, pool_config.as_ref(), None, "priority");
            }
        }
        if pool_config.is_none() {
            self.build_and_publish(&t, false, None, None, "full");
        } else {
            self.spawn_coinbaser(t, new_block, serial);
        }
    }

    fn spawn_coinbaser(self: &Arc<Self>, t: Arc<Template>, new_block: bool, serial: u64) {
        let this = Arc::clone(self);
        let spawned = ratum::thread::try_spawn("coinbaser", move || {
            let coinbaser = this.pool.fetch_coinbaser(t.coinbase_value, t.prev_hash);
            if this.template_serial.load(Ordering::SeqCst) != serial {
                info!("coinbaser response for a superseded template; not used");
                return;
            }
            let pool_config = this.pool.pool_config();
            if new_block && pool_config.is_some() && coinbaser.is_none() {
                return;
            }
            this.build_and_publish(&t, false, pool_config.as_ref(), coinbaser, "full");
        });
        if let Err(e) = spawned {
            error!("could not start the coinbaser thread: {e}");
        }
    }
}
