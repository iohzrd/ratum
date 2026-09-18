//! The state every gateway thread shares, assembled once at startup and held in an `Arc`.

use crate::config::Config;
use crate::datum::PoolState;
use crate::job::{CoinbaseKind, Job, JobTable};
use crate::stratum;
use crate::template::waker::TemplateWaker;
use log::warn;
use ratum::latest::Latest;
use ratum::mining_info::LatestMiningInfo;
use ratum::rpc;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

pub struct Gateway {
    pub config: Config,
    pub node: rpc::Client,
    pub extra_nodes: Vec<rpc::Client>,
    pub pool: PoolState,
    pub jobs: JobTable,
    /// The number of the next job built, from which its slot and extranonce prefix are
    /// derived. It sits beside `jobs`, whose slots it indexes.
    pub next_job_serial: AtomicU64,
    pub mining_info: LatestMiningInfo,
    pub template_waker: TemplateWaker,
    /// Why no work is being served, for the status page and for logging a standing reason
    /// once: the template the node would not serve, or the job that would not build. None
    /// while work is served.
    pub work_error: Latest<Option<String>>,
    pub stratum: stratum::State,
}

impl Gateway {
    pub fn new(config: Config, node: rpc::Client) -> Arc<Self> {
        let extra_nodes = config
            .extra_block_submissions
            .urls
            .iter()
            .filter_map(|u| {
                rpc::Client::new(u, "", "", None)
                    .inspect_err(|e| warn!("extra_block_submissions url ignored: {e}"))
                    .ok()
            })
            .collect();
        Arc::new(Self {
            stratum: stratum::State::new(&config),
            pool: PoolState::new(config.shares_in_stale_window()),
            jobs: JobTable::new(config.datum.protocol_job_slots, config.job_retention()),
            next_job_serial: AtomicU64::new(0),
            config,
            node,
            extra_nodes,
            mining_info: LatestMiningInfo::default(),
            template_waker: TemplateWaker::default(),
            work_error: Latest::default(),
        })
    }

    /// Serves the job under `kind`'s coinbase and wakes every connection to send it.
    pub fn publish(&self, job: Arc<Job>, kind: CoinbaseKind) {
        self.jobs.publish(job, kind);
        self.stratum.wake_all();
    }

    pub fn network_share(&self) -> Option<f64> {
        self.mining_info.network_share(self.stratum.summary().hashrate_hs)
    }

    pub fn over_network_share(&self) -> Option<f64> {
        let limit = self.config.max_network_share()?;
        self.network_share().filter(|share| *share > limit)
    }
}
