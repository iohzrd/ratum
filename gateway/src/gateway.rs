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
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

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
    /// The hashes of the newest blocks miners found, so a share resubmitted after it was found
    /// is not submitted to the nodes, or sent to the pool as a block, again.
    found_blocks: Mutex<VecDeque<[u8; 32]>>,
}

/// The block hashes `Gateway::found_blocks` holds.
const MAX_FOUND_BLOCKS: usize = 64;

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
            found_blocks: Mutex::new(VecDeque::with_capacity(MAX_FOUND_BLOCKS)),
        })
    }

    /// Records a block found under `hash`; false when it was found already.
    pub fn first_find(&self, hash: [u8; 32]) -> bool {
        let mut found = ratum::lock(&self.found_blocks);
        if found.contains(&hash) {
            return false;
        }
        if found.len() >= MAX_FOUND_BLOCKS {
            found.pop_front();
        }
        found.push_back(hash);
        true
    }

    /// Serves the job under `kind`'s coinbase and wakes every connection to send it. Returns
    /// false, and wakes none, when the job table refused the job: it builds on a previous
    /// block other than the newest template's (`JobTable::publish`).
    pub fn publish(&self, job: Arc<Job>, kind: CoinbaseKind) -> bool {
        let published = self.jobs.publish(job, kind);
        if published {
            self.stratum.wake_all();
        }
        published
    }

    pub fn network_share(&self) -> Option<f64> {
        self.mining_info.network_share(self.stratum.summary().hashrate_hs)
    }

    pub fn over_network_share(&self) -> Option<f64> {
        let limit = self.config.max_network_share()?;
        self.network_share().filter(|share| *share > limit)
    }
}
