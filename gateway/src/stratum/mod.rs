mod connection;

use crate::config::Config;
use crate::datum;
use crate::dupes::Dupes;
use crate::job::{Job, MAX_JOBS};
use crate::tally::Tally;
use connection::{Connection, Disconnect};
use log::{debug, info, warn};
use mio::Waker;
use std::io;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HASHRATE_WINDOW_VALID: Duration = Duration::from_secs(3 * ratum::SECS_PER_MINUTE);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(5);
const DIFF_TO_THS: f64 = ratum::HASHES_PER_DIFFICULTY / ratum::HASHES_PER_TERAHASH;

#[derive(Default)]
pub struct Jobs {
    pub ring: Vec<Option<Arc<Job>>>,
    pub current: Option<Arc<Job>>,
    pub empty: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClientStats {
    pub remote: String,
    pub unique_id: u64,
    pub useragent: String,
    pub username: String,
    pub subscribed: bool,
    pub subscribed_at: Option<Instant>,
    pub current_diff: u64,
    pub accepted: Tally,
    pub rejected: Tally,
    pub fee: Tally,
    pub last_accepted: Option<Instant>,
    pub window_diff: u64,
    pub window: Duration,
    pub window_ended: Option<Instant>,
}

impl ClientStats {
    pub fn hashrate_ths(&self) -> Option<f64> {
        let ended = self.window_ended?;
        if ended.elapsed() > HASHRATE_WINDOW_VALID || self.window.is_zero() {
            return None;
        }
        Some(self.window_diff as f64 / self.window.as_secs_f64() * DIFF_TO_THS)
    }
}

pub struct ClientEntry {
    pub kill: AtomicBool,
    pub stats: Mutex<ClientStats>,
    pub(in crate::stratum) waker: Arc<Waker>,
}

impl ClientEntry {
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            debug!("could not wake a stratum connection thread: {e}");
        }
    }

    fn request_kill(&self) {
        self.kill.store(true, Ordering::Relaxed);
        self.wake();
    }
}

#[derive(Default)]
pub struct ClientSummary {
    pub connections: usize,
    pub subscribed: usize,
    pub hashrate_ths: f64,
}

pub struct Server {
    pub config: Arc<Config>,
    pub datum: Arc<datum::Pool>,
    pub node: ratum::rpc::Client,
    pub notify: Arc<crate::template::Notify>,
    pub jobs: Mutex<Jobs>,
    pub(in crate::stratum) generation: AtomicU64,
    pub(in crate::stratum) clients: Mutex<Vec<Arc<ClientEntry>>>,
    pub(in crate::stratum) dupes: Mutex<Dupes>,
    pub(in crate::stratum) next_unique_id: AtomicU64,
    pub rejecting: AtomicBool,
    pub fee: Mutex<Tally>,
    pub extra_nodes: Vec<ratum::rpc::Client>,
    pub listening: AtomicBool,
}

impl Server {
    pub fn new(
        config: Arc<Config>,
        datum: Arc<datum::Pool>,
        node: ratum::rpc::Client,
        notify: Arc<crate::template::Notify>,
    ) -> Arc<Self> {
        let extra_nodes = config
            .extra_block_submissions
            .urls
            .iter()
            .filter_map(|u| {
                let c = crate::submit::extra_client(u);
                if c.is_none() {
                    warn!("extra_block_submissions url {u:?} is not http[s]://[user:pass@]host:port; ignored");
                }
                c
            })
            .collect();
        let dupes = Dupes::new(config.dupe_table_capacity(), config.stale_window());
        Arc::new(Self {
            config,
            datum,
            node,
            notify,
            jobs: Mutex::new(Jobs { ring: vec![None; MAX_JOBS], ..Default::default() }),
            generation: AtomicU64::new(0),
            clients: Mutex::new(Vec::new()),
            dupes: Mutex::new(dupes),
            next_unique_id: AtomicU64::new(1),
            rejecting: AtomicBool::new(false),
            fee: Mutex::new(Tally::default()),
            extra_nodes,
            listening: AtomicBool::new(false),
        })
    }

    pub fn publish(&self, job: Arc<Job>, empty: bool) {
        {
            let mut slots = ratum::lock(&self.datum.slots);
            let i = job.datum_slot as usize;
            if i < slots.len() {
                slots[i] = Some(Arc::clone(&job));
            }
        }
        let mut j = ratum::lock(&self.jobs);
        if job.is_new_block {
            for other in j.ring.iter().flatten() {
                other.stale_prevblock.store(true, Ordering::Relaxed);
            }
        }
        j.ring[job.global_index as usize] = Some(Arc::clone(&job));
        j.current = Some(job);
        j.empty = empty;
        self.generation.fetch_add(1, Ordering::Release);
        drop(j);
        for c in ratum::lock(&self.clients).iter() {
            c.wake();
        }
    }

    pub fn current_job(&self) -> Option<Arc<Job>> {
        ratum::lock(&self.jobs).current.clone()
    }

    pub(in crate::stratum) fn current_for_send(&self) -> (Option<Arc<Job>>, bool, u64) {
        let j = ratum::lock(&self.jobs);
        (j.current.clone(), j.empty, self.generation.load(Ordering::Acquire))
    }

    pub fn connection_count(&self) -> usize {
        ratum::lock(&self.clients).len()
    }

    pub fn summary(&self) -> ClientSummary {
        let mut s = ClientSummary::default();
        for c in ratum::lock(&self.clients).iter() {
            let st = ratum::lock(&c.stats);
            s.connections += 1;
            s.subscribed += usize::from(st.subscribed);
            s.hashrate_ths += st.hashrate_ths().unwrap_or(0.0);
        }
        s
    }

    pub fn subscriber_count(&self) -> usize {
        self.summary().subscribed
    }

    pub fn client_stats(&self) -> Vec<ClientStats> {
        self.client_stats_where(|_| true)
    }

    pub fn client_stats_where(&self, keep: impl Fn(&ClientStats) -> bool) -> Vec<ClientStats> {
        ratum::lock(&self.clients)
            .iter()
            .filter_map(|c| {
                let st = ratum::lock(&c.stats);
                keep(&st).then(|| st.clone())
            })
            .collect()
    }

    pub fn shutdown_all(&self) {
        info!("Disconnecting all stratum clients");
        for c in ratum::lock(&self.clients).iter() {
            c.request_kill();
        }
    }

    pub fn kill_client(&self, unique_id: u64) -> bool {
        for c in ratum::lock(&self.clients).iter() {
            if ratum::lock(&c.stats).unique_id == unique_id {
                c.request_kill();
                return true;
            }
        }
        false
    }
}

pub fn listen(server: Arc<Server>) -> io::Result<()> {
    let s = &server.config.stratum;
    let listener =
        ratum::http::bind_first(&s.listen_addr, s.listen_port, |a: &str| TcpListener::bind(a))
            .map_err(io::Error::other)?;
    info!("Stratum V1 Server Init complete: listening on {}", listener.local_addr()?);
    server.listening.store(true, Ordering::Relaxed);
    let mut last_reject_log: Option<Instant> = None;
    let mut rejected = 0u64;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                std::thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
        };
        if server.rejecting.load(Ordering::Relaxed) {
            rejected += 1;
            if last_reject_log.is_none_or(|t| t.elapsed() >= REJECT_LOG_INTERVAL) {
                warn!(
                    "Refusing stratum connections while the pool is unreachable and datum.pooled_mining_only is set ({rejected} refused)"
                );
                last_reject_log = Some(Instant::now());
            }
            continue;
        }
        if server.connection_count() >= s.max_clients {
            debug!("refusing a connection: {} clients connected", s.max_clients);
            continue;
        }
        let server = Arc::clone(&server);
        let spawned = ratum::thread::try_spawn("stratum-client", move || {
            match Connection::run(server, stream) {
                Ok(()) | Err(Disconnect::Io(_) | Disconnect::Killed | Disconnect::Idle(_)) => {}
                Err(e @ Disconnect::Protocol(_)) => info!("Stratum client connection closed: {e}"),
            }
        });
        if let Err(e) = spawned {
            warn!("could not start a client thread: {e}");
        }
    }
    Ok(())
}
