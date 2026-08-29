//! The Stratum v1 server, Siacoin dialect, serving version 2 headers. One thread per
//! connection; the messages and their formats are the C gateway's (`datum_stratum.c`).

use crate::address;
use crate::config::Config;
use crate::datum::{self, QueuedShare};
use crate::dupes::Dupes;
use crate::job::{COINBASE_SUBSIDY_ONLY, Job, MAX_JOBS};
use crate::username::{self, FeeMeter};
use crate::vardiff::{self, Vardiff};
use log::{debug, error, info, warn};
use ratum::target;
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const CLIENT_BUFFER: usize = 16384 * 3 + 1024;
const MAX_REQUEST_ID_CHARS: usize = 64;
const READ_POLL: Duration = Duration::from_millis(50);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(11150);
const STAT_CYCLE: Duration = Duration::from_secs(60);
/// Difficulty to TH/s: `diff * 2^32 / 1e12` per second.
const DIFF_TO_THS: f64 = 0.004294967296;

/// What a share's job lookup and header build produced.
struct Reject(i64, &'static str);

const UNKNOWN_WORK: Reject = Reject(20, "unknown-work");
const STALE_WORK: Reject = Reject(21, "stale-work");
const STALE_PREVBLK: Reject = Reject(21, "stale-prevblk");
const DUPLICATE: Reject = Reject(22, "duplicate");
const HIGH_HASH: Reject = Reject(23, "high-hash");
const UNAUTHORIZED_WORKER: Reject = Reject(24, "unauthorized-worker");

/// The jobs the server holds: the ring by global index and the one new connections get.
#[derive(Default)]
pub struct Jobs {
    pub ring: Vec<Option<Arc<Job>>>,
    pub current: Option<Arc<Job>>,
    /// Counts publications; a connection compares it with the one it last sent.
    pub generation: u64,
    /// Whether the current job is to be sent with `clean_jobs`.
    pub clean: bool,
    /// Whether the current job is new-block empty work (subsidy-only coinbase).
    pub empty: bool,
}

/// Per-connection statistics, for the API.
#[derive(Clone, Debug, Default)]
pub struct ClientStats {
    pub remote: String,
    pub unique_id: u64,
    pub useragent: String,
    pub username: String,
    pub subscribed: bool,
    pub subscribed_at: Option<Instant>,
    pub sid: u32,
    pub authorized: bool,
    pub current_diff: u64,
    pub accepted_count: u64,
    pub accepted_diff: u64,
    pub rejected_count: u64,
    pub rejected_diff: u64,
    pub fee_count: u64,
    pub fee_diff: u64,
    pub last_accepted: Option<Instant>,
    pub coinbase_selection: u8,
    /// The completed window's accepted difficulty and its length, for the hashrate.
    pub window_diff: u64,
    pub window: Duration,
    pub window_ended: Option<Instant>,
}

impl ClientStats {
    /// Estimated TH/s from the last completed window, when it ended under three minutes ago.
    pub fn hashrate_ths(&self) -> Option<f64> {
        let ended = self.window_ended?;
        if ended.elapsed() > Duration::from_secs(180) || self.window.is_zero() {
            return None;
        }
        Some(self.window_diff as f64 / self.window.as_secs_f64() * DIFF_TO_THS)
    }
}

pub struct ClientEntry {
    pub kill: AtomicBool,
    pub stats: Mutex<ClientStats>,
}

pub struct Server {
    pub config: Arc<Config>,
    pub datum: Arc<datum::Shared>,
    pub node: ratum::rpc::Client,
    pub notify: Arc<crate::template::Notify>,
    pub jobs: Mutex<Jobs>,
    pub job_signal: Condvar,
    pub clients: Mutex<Vec<Arc<ClientEntry>>>,
    dupes: Mutex<Dupes>,
    next_unique_id: AtomicU64,
    /// Set while `pooled_mining_only` and the pool is not connected: connections are refused.
    pub rejecting: AtomicBool,
    pub fee_share_count: AtomicU64,
    pub fee_share_diff: AtomicU64,
    pub extra_nodes: Vec<ratum::rpc::Client>,
    pub listening: AtomicBool,
}

impl Server {
    pub fn new(
        config: Arc<Config>,
        datum: Arc<datum::Shared>,
        node: ratum::rpc::Client,
        notify: Arc<crate::template::Notify>,
    ) -> Arc<Self> {
        let s = &config.stratum;
        let capacity = s.max_clients_per_thread as u64
            * s.vardiff_target_shares_min
            * (s.share_stale_seconds / 60)
            * 16
            * s.max_threads as u64;
        let accept_window =
            Duration::from_secs(s.share_stale_seconds + config.bitcoind.work_update_seconds);
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
        Arc::new(Server {
            config,
            datum,
            node,
            notify,
            jobs: Mutex::new(Jobs { ring: vec![None; MAX_JOBS], ..Default::default() }),
            job_signal: Condvar::new(),
            clients: Mutex::new(Vec::new()),
            dupes: Mutex::new(Dupes::new(capacity as usize, accept_window)),
            next_unique_id: AtomicU64::new(1),
            rejecting: AtomicBool::new(false),
            fee_share_count: AtomicU64::new(0),
            fee_share_diff: AtomicU64::new(0),
            extra_nodes,
            listening: AtomicBool::new(false),
        })
    }

    /// Make `job` the one served. `empty` marks new-block work sent with `clean_jobs` and the
    /// subsidy-only coinbase. A new-block job marks every other job stale, as
    /// `update_stratum_job` does: a forced rebuild on the same tip (the pool connection came
    /// or went) also retires the jobs built with the previous payout script, whose shares the
    /// pool would refuse.
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
        j.generation += 1;
        j.clean = empty;
        j.empty = empty;
        drop(j);
        self.job_signal.notify_all();
    }

    pub fn current_job(&self) -> Option<Arc<Job>> {
        ratum::lock(&self.jobs).current.clone()
    }

    pub fn subscriber_count(&self) -> usize {
        ratum::lock(&self.clients).iter().filter(|c| ratum::lock(&c.stats).subscribed).count()
    }

    pub fn connection_count(&self) -> usize {
        ratum::lock(&self.clients).len()
    }

    pub fn total_hashrate_ths(&self) -> f64 {
        ratum::lock(&self.clients).iter().filter_map(|c| ratum::lock(&c.stats).hashrate_ths()).sum()
    }

    pub fn client_stats(&self) -> Vec<ClientStats> {
        ratum::lock(&self.clients).iter().map(|c| ratum::lock(&c.stats).clone()).collect()
    }

    /// Disconnect every client (`datum_stratum_v1_shutdown_all`).
    pub fn shutdown_all(&self) {
        info!("Disconnecting all stratum clients");
        for c in ratum::lock(&self.clients).iter() {
            c.kill.store(true, Ordering::Relaxed);
        }
    }

    pub fn kill_client(&self, unique_id: u64) -> bool {
        for c in ratum::lock(&self.clients).iter() {
            if ratum::lock(&c.stats).unique_id == unique_id {
                c.kill.store(true, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
}

/// Bind the listener and accept connections until the process ends. Called once a job
/// exists, as the C gateway does.
pub fn listen(server: Arc<Server>) -> io::Result<()> {
    let s = &server.config.stratum;
    let addr = if s.listen_addr.is_empty() {
        format!("[::]:{}", s.listen_port)
    } else {
        format!("{}:{}", s.listen_addr, s.listen_port)
    };
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) if s.listen_addr.is_empty() => {
            debug!("could not bind {addr} ({e}); binding IPv4 only");
            TcpListener::bind(format!("0.0.0.0:{}", s.listen_port))?
        }
        Err(e) => return Err(e),
    };
    info!("Stratum V1 Server Init complete: listening on {}", listener.local_addr()?);
    server.listening.store(true, Ordering::Relaxed);
    let mut last_reject_log = Instant::now() - Duration::from_secs(10);
    let mut rejected = 0u64;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if server.rejecting.load(Ordering::Relaxed) {
            rejected += 1;
            if last_reject_log.elapsed() >= Duration::from_secs(5) {
                warn!(
                    "Refusing stratum connections while the pool is unreachable and datum.pooled_mining_only is set ({rejected} refused)"
                );
                last_reject_log = Instant::now();
            }
            continue;
        }
        if server.connection_count() >= s.max_clients {
            debug!("refusing a connection: {} clients connected", s.max_clients);
            continue;
        }
        let server = Arc::clone(&server);
        std::thread::Builder::new()
            .name("stratum-client".into())
            .spawn(move || {
                if let Err(e) = Connection::run(server, stream) {
                    debug!("Stratum client connection closed. ({e})");
                }
            })
            .map_err(|e| {
                warn!("could not start a client thread: {e}");
                e
            })
            .ok();
    }
    Ok(())
}

struct Connection {
    server: Arc<Server>,
    entry: Arc<ClientEntry>,
    stream: TcpStream,
    remote: String,
    sid: u32,
    subscribed: bool,
    authorized: bool,
    username: String,
    useragent: String,
    vardiff: Vardiff,
    coinbase_selection: u8,
    /// The difficulty each job in the ring was served at to this connection.
    job_diffs: Vec<Option<u64>>,
    sent_generation: u64,
    connected: Instant,
    subscribed_at: Option<Instant>,
    last_accepted: Option<Instant>,
    /// Hashrate window.
    window_active: u64,
    window_started: Instant,
    fee: FeeMeter,
    next_idle_check: Instant,
}

impl Connection {
    fn run(server: Arc<Server>, stream: TcpStream) -> io::Result<()> {
        let remote = stream.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(READ_POLL))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let unique_id = server.next_unique_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(ClientEntry {
            kill: AtomicBool::new(false),
            stats: Mutex::new(ClientStats {
                remote: remote.clone(),
                unique_id,
                current_diff: server.config.stratum.vardiff_min,
                coinbase_selection: crate::coinbase::DEFAULT_TYPE,
                ..Default::default()
            }),
        });
        ratum::lock(&server.clients).push(Arc::clone(&entry));
        debug!("New Stratum client connected. {remote} ({unique_id})");
        let now = Instant::now();
        let mut c = Connection {
            server: Arc::clone(&server),
            entry: Arc::clone(&entry),
            stream,
            remote,
            // The C gateway packs a 22-bit client index and a thread id; here the connection
            // counter is the whole 32 bits, so two live connections never share extranonce1.
            sid: (unique_id as u32) ^ 0xB10C_F00D,
            subscribed: false,
            authorized: false,
            username: String::new(),
            useragent: String::new(),
            vardiff: Vardiff::new(
                vardiff::Params {
                    min: server.config.stratum.vardiff_min,
                    target_shares_min: server.config.stratum.vardiff_target_shares_min,
                    quickdiff_count: server.config.stratum.vardiff_quickdiff_count,
                    quickdiff_delta: server.config.stratum.vardiff_quickdiff_delta,
                },
                now,
            ),
            coinbase_selection: crate::coinbase::DEFAULT_TYPE,
            job_diffs: vec![None; MAX_JOBS],
            sent_generation: 0,
            connected: now,
            subscribed_at: None,
            last_accepted: None,
            window_active: 0,
            window_started: now,
            fee: FeeMeter::default(),
            next_idle_check: now + Duration::from_secs(10),
        };
        let result = c.serve();
        let mut clients = ratum::lock(&server.clients);
        clients.retain(|e| !Arc::ptr_eq(e, &entry));
        result
    }

    fn serve(&mut self) -> io::Result<()> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            if self.entry.kill.load(Ordering::Relaxed) {
                return Err(io::Error::other("kill request"));
            }
            if self.subscribed {
                let generation = ratum::lock(&self.server.jobs).generation;
                if generation != self.sent_generation {
                    self.send_current_job()?;
                }
            }
            self.idle_checks()?;
            self.update_stats();

            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() >= CLIENT_BUFFER {
                        return Err(io::Error::other(
                            "read buffer overrun before client command break",
                        ));
                    }
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                        let line = line.trim_end_matches('\r');
                        if let Err(why) = self.handle_line(line) {
                            return Err(io::Error::other(why));
                        }
                    }
                }
                Err(e)
                    if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn update_stats(&mut self) {
        let mut s = ratum::lock(&self.entry.stats);
        s.username = self.username.clone();
        s.useragent = self.useragent.clone();
        s.subscribed = self.subscribed;
        s.subscribed_at = self.subscribed_at;
        s.sid = self.sid;
        s.authorized = self.authorized;
        s.current_diff = self.vardiff.current;
        s.last_accepted = self.last_accepted;
        s.coinbase_selection = self.coinbase_selection;
        if self.window_started.elapsed() >= STAT_CYCLE {
            s.window_diff = self.window_active;
            s.window = self.window_started.elapsed();
            s.window_ended = Some(Instant::now());
            self.window_active = 0;
            self.window_started = Instant::now();
        }
    }

    fn idle_checks(&mut self) -> io::Result<()> {
        if Instant::now() < self.next_idle_check {
            return Ok(());
        }
        self.next_idle_check = Instant::now() + IDLE_CHECK_INTERVAL;
        let s = &self.server.config.stratum;
        let idle =
            |limit: u64, since: Instant| limit != 0 && since.elapsed() > Duration::from_secs(limit);
        let stats = ratum::lock(&self.entry.stats).clone();
        let reason = if !self.subscribed && idle(s.idle_timeout_no_subscribe, self.connected) {
            Some(("not subscribing", s.idle_timeout_no_subscribe))
        } else if self.subscribed
            && stats.accepted_count == 0
            && idle(s.idle_timeout_no_shares, self.connected)
        {
            Some(("submitting no accepted share", s.idle_timeout_no_shares))
        } else if self.subscribed
            && let Some(last) = self.last_accepted
            && idle(s.idle_timeout_max_last_work, last)
        {
            Some(("submitting no share", s.idle_timeout_max_last_work))
        } else {
            None
        };
        if let Some((what, secs)) = reason {
            debug!(
                "Kicking client {} ({}) for {what} for more than {secs} seconds",
                self.remote, self.username
            );
            return Err(io::Error::other(format!("idle: {what}")));
        }
        Ok(())
    }

    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.stream.write_all(line.as_bytes())?;
        self.stream.write_all(b"\n")
    }

    fn reply_result(&mut self, id: &str, result: Value) -> io::Result<()> {
        self.send_line(&format!("{{\"error\":null,\"id\":{id},\"result\":{result}}}"))
    }

    fn reply_error(&mut self, id: &str, r: Reject) -> io::Result<()> {
        self.send_line(&format!(
            "{{\"error\":[{},\"{}\",null],\"id\":{id},\"result\":null}}",
            r.0, r.1
        ))
    }

    /// Handle one request line. `Err` closes the connection.
    fn handle_line(&mut self, line: &str) -> Result<(), String> {
        if line.is_empty() {
            return Ok(());
        }
        if !line.starts_with('{') {
            return Err("request is not a JSON object".into());
        }
        let v: Value = serde_json::from_str(line).map_err(|e| format!("bad JSON: {e}"))?;
        let method = match v.get("method") {
            None => return Err("no method".into()),
            Some(Value::String(m)) if !m.is_empty() => m.clone(),
            Some(Value::String(_)) => return Err("empty method".into()),
            Some(_) => return Err("method is not a string".into()),
        };
        let id = match v.get("id") {
            None => return Err("no id".into()),
            Some(id) => id.to_string(),
        };
        if id.is_empty() || id.len() > MAX_REQUEST_ID_CHARS {
            return Err("id too long".into());
        }
        let Some(params) = v.get("params") else { return Err("no params".into()) };
        let r = match method.as_str() {
            "mining.subscribe" => self.on_subscribe(&id, params),
            "mining.authorize" => self.on_authorize(&id, params),
            "mining.configure" => self.on_configure(&id, params),
            "mining.submit" => self.on_submit(&id, params),
            _ => self.send_line(&format!(
                "{{\"error\":[-3,\"Method not found\",null],\"id\":{id},\"result\":null}}"
            )),
        };
        r.map_err(|e| e.to_string())
    }

    fn on_subscribe(&mut self, id: &str, params: &Value) -> io::Result<()> {
        if self.subscribed {
            return Ok(());
        }
        let s = &self.server.config.stratum;
        self.vardiff.current = s.vardiff_min;
        self.coinbase_selection = crate::coinbase::DEFAULT_TYPE;
        if let Some(ua) = params.get(0).and_then(Value::as_str) {
            self.useragent = ua
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || ". -_=@,|/:<>';".contains(*c))
                .take(127)
                .collect();
        }
        if s.fingerprint_miners && !self.useragent.is_empty() {
            let ua = self.useragent.as_str();
            if ua.starts_with("Antminer S21/") {
                self.coinbase_selection = 5;
            } else if ua.starts_with("PowerPlay-BM/") || ua.starts_with("xminer-1.") {
                self.coinbase_selection = 4;
            } else if ua.starts_with("whatsminer/v1") {
                self.coinbase_selection = 3;
            } else if ua.contains("bosminer-plus-tuner") {
                self.coinbase_selection = 5;
            } else if ua.starts_with("NiceHash/") {
                self.vardiff.current = 524_288;
                self.vardiff.forced_floor = 524_288;
                self.coinbase_selection = 1;
            } else if ua.starts_with("bitaxe") {
                self.coinbase_selection = 3;
            }
        }
        self.vardiff.current = self.vardiff.current.max(s.vardiff_min);
        let sid = format!("{:08x}", self.sid);
        self.reply_result(
            id,
            json!([
                [
                    ["mining.notify", format!("{sid}1")],
                    ["mining.set_difficulty", format!("{sid}2")]
                ],
                format!("00000000{sid}"),
                8
            ]),
        )?;
        self.send_difficulty()?;
        self.subscribed = true;
        self.subscribed_at = Some(Instant::now());
        self.vardiff.reset_snapshot(Instant::now());
        self.send_job(true, false)?;
        Ok(())
    }

    fn on_authorize(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let username = params.get(0).and_then(Value::as_str).unwrap_or("NULL");
        self.username = username.chars().take(191).collect();
        if self.server.config.stratum.require_address_username
            && !address::username_is_payable(username)
        {
            let shown: String = username
                .chars()
                .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
                .collect();
            info!(
                "Refusing authorization of \"{shown}\" from {}: stratum.require_address_username is set and the username does not begin with an address a coinbase output can pay.",
                self.remote
            );
            return self.send_line(&format!(
                "{{\"error\":[24,\"unauthorized-worker\",null],\"id\":{id},\"result\":false}}"
            ));
        }
        self.authorized = true;
        self.reply_result(id, Value::Bool(true))
    }

    fn on_configure(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let Some(list) = params.get(0).and_then(Value::as_array) else {
            return Err(io::Error::other("mining.configure without an extension list"));
        };
        if params.get(1).is_none() {
            return Err(io::Error::other("mining.configure without options"));
        }
        let mut result = serde_json::Map::new();
        for ext in list {
            match ext.as_str() {
                Some("version-rolling") => {
                    result.insert("version-rolling".into(), Value::Bool(false));
                }
                Some("minimum-difficulty") => {
                    result.insert("minimum-difficulty".into(), Value::Bool(false));
                }
                _ => {}
            }
        }
        self.reply_result(id, Value::Object(result))
    }

    fn send_difficulty(&mut self) -> io::Result<()> {
        let d = self.vardiff.mark_sent();
        self.send_line(&format!(
            "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{d}]}}"
        ))
    }

    fn pot_byte(&self, quickdiff: bool, global_index: u8) -> u8 {
        let diff = if quickdiff {
            self.vardiff.quickdiff_value
        } else {
            self.job_diffs[global_index as usize].unwrap_or(self.vardiff.last_sent.max(1))
        };
        target::floor_pot(diff)
    }

    /// Send the server's current job, with the clean flag its publication carries.
    fn send_current_job(&mut self) -> io::Result<()> {
        let (generation, clean, empty) = {
            let j = ratum::lock(&self.server.jobs);
            (j.generation, j.clean, j.empty)
        };
        self.sent_generation = generation;
        self.send_job(clean, empty)
    }

    fn send_job(&mut self, clean: bool, new_block: bool) -> io::Result<()> {
        let Some(job) = self.server.current_job() else { return Ok(()) };
        self.sent_generation = ratum::lock(&self.server.jobs).generation;
        self.notify(&job, clean, false, new_block)
    }

    fn notify(
        &mut self,
        job: &Arc<Job>,
        clean: bool,
        quickdiff: bool,
        new_block: bool,
    ) -> io::Result<()> {
        let quickdiff = quickdiff && !new_block;
        if !quickdiff {
            // With `no_quick` the update never requests a quick raise.
            self.vardiff.update(true, Instant::now());
        }
        let pool_min = self.server.datum.min_difficulty();
        if job.is_datum_job && self.vardiff.current < pool_min {
            self.vardiff.current = pool_min;
        }
        if self.vardiff.last_sent != self.vardiff.current {
            self.send_difficulty()?;
        }
        let g = job.global_index as usize;
        if !quickdiff {
            self.job_diffs[g] = Some(self.vardiff.last_sent);
            self.vardiff.quickdiff_active = false;
        } else {
            self.vardiff.quickdiff_active = true;
            self.vardiff.quickdiff_value = self.vardiff.last_sent;
        }
        let cb_select = if new_block { COINBASE_SUBSIDY_ONLY } else { self.coinbase_selection };
        let job_id = if quickdiff {
            format!("Q{}{cb_select:02x}", job.job_id)
        } else if new_block {
            format!("N{}ff", job.job_id)
        } else {
            format!("{}{cb_select:02x}", job.job_id)
        };
        let pot = self.pot_byte(quickdiff, job.global_index);
        let Some(commitment) = job.commitment(cb_select, pot) else {
            return Err(io::Error::other("job has no coinbase for the selection"));
        };
        let clean_flag = clean || quickdiff || new_block;
        let line = format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"{job_id}\",\"{}\",\"000000{}\",\"\",[],\"\",\"{}\",\"{}\",{clean_flag}]}}",
            hex::encode(job.prevblock_hidden),
            hex::encode(commitment.h2),
            job.template.bits,
            job.ntime_hex,
        );
        self.send_line(&line)
    }

    fn count_rejected(&mut self, diff: u64) {
        let mut st = ratum::lock(&self.entry.stats);
        st.rejected_count += 1;
        st.rejected_diff = st.rejected_diff.saturating_add(diff);
    }

    fn on_submit(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let fallback_diff = self.vardiff.last_sent;
        match self.check_submit(params) {
            Ok(diff) => {
                self.reply_result(id, Value::Bool(true))?;
                {
                    let mut st = ratum::lock(&self.entry.stats);
                    st.accepted_count += 1;
                    st.accepted_diff = st.accepted_diff.saturating_add(diff);
                }
                self.vardiff.count_share();
                self.window_active = self.window_active.saturating_add(diff);
                self.last_accepted = Some(Instant::now());
                // A quick raise is announced at once with a `Q` job.
                if self.vardiff.update(false, Instant::now())
                    && let Some(job) = self.server.current_job()
                {
                    self.notify(&job, true, true, false)?;
                }
                Ok(())
            }
            Err((reject, diff)) => {
                self.count_rejected(diff.unwrap_or(fallback_diff));
                self.reply_error(id, reject)
            }
        }
    }

    /// Check a share and forward it; returns the job difficulty credited or the rejection
    /// with the difficulty to count it under.
    fn check_submit(&mut self, params: &Value) -> Result<u64, (Reject, Option<u64>)> {
        let job_id_param = params.get(1).and_then(Value::as_str).ok_or((UNKNOWN_WORK, None))?;
        let (job_id, quickdiff, empty_work) = match job_id_param.len() {
            16 => (job_id_param, false, false),
            17 if job_id_param.starts_with('Q') => (&job_id_param[1..], true, false),
            17 if job_id_param.starts_with('N') => (&job_id_param[1..], false, true),
            _ => return Err((UNKNOWN_WORK, None)),
        };
        let global_index = crate::job::global_index_of(job_id).ok_or((UNKNOWN_WORK, None))?;
        let job = ratum::lock(&self.server.jobs).ring[global_index as usize]
            .clone()
            .ok_or((UNKNOWN_WORK, None))?;
        if job.job_id.get(..8) != job_id.get(..8) {
            return Err((UNKNOWN_WORK, None));
        }
        let job_diff = if quickdiff {
            self.vardiff.quickdiff_value
        } else {
            self.job_diffs[global_index as usize].ok_or((UNKNOWN_WORK, None))?
        };
        let rejected = |r: Reject| (r, Some(job_diff));

        let en2 = params.get(2).and_then(Value::as_str).ok_or(rejected(UNKNOWN_WORK))?;
        if en2.len() != 16 {
            return Err(rejected(UNKNOWN_WORK));
        }
        let en2 = hex::decode(en2).map_err(|_| rejected(UNKNOWN_WORK))?;
        let mut extranonce = [0u8; 16];
        extranonce[4..8].copy_from_slice(&self.sid.to_be_bytes());
        extranonce[8..].copy_from_slice(&en2);

        let coinbase_index =
            u8::from_str_radix(&job_id[14..16], 16).map_err(|_| rejected(UNKNOWN_WORK))?;
        if empty_work {
            if coinbase_index != COINBASE_SUBSIDY_ONLY {
                return Err(rejected(UNKNOWN_WORK));
            }
        } else if coinbase_index as usize >= job.coinbases.len() {
            return Err(rejected(UNKNOWN_WORK));
        }

        let parse8 = |s: &str| -> Option<[u8; 8]> {
            match s.len() {
                16 => hex::decode(s).ok()?.try_into().ok(),
                8 => {
                    let v = u32::from_str_radix(s, 16).ok()?;
                    let mut out = [0u8; 8];
                    out[..4].copy_from_slice(&v.to_le_bytes());
                    Some(out)
                }
                _ => None,
            }
        };
        let ntime =
            params.get(3).and_then(Value::as_str).and_then(parse8).ok_or(rejected(UNKNOWN_WORK))?;
        let nonce =
            params.get(4).and_then(Value::as_str).and_then(parse8).ok_or(rejected(UNKNOWN_WORK))?;

        let pot = self.pot_byte(quickdiff, global_index);
        let header = job
            .header(coinbase_index, pot, extranonce, nonce, ntime)
            .ok_or(rejected(UNKNOWN_WORK))?;
        let header_bytes = header.serialize();
        let hash = header.hash_components().result;

        // `miner_username` is what the miner sent; `username` is who the share is credited
        // to once a `~modifier` has been applied. stratum.require_address_username checks
        // the miner's own username, as the C gateway does, not the address its modifier names.
        let miner_username = params.get(0).and_then(Value::as_str).unwrap_or("NULL").to_string();
        let cfg = &self.server.config;
        let username = username::apply_modifier(
            &cfg.stratum.username_modifiers,
            &cfg.mining.pool_address,
            &miner_username,
            &hash,
        )
        .unwrap_or_else(|| miner_username.clone());

        let is_block = target::meets_target(&hash, &job.block_target);
        if is_block {
            let display = hex::encode(hash);
            for _ in 0..3 {
                warn!("******** BLOCK FOUND - {display} ********");
            }
            self.submit_block(&job, coinbase_index, pot, &header_bytes, &display);
        }

        let checked = self.check_share(&job, &hash, pot, &miner_username);
        // A block reaches the pool whatever the checks said: under the miner's own name when
        // a check refused it (the C gateway's attribution), and through the fee accounting
        // like any accepted share when they passed.
        if job.is_datum_job && (is_block || checked.is_ok()) {
            let wire_username = if checked.is_ok() {
                self.fee_username(&username, job_diff)
            } else {
                username.clone()
            };
            self.server.datum.submit(QueuedShare {
                job: Arc::clone(&job),
                coinbase_id: coinbase_index,
                is_block,
                subsidy_only: empty_work,
                quickdiff,
                target_byte: pot,
                header: header_bytes,
                username: wire_username,
            });
        }
        checked.map_err(rejected)?;
        Ok(job_diff)
    }

    /// The checks an accepted share passes, in the C gateway's order.
    fn check_share(
        &self,
        job: &Arc<Job>,
        hash: &[u8; 32],
        pot: u8,
        username: &str,
    ) -> Result<(), Reject> {
        let cfg = &self.server.config;
        if job.is_stale_prevblock() {
            return Err(STALE_PREVBLK);
        }
        if !target::meets_target(hash, &target::target_for_pot(pot)) {
            return Err(HIGH_HASH);
        }
        let stale =
            Duration::from_secs(cfg.stratum.share_stale_seconds + cfg.bitcoind.work_update_seconds);
        if job.created.elapsed() > stale {
            return Err(STALE_WORK);
        }
        if !ratum::lock(&self.server.dupes).insert(*hash, job.created) {
            return Err(DUPLICATE);
        }
        if cfg.stratum.require_address_username && !address::username_is_payable(username) {
            return Err(UNAUTHORIZED_WORKER);
        }
        Ok(())
    }

    fn submit_block(
        &self,
        job: &Arc<Job>,
        coinbase_index: u8,
        pot: u8,
        header: &[u8; 164],
        hash_hex: &str,
    ) {
        let Some(block) = crate::submit::assemble(job, coinbase_index, pot, header) else {
            error!("could not assemble the block for {hash_hex}");
            return;
        };
        debug!("Block Payload: {}", hex::encode(&block));
        let block = Arc::new(block);
        let cfg = &self.server.config;
        // The C gateway's order: its submitblock thread first (a second submission to the
        // node on its own connection, then the extra nodes), the file, then the submission
        // on this thread.
        crate::submit::submit_redundant(
            self.server.node.clone(),
            self.server.extra_nodes.clone(),
            Arc::clone(&block),
            hash_hex.to_string(),
            Arc::clone(&self.server.notify),
        );
        if !cfg.mining.save_submitblocks_dir.is_empty() {
            crate::submit::save_to_dir(&cfg.mining.save_submitblocks_dir, hash_hex, &block);
        }
        let accepted =
            crate::submit::submit_to(&self.server.node, "upstream node", &block, hash_hex);
        if accepted {
            // The submitted block is the new tip; the template thread compares the hash.
            self.server.notify.raise_for(hash_hex);
        }
    }

    /// The username a pooled share is sent under: the fee address for the share the fee
    /// meter names (`stratum_fee_username`), the miner's otherwise.
    fn fee_username(&mut self, username: &str, diff: u64) -> String {
        let cfg = &self.server.config;
        let charged = self.fee.charge(diff, u64::from(cfg.datum.gateway_fee_bps), || {
            let mut b = [0u8; 8];
            dryoc::rng::copy_randombytes(&mut b);
            u64::from_le_bytes(b)
        });
        if !charged {
            return username.to_string();
        }
        {
            let mut st = ratum::lock(&self.entry.stats);
            st.fee_count += 1;
            st.fee_diff = st.fee_diff.saturating_add(diff);
        }
        self.server.fee_share_count.fetch_add(1, Ordering::Relaxed);
        self.server.fee_share_diff.fetch_add(diff, Ordering::Relaxed);
        cfg.fee_address().to_string()
    }
}
