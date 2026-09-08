use crate::coinbase::COINBASE_POOLED;
use crate::config::Config;
use crate::datum::{self, QueuedShare};
use crate::dupes::Dupes;
use crate::job::{
    COINBASE_SUBSIDY_ONLY, JOB_ID_TIME_CHARS, Job, JobRef, MAX_JOBS, SIA_FIELD_SIZE,
    parse_sia_field,
};
use crate::tally::{FeeMeter, Tally};
use crate::username;
use crate::vardiff::{self, Vardiff};
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::share::{
    EXTRANONCE_SIZE_V2, EXTRANONCE_V2_PAD, EXTRANONCE1_SIZE, EXTRANONCE2_SIZE,
};
use ratum::poll::PolledSocket;
use ratum::target;
use serde_json::{Value, json};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CLIENT_BUFFER: usize = 16384 * 3 + 1024;
const MAX_REQUEST_ID_CHARS: usize = 64;
const MAX_USER_AGENT_CHARS: usize = 127;
const MAX_USERNAME_CHARS: usize = 191;
const NICEHASH_MIN_DIFFICULTY: u64 = 524_288;
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(11150);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const STAT_CYCLE: Duration = Duration::from_secs(60);
const HASHRATE_WINDOW_VALID: Duration = Duration::from_secs(3 * ratum::SECS_PER_MINUTE);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(5);
const FIRST_IDLE_CHECK_DELAY: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 4096;
const DIFF_TO_THS: f64 = ratum::HASHES_PER_DIFFICULTY / ratum::HASHES_PER_TERAHASH;
const SESSION_ID_XOR: u32 = 0xB10C_F00D;
const BLOCK_FOUND_LOG_LINES: usize = 3;

#[derive(Clone, Copy)]
struct Reject(i64, &'static str);

const UNKNOWN_WORK: Reject = Reject(20, "unknown-work");
const STALE_WORK: Reject = Reject(21, "stale-work");
const STALE_PREVBLK: Reject = Reject(21, "stale-prevblk");
const DUPLICATE: Reject = Reject(22, "duplicate");
const HIGH_HASH: Reject = Reject(23, "high-hash");
const UNAUTHORIZED_WORKER: Reject = Reject(24, "unauthorized-worker");
const METHOD_NOT_FOUND: Reject = Reject(-3, "Method not found");

#[derive(Debug, thiserror::Error)]
enum Disconnect {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("idle: {0}")]
    Idle(&'static str),
    #[error("kill request")]
    Killed,
}

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
    waker: Arc<Waker>,
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
    pub datum: Arc<datum::Shared>,
    pub node: ratum::rpc::Client,
    pub notify: Arc<crate::template::Notify>,
    pub jobs: Mutex<Jobs>,
    generation: AtomicU64,
    clients: Mutex<Vec<Arc<ClientEntry>>>,
    dupes: Mutex<Dupes>,
    next_unique_id: AtomicU64,
    pub rejecting: AtomicBool,
    pub fee: Mutex<Tally>,
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
        Arc::new(Server {
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

    fn current_for_send(&self) -> (Option<Arc<Job>>, bool, u64) {
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
    let mut listener = None;
    let mut last = io::Error::other("no address to bind");
    for addr in ratum::http::bind_candidates(&s.listen_addr, s.listen_port) {
        match TcpListener::bind(&addr) {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) => {
                debug!("could not bind {addr} ({e})");
                last = e;
            }
        }
    }
    let listener = listener.ok_or(last)?;
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
        let spawned = std::thread::Builder::new().name("stratum-client".into()).spawn(move || {
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

struct SubmitRequest {
    job: Arc<Job>,
    job_diff: u64,
    job_ref: JobRef,
    extranonce: [u8; EXTRANONCE_SIZE_V2],
    ntime: [u8; SIA_FIELD_SIZE],
    nonce: [u8; SIA_FIELD_SIZE],
    miner_username: String,
}

struct Connection {
    server: Arc<Server>,
    entry: Arc<ClientEntry>,
    socket: PolledSocket,
    remote: String,
    sid: u32,
    subscribed: bool,
    authorized: bool,
    username: String,
    vardiff: Vardiff,
    job_diffs: Vec<Option<u64>>,
    sent_generation: u64,
    connected: Instant,
    last_accepted: Option<Instant>,
    window_active: u64,
    window_started: Instant,
    fee: FeeMeter,
    next_idle_check: Instant,
}

impl Connection {
    fn run(server: Arc<Server>, stream: TcpStream) -> Result<(), Disconnect> {
        let remote = stream.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
        stream.set_nodelay(true)?;
        let socket = PolledSocket::new(stream)?;
        let waker = Arc::new(socket.waker()?);
        let unique_id = server.next_unique_id.fetch_add(1, Ordering::Relaxed);
        let sid = (unique_id as u32) ^ SESSION_ID_XOR;
        let entry = Arc::new(ClientEntry {
            kill: AtomicBool::new(false),
            waker,
            stats: Mutex::new(ClientStats {
                remote: remote.clone(),
                unique_id,
                current_diff: server.config.stratum.vardiff_min,
                ..Default::default()
            }),
        });
        ratum::lock(&server.clients).push(Arc::clone(&entry));
        debug!("New Stratum client connected. {remote} ({unique_id})");
        let now = Instant::now();
        let s = &server.config.stratum;
        let mut c = Connection {
            entry: Arc::clone(&entry),
            socket,
            remote,
            sid,
            subscribed: false,
            authorized: false,
            username: String::new(),
            vardiff: Vardiff::new(
                vardiff::Params {
                    min: s.vardiff_min,
                    target_shares_min: s.vardiff_target_shares_min,
                    quickdiff_count: s.vardiff_quickdiff_count,
                    quickdiff_delta: s.vardiff_quickdiff_delta,
                },
                now,
            ),
            job_diffs: vec![None; MAX_JOBS],
            sent_generation: 0,
            connected: now,
            last_accepted: None,
            window_active: 0,
            window_started: now,
            fee: FeeMeter::default(),
            next_idle_check: now + FIRST_IDLE_CHECK_DELAY,
            server: Arc::clone(&server),
        };
        let result = c.serve();
        ratum::lock(&server.clients).retain(|e| !Arc::ptr_eq(e, &entry));
        debug!("Stratum client connection closed. ({:?})", result.as_ref().err());
        result
    }

    fn serve(&mut self) -> Result<(), Disconnect> {
        let mut buf = Vec::with_capacity(READ_CHUNK);
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if self.entry.kill.load(Ordering::Relaxed) {
                return Err(Disconnect::Killed);
            }
            if self.subscribed
                && self.server.generation.load(Ordering::Acquire) != self.sent_generation
            {
                self.send_current_job()?;
            }
            self.idle_checks()?;
            self.roll_window();

            if !self.socket.readable() {
                let timeout = self.until_next_check();
                self.socket.wait(Some(timeout))?;
                continue;
            }
            match self.socket.read(&mut chunk)? {
                Some(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Some(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() >= CLIENT_BUFFER {
                        return Err(Disconnect::Protocol(
                            "read buffer overrun before client command break".into(),
                        ));
                    }
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                        self.handle_line(line.trim_end_matches('\r'))?;
                    }
                }
                None => {}
            }
        }
    }

    fn until_next_check(&self) -> Duration {
        let due = self.next_idle_check.min(self.window_started + STAT_CYCLE);
        due.saturating_duration_since(Instant::now())
    }

    fn with_stats(&self, f: impl FnOnce(&mut ClientStats)) {
        f(&mut ratum::lock(&self.entry.stats));
    }

    fn roll_window(&mut self) {
        if self.window_started.elapsed() < STAT_CYCLE {
            return;
        }
        let (diff, window) = (self.window_active, self.window_started.elapsed());
        self.with_stats(|s| {
            s.window_diff = diff;
            s.window = window;
            s.window_ended = Some(Instant::now());
        });
        self.window_active = 0;
        self.window_started = Instant::now();
    }

    fn idle_checks(&mut self) -> Result<(), Disconnect> {
        if Instant::now() < self.next_idle_check {
            return Ok(());
        }
        self.next_idle_check = Instant::now() + IDLE_CHECK_INTERVAL;
        let s = &self.server.config.stratum;
        let idle =
            |limit: u64, since: Instant| limit != 0 && since.elapsed() > Duration::from_secs(limit);
        let accepted = ratum::lock(&self.entry.stats).accepted.count;
        let reason = if !self.subscribed && idle(s.idle_timeout_no_subscribe, self.connected) {
            Some(("not subscribing", s.idle_timeout_no_subscribe))
        } else if self.subscribed && accepted == 0 && idle(s.idle_timeout_no_shares, self.connected)
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
            return Err(Disconnect::Idle(what));
        }
        Ok(())
    }

    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.socket.write_all(line.as_bytes(), WRITE_TIMEOUT)?;
        self.socket.write_all(b"\n", WRITE_TIMEOUT)
    }

    fn reply(&mut self, id: &str, error: Option<Reject>, result: Value) -> io::Result<()> {
        let error = match error {
            Some(Reject(code, text)) => format!("[{code},\"{text}\",null]"),
            None => "null".to_string(),
        };
        self.send_line(&format!("{{\"error\":{error},\"id\":{id},\"result\":{result}}}"))
    }

    fn reply_result(&mut self, id: &str, result: Value) -> io::Result<()> {
        self.reply(id, None, result)
    }

    fn reply_error(&mut self, id: &str, r: Reject) -> io::Result<()> {
        self.reply(id, Some(r), Value::Null)
    }

    fn handle_line(&mut self, line: &str) -> Result<(), Disconnect> {
        if line.is_empty() {
            return Ok(());
        }
        let bad = |why: &str| Disconnect::Protocol(why.to_string());
        if !line.starts_with('{') {
            return Err(bad("request is not a JSON object"));
        }
        let v: Value = serde_json::from_str(line).map_err(|e| bad(&format!("bad JSON: {e}")))?;
        let method = match v.get("method") {
            None => return Err(bad("no method")),
            Some(Value::String(m)) if !m.is_empty() => m.clone(),
            Some(Value::String(_)) => return Err(bad("empty method")),
            Some(_) => return Err(bad("method is not a string")),
        };
        let id = match v.get("id") {
            None => return Err(bad("no id")),
            Some(id) => id.to_string(),
        };
        if id.is_empty() || id.len() > MAX_REQUEST_ID_CHARS {
            return Err(bad("id too long"));
        }
        let Some(params) = v.get("params") else { return Err(bad("no params")) };
        match method.as_str() {
            "mining.subscribe" => self.on_subscribe(&id, params)?,
            "mining.authorize" => self.on_authorize(&id, params)?,
            "mining.configure" => self.on_configure(&id, params)?,
            "mining.submit" => self.on_submit(&id, params)?,
            _ => self.reply_error(&id, METHOD_NOT_FOUND)?,
        }
        Ok(())
    }

    fn on_subscribe(&mut self, id: &str, params: &Value) -> io::Result<()> {
        if self.subscribed {
            return Ok(());
        }
        let s = &self.server.config.stratum;
        let useragent: String =
            params.get(0).and_then(Value::as_str).map_or_else(String::new, |ua| {
                ua.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || ". -_=@,|/:<>';".contains(*c))
                    .take(MAX_USER_AGENT_CHARS)
                    .collect()
            });
        if s.fingerprint_miners && useragent.starts_with("NiceHash/") {
            self.vardiff.raise_floor(NICEHASH_MIN_DIFFICULTY);
        }
        let sid = format!("{:08x}", self.sid);
        let pad = "0".repeat(2 * EXTRANONCE_V2_PAD);
        self.reply_result(
            id,
            json!([
                [
                    ["mining.notify", format!("{sid}1")],
                    ["mining.set_difficulty", format!("{sid}2")]
                ],
                format!("{pad}{sid}"),
                EXTRANONCE2_SIZE
            ]),
        )?;
        self.send_difficulty()?;
        self.subscribed = true;
        self.with_stats(|st| {
            st.useragent = useragent;
            st.subscribed = true;
            st.subscribed_at = Some(Instant::now());
        });
        self.vardiff.reset_snapshot(Instant::now());
        let (job, _, generation) = self.server.current_for_send();
        self.sent_generation = generation;
        if let Some(job) = job {
            self.notify(&job, true, false, false)?;
        }
        Ok(())
    }

    fn on_authorize(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let username = params.get(0).and_then(Value::as_str).unwrap_or("NULL");
        self.username = username.chars().take(MAX_USERNAME_CHARS).collect();
        let name = self.username.clone();
        self.with_stats(|st| st.username = name);
        if self.server.config.stratum.require_address_username && !username::is_payable(username) {
            let shown: String = username
                .chars()
                .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
                .collect();
            info!(
                "Refusing authorization of \"{shown}\" from {}: stratum.require_address_username is set and the username does not begin with an address a coinbase output can pay.",
                self.remote
            );
            return self.reply(id, Some(UNAUTHORIZED_WORKER), Value::Bool(false));
        }
        self.authorized = true;
        self.reply_result(id, Value::Bool(true))
    }

    fn on_configure(&mut self, id: &str, params: &Value) -> Result<(), Disconnect> {
        let Some(list) = params.get(0).and_then(Value::as_array) else {
            return Err(Disconnect::Protocol("mining.configure without an extension list".into()));
        };
        if params.get(1).is_none() {
            return Err(Disconnect::Protocol("mining.configure without options".into()));
        }
        let mut result = serde_json::Map::new();
        for ext in list {
            if let Some(name @ ("version-rolling" | "minimum-difficulty")) = ext.as_str() {
                result.insert(name.into(), Value::Bool(false));
            }
        }
        Ok(self.reply_result(id, Value::Object(result))?)
    }

    fn send_difficulty(&mut self) -> io::Result<()> {
        let d = self.vardiff.mark_sent();
        self.with_stats(|st| st.current_diff = d);
        self.send_line(&format!(
            "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{d}]}}"
        ))
    }

    fn served_diff(&self, r: &JobRef) -> Option<u64> {
        if r.quickdiff {
            Some(self.vardiff.quickdiff_value())
        } else {
            self.job_diffs[r.global_index as usize]
        }
    }

    fn send_current_job(&mut self) -> io::Result<()> {
        let (job, empty, generation) = self.server.current_for_send();
        self.sent_generation = generation;
        match job {
            Some(job) => self.notify(&job, empty, false, empty),
            None => Ok(()),
        }
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
            self.vardiff.update(true, Instant::now());
        }
        if job.is_datum_job {
            self.vardiff.hold_at_least(self.server.datum.min_difficulty());
        }
        if self.vardiff.change_pending() {
            self.send_difficulty()?;
        }
        let diff = self.vardiff.job_sent(quickdiff);
        if !quickdiff {
            self.job_diffs[job.global_index as usize] = Some(diff);
        }
        let r = JobRef {
            global_index: job.global_index,
            quickdiff,
            empty: new_block,
            coinbase: if new_block { COINBASE_SUBSIDY_ONLY } else { COINBASE_POOLED },
        };
        let pot = target::floor_pot(diff.max(1));
        let Some(commitment) = job.commitment(r.coinbase, pot) else {
            return Err(io::Error::other("job has no coinbase for the selection"));
        };
        let clean_flag = clean || quickdiff || new_block;
        let coinb1 = format!(
            "{}{}",
            "00".repeat(ratum::header::COINB1_LEADING_ZEROS),
            hex::encode(commitment.h2)
        );
        let line = format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"{}\",\"{}\",\"{coinb1}\",\"\",[],\"\",\"{:08x}\",\"{}\",{clean_flag}]}}",
            r.notify_id(job),
            hex::encode(job.prevblock_hidden),
            target::share_nbits(pot),
            job.ntime_hex,
        );
        self.send_line(&line)
    }

    fn on_submit(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let req = match self.parse_submit(params) {
            Ok(req) => req,
            Err((reject, diff)) => {
                let diff = diff.unwrap_or(self.vardiff.last_sent());
                self.with_stats(|st| st.rejected.add(diff));
                return self.reply_error(id, reject);
            }
        };
        let diff = req.job_diff;
        match self.evaluate(&req) {
            Ok(()) => {
                self.reply_result(id, Value::Bool(true))?;
                self.with_stats(|st| {
                    st.accepted.add(diff);
                    st.last_accepted = Some(Instant::now());
                });
                self.vardiff.count_share();
                self.window_active = self.window_active.saturating_add(diff);
                self.last_accepted = Some(Instant::now());
                if self.vardiff.update(false, Instant::now())
                    && let Some(job) = self.server.current_job()
                {
                    self.notify(&job, true, true, false)?;
                }
                Ok(())
            }
            Err(reject) => {
                self.with_stats(|st| st.rejected.add(diff));
                self.reply_error(id, reject)
            }
        }
    }

    fn parse_submit(&self, params: &Value) -> Result<SubmitRequest, (Reject, Option<u64>)> {
        let unknown = (UNKNOWN_WORK, None);
        let id_param = params.get(1).and_then(Value::as_str).ok_or(unknown)?;
        let (job_ref, job_id) = JobRef::parse(id_param).ok_or(unknown)?;
        let job = ratum::lock(&self.server.jobs).ring[job_ref.global_index as usize]
            .clone()
            .ok_or(unknown)?;
        if job.job_id.get(..JOB_ID_TIME_CHARS) != job_id.get(..JOB_ID_TIME_CHARS) {
            return Err(unknown);
        }
        let job_diff = self.served_diff(&job_ref).ok_or(unknown)?;
        let rejected = (UNKNOWN_WORK, Some(job_diff));

        let en2 = params.get(2).and_then(Value::as_str).ok_or(rejected)?;
        if en2.len() != 2 * EXTRANONCE2_SIZE {
            return Err(rejected);
        }
        let en2 = hex::decode(en2).map_err(|_| rejected)?;
        let mut extranonce = [0u8; EXTRANONCE_SIZE_V2];
        let sid_at = EXTRANONCE_V2_PAD;
        let en2_at = EXTRANONCE1_SIZE;
        extranonce[sid_at..en2_at].copy_from_slice(&self.sid.to_be_bytes());
        extranonce[en2_at..].copy_from_slice(&en2);
        if !job_ref.empty && job_ref.coinbase != COINBASE_POOLED {
            return Err(rejected);
        }
        let ntime =
            params.get(3).and_then(Value::as_str).and_then(parse_sia_field).ok_or(rejected)?;
        let nonce =
            params.get(4).and_then(Value::as_str).and_then(parse_sia_field).ok_or(rejected)?;
        let miner_username = params.get(0).and_then(Value::as_str).unwrap_or("NULL").to_string();
        Ok(SubmitRequest { job, job_diff, job_ref, extranonce, ntime, nonce, miner_username })
    }

    fn evaluate(&mut self, req: &SubmitRequest) -> Result<(), Reject> {
        let job = &req.job;
        let r = req.job_ref;
        let pot = target::floor_pot(req.job_diff);
        let header = job
            .header(r.coinbase, pot, req.extranonce, req.nonce, req.ntime)
            .ok_or(UNKNOWN_WORK)?;
        let hash = job.share_pow_hash(&header);
        let is_block = job.abw.is_none() && target::meets_target(&hash, &job.block_target);
        if is_block {
            let display = hex::encode(hash);
            for _ in 0..BLOCK_FOUND_LOG_LINES {
                warn!("******** BLOCK FOUND - {display} ********");
            }
            self.submit_block(job, r.coinbase, pot, &header.serialize(), &display);
        }

        let checked = self.check_share(job, &hash, pot, &req.miner_username);
        if job.is_datum_job && (is_block || checked.is_ok()) {
            let wire_username = if checked.is_ok() && self.fee_charged(req.job_diff) {
                self.server.config.fee_address().to_string()
            } else {
                let cfg = &self.server.config;
                username::apply_modifier(
                    &cfg.stratum.username_modifiers,
                    &cfg.mining.pool_address,
                    &req.miner_username,
                    &hash,
                )
                .unwrap_or_else(|| req.miner_username.clone())
            };
            self.server.datum.submit(QueuedShare {
                job: Arc::clone(job),
                coinbase_id: r.coinbase,
                is_block,
                subsidy_only: r.empty,
                quickdiff: r.quickdiff,
                target_byte: pot,
                header,
                username: wire_username,
            });
        }
        checked
    }

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
        if job.created.elapsed() > cfg.stale_window() {
            return Err(STALE_WORK);
        }
        if !ratum::lock(&self.server.dupes).insert(*hash, job.created) {
            return Err(DUPLICATE);
        }
        if cfg.stratum.require_address_username && !username::is_payable(username) {
            return Err(UNAUTHORIZED_WORKER);
        }
        Ok(())
    }

    fn submit_block(
        &self,
        job: &Arc<Job>,
        coinbase_index: u8,
        pot: u8,
        header: &[u8; ratum::header::HEADER_V2_SIZE],
        hash_hex: &str,
    ) {
        let Some(block) = crate::submit::assemble(job, coinbase_index, pot, header) else {
            error!("could not assemble the block for {hash_hex}");
            return;
        };
        debug!("Block Payload: {}", hex::encode(&block));
        let block = Arc::new(block);
        let cfg = &self.server.config;
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
            self.server.notify.raise_for(hash_hex);
        }
    }

    fn fee_charged(&mut self, diff: u64) -> bool {
        let bps = u64::from(self.server.config.datum.gateway_fee_bps);
        let charged = self.fee.charge(diff, bps, ratum::rand::u64);
        if charged {
            self.with_stats(|st| st.fee.add(diff));
            ratum::lock(&self.server.fee).add(diff);
        }
        charged
    }
}
