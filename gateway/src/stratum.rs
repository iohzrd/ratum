//! The Stratum v1 server, Siacoin dialect, serving version 2 headers. One thread per
//! connection; the messages and their formats are the C gateway's (`datum_stratum.c`).
//!
//! Each connection thread blocks in `mio::Poll` on its socket and on a `mio::Waker`. The
//! waker is called when a job is published and when a kill request is made, so the thread
//! reads the server's generation counter and `ClientEntry::kill` at once rather than at a
//! read timeout. The remaining timeouts are the idle checks and the hashrate window.

use crate::address;
use crate::coinbase::COINBASE_POOLED;
use crate::config::Config;
use crate::datum::{self, QueuedShare};
use crate::dupes::Dupes;
use crate::job::{COINBASE_SUBSIDY_ONLY, Job, JobRef, MAX_JOBS, parse_sia_field};
use crate::tally::Tally;
use crate::username::{self, FeeMeter};
use crate::vardiff::{self, Vardiff};
use log::{debug, error, info, warn};
use mio::net::TcpStream as PolledStream;
use mio::{Events, Interest, Poll, Token, Waker};
use ratum::target;
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CLIENT_BUFFER: usize = 16384 * 3 + 1024;
const MAX_REQUEST_ID_CHARS: usize = 64;
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(11150);
/// How long a write waits for the socket to take the rest of the line before it fails with
/// `TimedOut`.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// The connection's socket in its `Poll`.
const SOCKET: Token = Token(0);
/// The `Waker` a new job or a kill request calls.
const WAKE: Token = Token(1);
const STAT_CYCLE: Duration = Duration::from_secs(60);
/// Difficulty to TH/s: `diff * 2^32 / 1e12` per second.
const DIFF_TO_THS: f64 = 0.004294967296;

/// A stratum error: the code and the text of the `error` array.
#[derive(Clone, Copy)]
struct Reject(i64, &'static str);

const UNKNOWN_WORK: Reject = Reject(20, "unknown-work");
const STALE_WORK: Reject = Reject(21, "stale-work");
const STALE_PREVBLK: Reject = Reject(21, "stale-prevblk");
const DUPLICATE: Reject = Reject(22, "duplicate");
const HIGH_HASH: Reject = Reject(23, "high-hash");
const UNAUTHORIZED_WORKER: Reject = Reject(24, "unauthorized-worker");
const METHOD_NOT_FOUND: Reject = Reject(-3, "Method not found");

/// Why a connection was closed.
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

/// The jobs the server holds: the ring by global index and the one new connections get.
#[derive(Default)]
pub struct Jobs {
    pub ring: Vec<Option<Arc<Job>>>,
    pub current: Option<Arc<Job>>,
    /// Whether the current job is new-block empty work (subsidy-only coinbase), sent with
    /// `clean_jobs`.
    pub empty: bool,
}

/// Per-connection statistics, for the API. Written by the connection at the events that
/// change them.
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
    /// Wakes the connection thread out of `Poll::poll`, so that it reads `kill` and the
    /// server's generation counter without waiting for its next timed check.
    waker: Arc<Waker>,
}

impl ClientEntry {
    /// Wake the connection thread. A failed write to the waker only delays that thread
    /// until its next timed check, so it is logged and not propagated.
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            debug!("could not wake a stratum connection thread: {e}");
        }
    }

    /// Set the kill flag and wake the connection thread, which then returns `Killed`.
    fn request_kill(&self) {
        self.kill.store(true, Ordering::Relaxed);
        self.wake();
    }
}

/// What one pass over the client list yields.
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
    /// Counts publications; a connection compares it with the one it last sent.
    generation: AtomicU64,
    clients: Mutex<Vec<Arc<ClientEntry>>>,
    dupes: Mutex<Dupes>,
    next_unique_id: AtomicU64,
    /// Set while `pooled_mining_only` and the pool is not connected: connections are refused.
    pub rejecting: AtomicBool,
    /// The shares credited to the fee address.
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
        j.empty = empty;
        self.generation.fetch_add(1, Ordering::Release);
        drop(j);
        // Each connection thread compares the counter after its waker returns it from
        // `Poll::poll`, so the job reaches a subscriber as soon as it is scheduled.
        for c in ratum::lock(&self.clients).iter() {
            c.wake();
        }
    }

    pub fn current_job(&self) -> Option<Arc<Job>> {
        ratum::lock(&self.jobs).current.clone()
    }

    /// The current job, whether it is empty work, and the generation it was published at.
    fn current_for_send(&self) -> (Option<Arc<Job>>, bool, u64) {
        let j = ratum::lock(&self.jobs);
        (j.current.clone(), j.empty, self.generation.load(Ordering::Acquire))
    }

    pub fn connection_count(&self) -> usize {
        ratum::lock(&self.clients).len()
    }

    /// The connection, subscription and hashrate totals in one pass over the client list.
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

    /// The statistics of the clients `keep` selects, filtered before they are copied.
    pub fn client_stats_where(&self, keep: impl Fn(&ClientStats) -> bool) -> Vec<ClientStats> {
        ratum::lock(&self.clients)
            .iter()
            .filter_map(|c| {
                let st = ratum::lock(&c.stats);
                keep(&st).then(|| st.clone())
            })
            .collect()
    }

    /// Disconnect every client (`datum_stratum_v1_shutdown_all`).
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

/// Bind the listener and accept connections until the process ends. Called once a job
/// exists, as the C gateway does.
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
            .spawn(move || match Connection::run(server, stream) {
                Ok(()) | Err(Disconnect::Io(_) | Disconnect::Killed | Disconnect::Idle(_)) => {}
                Err(e @ Disconnect::Protocol(_)) => info!("Stratum client connection closed: {e}"),
            })
            .map_err(|e| {
                warn!("could not start a client thread: {e}");
                e
            })
            .ok();
    }
    Ok(())
}

/// A `mining.submit` once parsed: the job it names and the fields the miner set.
struct SubmitRequest {
    job: Arc<Job>,
    /// The difficulty the job was served at to this connection.
    job_diff: u64,
    job_ref: JobRef,
    extranonce: [u8; 16],
    ntime: [u8; 8],
    nonce: [u8; 8],
    /// What the miner sent as its username.
    miner_username: String,
}

struct Connection {
    server: Arc<Server>,
    entry: Arc<ClientEntry>,
    stream: PolledStream,
    /// Readiness for the socket and the waker; the thread blocks here between reads.
    poll: Poll,
    events: Events,
    /// Set when the poll reports the socket readable, cleared when a read returns
    /// `WouldBlock`: the registration is edge triggered, so readiness holds until then.
    readable: bool,
    remote: String,
    sid: u32,
    subscribed: bool,
    authorized: bool,
    username: String,
    vardiff: Vardiff,
    /// The difficulty each job in the ring was served at to this connection.
    job_diffs: Vec<Option<u64>>,
    sent_generation: u64,
    connected: Instant,
    last_accepted: Option<Instant>,
    /// Hashrate window.
    window_active: u64,
    window_started: Instant,
    fee: FeeMeter,
    next_idle_check: Instant,
}

impl Connection {
    fn run(server: Arc<Server>, stream: TcpStream) -> Result<(), Disconnect> {
        let remote = stream.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
        stream.set_nodelay(true)?;
        // The poll reports readiness; the socket itself never blocks, and both directions
        // return `WouldBlock` instead.
        stream.set_nonblocking(true)?;
        let mut stream = PolledStream::from_std(stream);
        let poll = Poll::new()?;
        poll.registry().register(&mut stream, SOCKET, Interest::READABLE | Interest::WRITABLE)?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let unique_id = server.next_unique_id.fetch_add(1, Ordering::Relaxed);
        // The C gateway packs a 22-bit client index and a thread id; here the connection
        // counter is the whole 32 bits, so two live connections never share extranonce1.
        let sid = (unique_id as u32) ^ 0xB10C_F00D;
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
            stream,
            poll,
            events: Events::with_capacity(8),
            readable: false,
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
            next_idle_check: now + Duration::from_secs(10),
            server: Arc::clone(&server),
        };
        let result = c.serve();
        ratum::lock(&server.clients).retain(|e| !Arc::ptr_eq(e, &entry));
        debug!("Stratum client connection closed. ({:?})", result.as_ref().err());
        result
    }

    fn serve(&mut self) -> Result<(), Disconnect> {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
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

            if !self.readable {
                // Nothing left to read: block until the socket is readable, the waker is
                // called for a new job or a kill request, or a timed check is due.
                let timeout = self.until_next_check();
                self.wait(Some(timeout))?;
                continue;
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => {
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
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.readable = false,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// How long the thread may sleep before a timed check is due: the idle checks and the
    /// end of the hashrate window.
    fn until_next_check(&self) -> Duration {
        let due = self.next_idle_check.min(self.window_started + STAT_CYCLE);
        due.saturating_duration_since(Instant::now())
    }

    /// Block until an event or `timeout`, recording read readiness. A waker event needs no
    /// record: `serve` reads `kill` and the generation counter each time around the loop.
    /// `Interrupted` returns with no event, as a timeout does.
    fn wait(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self.poll.poll(&mut self.events, timeout) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
            Err(e) => return Err(e),
        }
        for ev in self.events.iter() {
            // A closed or errored socket is read so that `read` reports it.
            if ev.token() == SOCKET && (ev.is_readable() || ev.is_read_closed() || ev.is_error()) {
                self.readable = true;
            }
        }
        Ok(())
    }

    fn with_stats(&self, f: impl FnOnce(&mut ClientStats)) {
        f(&mut ratum::lock(&self.entry.stats));
    }

    /// Close the hashrate window once it has run `STAT_CYCLE`.
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
        self.write_all(line.as_bytes())?;
        self.write_all(b"\n")
    }

    /// Write every byte, waiting for write readiness while the socket buffer is full.
    /// Fails with `TimedOut` once `WRITE_TIMEOUT` has passed, as the socket write timeout
    /// did. Read readiness seen while waiting is kept for `serve`.
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + WRITE_TIMEOUT;
        let mut rest = data;
        while !rest.is_empty() {
            match self.stream.write(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    self.wait(Some(left))?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// A response to request `id`: `error` is the stratum error array or null.
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

    /// Handle one request line. `Err` closes the connection.
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
                    .take(127)
                    .collect()
            });
        // Fingerprinting keeps one effect of the C gateway's: NiceHash rents hashrate at a
        // high minimum difficulty. The coinbase size class it also assigned per miner is
        // removed; every miner receives the one pooled coinbase (`coinbase::COINBASE_POOLED`).
        if s.fingerprint_miners && useragent.starts_with("NiceHash/") {
            self.vardiff.raise_floor(524_288);
        }
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
        self.username = username.chars().take(191).collect();
        let name = self.username.clone();
        self.with_stats(|st| st.username = name);
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

    /// The difficulty a share on `r`'s job is checked against: the quick-raise value for a
    /// `Q` job, otherwise what the job was served at.
    fn served_diff(&self, r: &JobRef) -> Option<u64> {
        if r.quickdiff {
            Some(self.vardiff.quickdiff_value())
        } else {
            self.job_diffs[r.global_index as usize]
        }
    }

    /// Send the server's current job; new-block empty work is sent with `clean_jobs`.
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
            // With `no_quick` the update never requests a quick raise.
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
        // The nbits field carries `share_nbits(pot)`, not the template's bits, as the C
        // gateway sends for every BLAKE2b job: the compact target nearest to and not easier
        // than the miner's share target, so the hasher is not given the network target.
        let line = format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"{}\",\"{}\",\"000000{}\",\"\",[],\"\",\"{:08x}\",\"{}\",{clean_flag}]}}",
            r.notify_id(job),
            hex::encode(job.prevblock_hidden),
            hex::encode(commitment.h2),
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
                // A quick raise is announced at once with a `Q` job.
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

    /// The request's job and fields; a rejection carries the difficulty to count it under
    /// once the job is known.
    fn parse_submit(&self, params: &Value) -> Result<SubmitRequest, (Reject, Option<u64>)> {
        let unknown = (UNKNOWN_WORK, None);
        let id_param = params.get(1).and_then(Value::as_str).ok_or(unknown)?;
        let (job_ref, job_id) = JobRef::parse(id_param).ok_or(unknown)?;
        let job = ratum::lock(&self.server.jobs).ring[job_ref.global_index as usize]
            .clone()
            .ok_or(unknown)?;
        if job.job_id.get(..8) != job_id.get(..8) {
            return Err(unknown);
        }
        let job_diff = self.served_diff(&job_ref).ok_or(unknown)?;
        let rejected = (UNKNOWN_WORK, Some(job_diff));

        let en2 = params.get(2).and_then(Value::as_str).ok_or(rejected)?;
        if en2.len() != 16 {
            return Err(rejected);
        }
        let en2 = hex::decode(en2).map_err(|_| rejected)?;
        let mut extranonce = [0u8; 16];
        extranonce[4..8].copy_from_slice(&self.sid.to_be_bytes());
        extranonce[8..].copy_from_slice(&en2);
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

    /// Build the share's header, submit a block it names, run the checks, and forward it to
    /// the pool. Returns the rejection, if any, the miner is told.
    fn evaluate(&mut self, req: &SubmitRequest) -> Result<(), Reject> {
        let job = &req.job;
        let r = req.job_ref;
        let pot = target::floor_pot(req.job_diff);
        let header = job
            .header(r.coinbase, pot, req.extranonce, req.nonce, req.ntime)
            .ok_or(UNKNOWN_WORK)?;
        // Under an ABW assignment this is the raw hash the miner computed; the gateway cannot
        // apply the pool's mask, so it never computes the final block hash and cannot classify a
        // block. Without an assignment it is the final hash, as before.
        let hash = job.share_pow_hash(&header);

        // `miner_username` is what the miner sent; `username` is who the share is credited
        // to once a `~modifier` has been applied. stratum.require_address_username checks
        // the miner's own username, as the C gateway does, not the address its modifier names.
        let username = username::apply_modifier(
            &self.server.config.stratum.username_modifiers,
            &self.server.config.mining.pool_address,
            &req.miner_username,
            &hash,
        )
        .unwrap_or_else(|| req.miner_username.clone());

        // A job under an ABW assignment masks the network target with the pool's key, so
        // the gateway cannot distinguish a block from a share and must not submit one: the pool
        // holds the key, classifies the candidate, and submits it. Only a version 1 or solo
        // job is classified and submitted here.
        let is_block = job.abw.is_none() && target::meets_target(&hash, &job.block_target);
        if is_block {
            let display = hex::encode(hash);
            for _ in 0..3 {
                warn!("******** BLOCK FOUND - {display} ********");
            }
            self.submit_block(job, r.coinbase, pot, &header.serialize(), &display);
        }

        let checked = self.check_share(job, &hash, pot, &req.miner_username);
        // A block reaches the pool whatever the checks said: under the miner's own name when
        // a check refused it (the C gateway's attribution), and through the fee accounting
        // like any accepted share when they passed.
        if job.is_datum_job && (is_block || checked.is_ok()) {
            let wire_username = if checked.is_ok() && self.fee_charged(req.job_diff) {
                self.server.config.fee_address().to_string()
            } else {
                username
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
        if job.created.elapsed() > cfg.stale_window() {
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

    /// Whether this share is the fee's (`stratum_fee_username`), recorded when it is.
    fn fee_charged(&mut self, diff: u64) -> bool {
        let bps = u64::from(self.server.config.datum.gateway_fee_bps);
        let charged = self.fee.charge(diff, bps, || {
            let mut b = [0u8; 8];
            dryoc::rng::copy_randombytes(&mut b);
            u64::from_le_bytes(b)
        });
        if charged {
            self.with_stats(|st| st.fee.add(diff));
            ratum::lock(&self.server.fee).add(diff);
        }
        charged
    }
}

/// The connection thread against a client socket: the readiness path, the requests, and the
/// events that end the connection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::Builder;
    use crate::template::tests::{config, template};
    use std::io::{BufRead, BufReader};
    use std::thread::JoinHandle;

    /// How long a test waits for a line or a thread to end. The events under test are
    /// signalled by the waker, so they arrive in microseconds; the first timed check of a
    /// connection is `IDLE_CHECK_INTERVAL` away, well past this.
    const DEADLINE: Duration = Duration::from_millis(250);

    fn test_server() -> Arc<Server> {
        let config = Arc::new(config());
        let notify = Arc::new(crate::template::Notify::default());
        let shared = Arc::new(datum::Shared::new(
            config.datum.protocol_job_slots,
            64,
            Arc::clone(&notify),
            None,
        ));
        let node = ratum::rpc::Client::new("http://127.0.0.1:1", "u", "p").unwrap();
        Server::new(config, shared, node, notify)
    }

    /// A non-pooled job on the regtest template.
    fn a_job(server: &Server) -> Arc<Job> {
        let mut builder = Builder::new(Arc::clone(&server.config));
        Arc::new(builder.build(Arc::new(template()), false, None, None, None).unwrap())
    }

    /// A connection thread serving one end of a local socket pair, and a reader and writer
    /// for the client end.
    struct Client {
        server: Arc<Server>,
        lines: BufReader<TcpStream>,
        writer: TcpStream,
        thread: Option<JoinHandle<Result<(), Disconnect>>>,
    }

    impl Client {
        fn connect() -> Client {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (served, _) = listener.accept().unwrap();
            writer.set_read_timeout(Some(DEADLINE)).unwrap();
            let server = test_server();
            let s = Arc::clone(&server);
            let thread = std::thread::spawn(move || Connection::run(s, served));
            let lines = BufReader::new(writer.try_clone().unwrap());
            Client { server, lines, writer, thread: Some(thread) }
        }

        fn send(&mut self, line: &str) {
            self.writer.write_all(line.as_bytes()).unwrap();
            self.writer.write_all(b"\n").unwrap();
        }

        /// The next line the connection sent, as JSON.
        fn line(&mut self, what: &str) -> Value {
            let mut s = String::new();
            let n = self.lines.read_line(&mut s).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(n > 0, "{what}: the connection closed");
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("{what}: {s:?}: {e}"))
        }

        /// Subscribe and read the subscription reply and the difficulty it is followed by.
        fn subscribe(&mut self) {
            self.send(r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#);
            assert_eq!(self.line("subscribe reply")["id"], 1);
            assert_eq!(self.line("difficulty")["method"], "mining.set_difficulty");
        }

        fn unique_id(&self) -> u64 {
            self.server.client_stats().first().expect("one client").unique_id
        }

        /// Wait for the connection thread to end, and return why it did.
        fn ended(&mut self, what: &str) -> Disconnect {
            let thread = self.thread.take().expect("the thread was already joined");
            let started = Instant::now();
            while !thread.is_finished() {
                assert!(started.elapsed() < DEADLINE, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(1));
            }
            thread.join().unwrap().expect_err("the connection ended with an error")
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.server.shutdown_all();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    #[test]
    fn a_publication_reaches_a_subscriber_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let job = a_job(&c.server);
        let published = Instant::now();
        c.server.publish(Arc::clone(&job), false);
        let notify = c.line("mining.notify");
        assert!(published.elapsed() < DEADLINE, "the job waited for a timed check");
        assert_eq!(notify["method"], "mining.notify");
        let params = notify["params"].as_array().unwrap();
        assert_eq!(
            params[0].as_str().unwrap(),
            format!("{}{COINBASE_POOLED:02x}", job.job_id),
            "the notify names the published job and its pooled coinbase"
        );
    }

    /// A connection that has not subscribed is sent no job, and the publication does not end
    /// it: the waker only returns it from the poll.
    #[test]
    fn a_publication_sends_nothing_before_a_subscription() {
        let mut c = Client::connect();
        c.server.publish(a_job(&c.server), false);
        c.subscribe();
        // The subscription itself sends the current job, after the two subscription lines.
        assert_eq!(c.line("mining.notify")["method"], "mining.notify");
    }

    #[test]
    fn a_kill_request_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let id = c.unique_id();
        assert!(c.server.kill_client(id));
        assert!(matches!(c.ended("the kill request"), Disconnect::Killed));
        assert!(!c.server.kill_client(id), "the connection removed itself from the client list");
    }

    #[test]
    fn shutdown_all_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        c.server.shutdown_all();
        assert!(matches!(c.ended("the shutdown"), Disconnect::Killed));
    }

    /// Two requests written as one read are both answered, and a request split across two
    /// writes is answered once its newline arrives.
    #[test]
    fn requests_are_parsed_by_line_across_reads() {
        let mut c = Client::connect();
        c.writer
            .write_all(
                concat!(
                    r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#,
                    "\n",
                    r#"{"id":2,"method":"mining.authorize","params":["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]}"#,
                    "\n",
                )
                .as_bytes(),
            )
            .unwrap();
        assert_eq!(c.line("subscribe reply")["id"], 1);
        assert_eq!(c.line("difficulty")["method"], "mining.set_difficulty");
        let authorize = c.line("authorize reply");
        assert_eq!(authorize["id"], 2);
        assert_eq!(authorize["result"], Value::Bool(true));

        c.writer.write_all(br#"{"id":3,"method":"mining.au"#).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        c.writer.write_all(b"thorize\",\"params\":[\"worker\"]}\n").unwrap();
        assert_eq!(c.line("the reply to the split request")["id"], 3);
    }

    #[test]
    fn an_unknown_method_is_answered_with_an_error() {
        let mut c = Client::connect();
        c.send(r#"{"id":7,"method":"mining.nothing","params":[]}"#);
        let reply = c.line("error reply");
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"][0], METHOD_NOT_FOUND.0);
        assert_eq!(reply["error"][1], METHOD_NOT_FOUND.1);
    }

    #[test]
    fn a_closed_socket_ends_the_connection() {
        let mut c = Client::connect();
        c.subscribe();
        c.writer.shutdown(std::net::Shutdown::Both).unwrap();
        let ended = c.ended("the closed socket");
        assert!(matches!(ended, Disconnect::Io(_)), "{ended:?}");
    }

    #[test]
    fn a_line_over_the_buffer_ends_the_connection() {
        let mut c = Client::connect();
        let long = format!("{{\"id\":1,\"method\":\"{}\"", "x".repeat(CLIENT_BUFFER));
        // The peer may close before the whole request is written.
        let _ = c.writer.write_all(long.as_bytes());
        let ended = c.ended("the buffer overrun");
        assert!(
            matches!(&ended, Disconnect::Protocol(why) if why.contains("read buffer overrun")),
            "{ended:?}"
        );
    }
}
