//! One stratum client, on its own thread: the requests it sends, the work sent back to it, and the
//! idle limits that end it.

mod shares;

use super::notify_id::NotifyPrefix;
use super::{ClientEntry, ClientStats};
use crate::gateway::Gateway;
use crate::job::{Job, Publication};
use crate::vardiff::{self, NotifyDifficulty, Vardiff};
use log::{debug, info};
use ratum::datum::messages::share::{HEADER_EXTRANONCE_PAD, HEADER_EXTRANONCE_SIZE, MAX_JOBS};
use ratum::lock;
use ratum::poll::{PolledSocket, WRITE_TIMEOUT};
use ratum::target;
use serde_json::{Value, json};
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const CLIENT_BUFFER: usize = 16384 * 3 + 1024;
const MAX_REQUEST_ID_CHARS: usize = 64;
const MAX_USER_AGENT_CHARS: usize = 127;
const MAX_USERNAME_CHARS: usize = 191;
const NICEHASH_MIN_DIFFICULTY: u64 = 524_288;
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(11150);
const FIRST_IDLE_CHECK_DELAY: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 4096;
const SESSION_ID_XOR: u32 = 0xB10C_F00D;
const HASHRATE_WINDOW: Duration = Duration::from_secs(60);
const EXTRANONCE1_SIZE: usize = HEADER_EXTRANONCE_PAD + size_of::<u32>();
const EXTRANONCE2_SIZE: usize = HEADER_EXTRANONCE_SIZE - EXTRANONCE1_SIZE;

#[derive(Clone, Copy)]
struct StratumError {
    code: i64,
    message: &'static str,
}

const UNKNOWN_WORK: StratumError = StratumError { code: 20, message: "unknown-work" };
const STALE_WORK: StratumError = StratumError { code: 21, message: "stale-work" };
const STALE_PREVBLK: StratumError = StratumError { code: 21, message: "stale-prevblk" };
const DUPLICATE: StratumError = StratumError { code: 22, message: "duplicate" };
const HIGH_HASH: StratumError = StratumError { code: 23, message: "high-hash" };
const UNAUTHORIZED_WORKER: StratumError = StratumError { code: 24, message: "unauthorized-worker" };
const METHOD_NOT_FOUND: StratumError = StratumError { code: -3, message: "Method not found" };

#[derive(Debug, thiserror::Error)]
pub(super) enum Disconnect {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("idle: {0}")]
    Idle(&'static str),
    #[error("kill request")]
    Killed,
}

pub(super) struct Connection {
    gateway: Arc<Gateway>,
    entry: Arc<ClientEntry>,
    socket: PolledSocket,
    sid: u32,
    vardiff: Vardiff,
    /// The difficulty each job slot was last served at. It spans `MAX_JOBS`, not
    /// `datum.protocol_job_slots`, because a submitted job id resolves to any slot under
    /// `MAX_JOBS`, which is what lets both sides index it directly.
    job_diffs: Vec<Option<u64>>,
    /// The `Publication::sequence` last sent, not the `Job::serial`: one job published
    /// under both coinbases must be sent twice.
    sent_sequence: Option<u64>,
    /// The previous block of the last job notified; none before the first notify. A notify
    /// on another previous block sets clean_jobs, whatever publication it sends: a
    /// connection that did not reach its loop while a new tip's empty work was the work
    /// served sends that tip's pooled work first.
    notified_prev_hash: Option<[u8; 32]>,
    connected_at: Instant,
    diff_since_window_start: u64,
    window_started_at: Instant,
    next_idle_check: Instant,
}

impl Connection {
    pub(super) fn run(gateway: Arc<Gateway>, stream: TcpStream) -> Result<(), Disconnect> {
        let peer = stream.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
        stream.set_nodelay(true)?;
        let socket = PolledSocket::new(stream)?;
        let waker = socket.waker()?;
        let unique_id = gateway.stratum.next_unique_id.fetch_add(1, Ordering::Relaxed);
        let sid = (unique_id as u32) ^ SESSION_ID_XOR;
        let entry = Arc::new(ClientEntry {
            kill_requested: AtomicBool::new(false),
            waker,
            unique_id,
            stats: Mutex::new(ClientStats {
                peer,
                current_diff: gateway.config.stratum.vardiff_min,
                ..Default::default()
            }),
        });
        lock(&gateway.stratum.clients).insert(unique_id, Arc::clone(&entry));
        debug!("New Stratum client connected. {} ({unique_id})", lock(&entry.stats).peer);
        let now = Instant::now();
        let s = &gateway.config.stratum;
        let mut c = Self {
            entry: Arc::clone(&entry),
            socket,
            sid,
            vardiff: Vardiff::new(
                vardiff::VardiffParams {
                    min: s.vardiff_min,
                    target_shares_min: s.vardiff_target_shares_min,
                    quickdiff_count: s.vardiff_quickdiff_count,
                    quickdiff_delta: s.vardiff_quickdiff_delta,
                },
                now,
            ),
            job_diffs: vec![None; MAX_JOBS],
            sent_sequence: None,
            notified_prev_hash: None,
            connected_at: now,
            diff_since_window_start: 0,
            window_started_at: now,
            next_idle_check: now + FIRST_IDLE_CHECK_DELAY,
            gateway: Arc::clone(&gateway),
        };
        let result = c.serve();
        lock(&gateway.stratum.clients).remove(&unique_id);
        debug!("Stratum client connection closed. ({:?})", result.as_ref().err());
        result
    }

    fn serve(&mut self) -> Result<(), Disconnect> {
        let mut buf = Vec::with_capacity(READ_CHUNK);
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if self.entry.kill_requested.load(Ordering::Relaxed) {
                return Err(Disconnect::Killed);
            }
            if self.stats().subscribed()
                && let Some(published) = self.gateway.jobs.current()
                && self.sent_sequence != Some(published.sequence)
            {
                self.send_job(&published)?;
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
                        let line = String::from_utf8_lossy(&buf[..pos]).into_owned();
                        buf.drain(..=pos);
                        self.handle_line(line.trim_end_matches('\r'))?;
                    }
                }
                None => {}
            }
        }
    }

    fn until_next_check(&self) -> Duration {
        let due = self.next_idle_check.min(self.window_started_at + HASHRATE_WINDOW);
        due.saturating_duration_since(Instant::now())
    }

    fn stats(&self) -> MutexGuard<'_, ClientStats> {
        lock(&self.entry.stats)
    }

    fn roll_window(&mut self) {
        let window = self.window_started_at.elapsed();
        if window < HASHRATE_WINDOW {
            return;
        }
        let hashes_per_second =
            ratum::hashrate::from_work(self.diff_since_window_start.into(), window);
        self.stats().hashrate = Some((Instant::now(), hashes_per_second));
        self.diff_since_window_start = 0;
        self.window_started_at = Instant::now();
    }

    fn idle_checks(&mut self) -> Result<(), Disconnect> {
        if Instant::now() < self.next_idle_check {
            return Ok(());
        }
        self.next_idle_check = Instant::now() + IDLE_CHECK_INTERVAL;
        let s = &self.gateway.config.stratum;
        let idle =
            |limit: u64, since: Instant| limit != 0 && since.elapsed() > Duration::from_secs(limit);
        let st = self.stats();
        let reason = if !st.subscribed() && idle(s.idle_timeout_no_subscribe, self.connected_at) {
            Some(("not subscribing", s.idle_timeout_no_subscribe))
        } else if st.subscribed()
            && st.shares.accepted.count == 0
            && idle(s.idle_timeout_no_shares, self.connected_at)
        {
            Some(("submitting no accepted share", s.idle_timeout_no_shares))
        } else if st.subscribed()
            && let Some(last) = st.last_accepted_at
            && idle(s.idle_timeout_max_last_work, last)
        {
            Some(("submitting no share", s.idle_timeout_max_last_work))
        } else {
            None
        };
        if let Some((what, secs)) = reason {
            debug!(
                "Kicking client {} ({:?}) for {what} for more than {secs} seconds",
                st.peer, st.username
            );
            return Err(Disconnect::Idle(what));
        }
        Ok(())
    }

    /// Writes the line and its terminator in one write: the socket has `TCP_NODELAY` set, so
    /// a separate write of the newline would be its own segment.
    fn send_line(&mut self, mut line: String) -> io::Result<()> {
        line.push('\n');
        self.socket.write_all(line.as_bytes(), WRITE_TIMEOUT)
    }

    fn reply(&mut self, id: &str, error: Option<StratumError>, result: Value) -> io::Result<()> {
        let error = match error {
            Some(StratumError { code, message }) => format!("[{code},\"{message}\",null]"),
            None => "null".to_string(),
        };
        self.send_line(format!("{{\"error\":{error},\"id\":{id},\"result\":{result}}}"))
    }

    fn reply_result(&mut self, id: &str, result: Value) -> io::Result<()> {
        self.reply(id, None, result)
    }

    fn reply_error(&mut self, id: &str, r: StratumError) -> io::Result<()> {
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
        if self.stats().subscribed() {
            return Ok(());
        }
        let s = &self.gateway.config.stratum;
        let user_agent: String =
            params.get(0).and_then(Value::as_str).map_or_else(String::new, |ua| {
                ua.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || ". -_=@,|/:<>';".contains(*c))
                    .take(MAX_USER_AGENT_CHARS)
                    .collect()
            });
        if s.fingerprint_miners && user_agent.starts_with("NiceHash/") {
            self.vardiff.raise_floor(NICEHASH_MIN_DIFFICULTY);
        }
        let sid = format!("{:08x}", self.sid);
        let pad = "0".repeat(2 * HEADER_EXTRANONCE_PAD);
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
        let d = self.vardiff.mark_sent();
        self.send_difficulty(d)?;
        let mut st = self.stats();
        st.user_agent = user_agent;
        st.subscribed_at = Some(Instant::now());
        drop(st);
        self.vardiff.reset_snapshot(Instant::now());
        // No previous block has been notified yet, so this notify sets clean_jobs, as the C
        // gateway's `send_mining_notify(c, true, false, false)` at subscribe does.
        if let Some(published) = self.gateway.jobs.current() {
            self.send_job(&published)?;
        }
        Ok(())
    }

    fn on_authorize(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let username = username_param(params);
        let name: String = username.chars().take(MAX_USERNAME_CHARS).collect();
        let refused: Option<String> =
            self.gateway.config.stratum.refuses_username(username).then(|| {
                name.chars()
                    .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
                    .collect()
            });
        self.stats().username = name;
        if let Some(shown) = refused {
            info!(
                "Refusing authorization of \"{shown}\" from {}: stratum.require_address_username is set and the username does not begin with an address a coinbase output can pay.",
                self.stats().peer
            );
            return self.reply(id, Some(UNAUTHORIZED_WORKER), Value::Bool(false));
        }
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

    /// Announces difficulty `d` as the C gateway does: `d * 65535 / 65536`, the same target
    /// relative to the difficulty-1 target stratum firmware divides by
    /// (`ratum::stratum_difficulty::format`). The share target stays the one `d` names.
    fn send_difficulty(&mut self, d: u64) -> io::Result<()> {
        self.stats().current_diff = d;
        self.send_line(format!(
            "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{}]}}",
            ratum::stratum_difficulty::format(d)
        ))
    }

    fn send_job(&mut self, published: &Publication) -> io::Result<()> {
        self.sent_sequence = Some(published.sequence);
        let prefix = NotifyPrefix::from(published.kind);
        self.notify(&published.job, prefix, prefix == NotifyPrefix::EmptyWork)
    }

    /// Sends a mining.notify of `job`. clean_jobs is `clean`, or true when the job builds on
    /// a previous block other than the last one this connection notified (or none was).
    fn notify(&mut self, job: &Arc<Job>, prefix: NotifyPrefix, clean: bool) -> io::Result<()> {
        let prev_hash = job.template.prev_hash;
        let clean = clean || self.notified_prev_hash != Some(prev_hash);
        let quickdiff = prefix == NotifyPrefix::Quickdiff;
        let floor = if job.is_datum_job { self.gateway.pool.min_difficulty() } else { 0 };
        let NotifyDifficulty { announce, diff } =
            self.vardiff.on_notify(floor, quickdiff, Instant::now());
        if let Some(d) = announce {
            self.send_difficulty(d)?;
        }
        if !quickdiff {
            self.job_diffs[job.slot as usize] = Some(diff);
        }
        let target_byte = target::floor_log2(diff.max(1));
        let Some(commitment) = job.commitment(prefix.coinbase(), target_byte) else {
            return Err(io::Error::other("job has no coinbase for the selection"));
        };
        let coinb1 = format!(
            "{}{}",
            "00".repeat(ratum::header::COINB1_LEADING_ZEROS),
            hex::encode(commitment.h2)
        );
        let line = format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"{}\",\"{}\",\"{coinb1}\",\"\",[],\"\",\"{:08x}\",\"{}\",{clean}]}}",
            prefix.notify_id(job),
            hex::encode(job.prevblock_hidden),
            target::share_nbits(target_byte),
            job.ntime_hex(),
        );
        self.notified_prev_hash = Some(prev_hash);
        self.send_line(line)
    }
}

/// `params[0]` cut at its first NUL, as in C: the pool reads the share's username up to a NUL.
fn username_param(params: &Value) -> &str {
    let username = params.get(0).and_then(Value::as_str).unwrap_or("NULL");
    username.split('\0').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{template, test_gateway};
    use crate::job::CoinbaseKind;
    use crate::job::builder::{JobInputs, build};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    const DEADLINE: Duration = Duration::from_millis(250);

    fn a_job(gateway: &Gateway) -> Arc<Job> {
        let job = build(&gateway.config, JobInputs::new(0, Arc::new(template())));
        Arc::new(job.unwrap())
    }

    struct Client {
        gateway: Arc<Gateway>,
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
            let gateway = test_gateway(|_| {});
            let g = Arc::clone(&gateway);
            let thread = std::thread::spawn(move || Connection::run(g, served));
            let lines = BufReader::new(writer.try_clone().unwrap());
            Client { gateway, lines, writer, thread: Some(thread) }
        }

        fn send(&mut self, line: &str) {
            self.writer.write_all(line.as_bytes()).unwrap();
            self.writer.write_all(b"\n").unwrap();
        }

        fn line(&mut self, what: &str) -> Value {
            let mut s = String::new();
            let n = self.lines.read_line(&mut s).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(n > 0, "{what}: the connection closed");
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("{what}: {s:?}: {e}"))
        }

        fn subscribe(&mut self) {
            self.send(r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#);
            assert_eq!(self.line("subscribe reply")["id"], 1);
            assert_eq!(self.line("difficulty")["method"], "mining.set_difficulty");
        }

        fn unique_id(&self) -> u64 {
            self.gateway.stratum.client_stats().first().expect("one client").0
        }

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
            self.gateway.stratum.shutdown_all();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    #[test]
    fn a_publication_reaches_a_subscriber_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let job = a_job(&c.gateway);
        let published = Instant::now();
        c.gateway.publish(Arc::clone(&job), CoinbaseKind::Pooled);
        let notify = c.line("mining.notify");
        assert!(published.elapsed() < DEADLINE, "the job waited for a timed check");
        assert_eq!(notify["method"], "mining.notify");
        let params = notify["params"].as_array().unwrap();
        assert_eq!(
            params[0].as_str().unwrap(),
            format!("{}{:02x}", job.stratum_job_id, CoinbaseKind::Pooled.wire_id()),
            "the notify names the published job and its pooled coinbase"
        );
    }

    /// A new tip serves empty work and then the work its coinbase pays. Both are one job,
    /// built once: the hardware never receives the coinbase, so only the notify's prefix and
    /// coinbase id separate them.
    #[test]
    fn a_new_tips_empty_work_and_pooled_work_are_one_job_notified_twice() {
        let mut c = Client::connect();
        c.subscribe();
        let job = a_job(&c.gateway);
        let notify_id = |c: &mut Client| {
            c.line("mining.notify")["params"][0].as_str().expect("a job id").to_string()
        };

        c.gateway.publish(Arc::clone(&job), CoinbaseKind::SubsidyOnly);
        let empty_work = notify_id(&mut c);
        c.gateway.publish(Arc::clone(&job), CoinbaseKind::Pooled);
        let pooled = notify_id(&mut c);

        assert_eq!(
            empty_work,
            format!("N{}{:02x}", job.stratum_job_id, CoinbaseKind::SubsidyOnly.wire_id())
        );
        assert_eq!(pooled, format!("{}{:02x}", job.stratum_job_id, CoinbaseKind::Pooled.wire_id()));
        assert_eq!(
            c.gateway.jobs.at(job.slot).map(|held| held.serial),
            Some(job.serial),
            "both publications are the one job, in the one slot"
        );
    }

    #[test]
    fn a_publication_sends_nothing_before_a_subscription() {
        let mut c = Client::connect();
        c.gateway.publish(a_job(&c.gateway), CoinbaseKind::Pooled);
        c.subscribe();
        assert_eq!(c.line("mining.notify")["method"], "mining.notify");
    }

    /// The job of serial `serial` on a template whose previous block is `prev_hash`.
    fn job_on(gateway: &Gateway, serial: u64, prev_hash: [u8; 32]) -> Arc<Job> {
        let t = crate::template::Template { prev_hash, ..template() };
        Arc::new(build(&gateway.config, JobInputs::new(serial, Arc::new(t))).unwrap())
    }

    fn clean_jobs(notify: &Value) -> bool {
        notify["params"][8].as_bool().expect("a clean_jobs flag")
    }

    /// The first notify after mining.subscribe sets clean_jobs, as the C gateway's does,
    /// though the work served is pooled work that carries no new tip.
    #[test]
    fn the_first_notify_after_a_subscription_sets_clean_jobs() {
        let mut c = Client::connect();
        c.gateway.publish(a_job(&c.gateway), CoinbaseKind::Pooled);
        c.subscribe();
        assert!(clean_jobs(&c.line("mining.notify")));
    }

    /// clean_jobs follows the previous block the connection last notified, not the kind of
    /// publication: pooled work on a new tip sets it when the connection never sent that
    /// tip's empty work (it did not reach its loop while the empty work was the work served),
    /// and pooled work on the tip already notified does not.
    #[test]
    fn a_notify_on_another_previous_block_sets_clean_jobs_whatever_its_prefix() {
        let mut c = Client::connect();
        c.subscribe();
        c.gateway.publish(job_on(&c.gateway, 0, [0; 32]), CoinbaseKind::Pooled);
        assert!(clean_jobs(&c.line("the first notify")));
        c.gateway.publish(job_on(&c.gateway, 1, [0; 32]), CoinbaseKind::Pooled);
        assert!(!clean_jobs(&c.line("pooled work on the same tip")));
        c.gateway.publish(job_on(&c.gateway, 2, [0x11; 32]), CoinbaseKind::Pooled);
        let notify = c.line("pooled work on a new tip");
        assert!(notify["params"][0].as_str().is_some_and(|id| !id.starts_with('N')));
        assert!(clean_jobs(&notify));
        c.gateway.publish(job_on(&c.gateway, 3, [0x11; 32]), CoinbaseKind::SubsidyOnly);
        assert!(clean_jobs(&c.line("empty work")), "empty work sets it on any tip");
    }

    /// mining.set_difficulty carries the difficulty as the C gateway formats it, 16384 *
    /// 65535 / 65536 for the default `stratum.vardiff_min`.
    #[test]
    fn the_difficulty_is_announced_as_the_c_gateway_formats_it() {
        let mut c = Client::connect();
        c.send(r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#);
        assert_eq!(c.line("subscribe reply")["id"], 1);
        let mut line = String::new();
        c.lines.read_line(&mut line).expect("the difficulty");
        assert_eq!(
            line,
            "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[16383.75]}\n"
        );
    }

    #[test]
    fn a_kill_request_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let id = c.unique_id();
        assert!(c.gateway.stratum.kill_client(id));
        assert!(matches!(c.ended("the kill request"), Disconnect::Killed));
        assert!(
            !c.gateway.stratum.kill_client(id),
            "the connection removed itself from the client list"
        );
    }

    #[test]
    fn shutdown_all_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        c.gateway.stratum.shutdown_all();
        assert!(matches!(c.ended("the shutdown"), Disconnect::Killed));
    }

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
        assert_eq!(reply["error"][0], METHOD_NOT_FOUND.code);
        assert_eq!(reply["error"][1], METHOD_NOT_FOUND.message);
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
        let _ = c.writer.write_all(long.as_bytes());
        let ended = c.ended("the buffer overrun");
        assert!(
            matches!(&ended, Disconnect::Protocol(why) if why.contains("read buffer overrun")),
            "{ended:?}"
        );
    }

    #[test]
    fn a_username_is_cut_at_its_first_nul_on_authorize_and_submit_alike() {
        let submit = serde_json::json!(["bc1qaddr.w\0\0\0\0x", "id", "00", "0", "0"]);
        assert_eq!(username_param(&submit), "bc1qaddr.w");
        assert_eq!(username_param(&serde_json::json!(["\0rest"])), "");
        assert_eq!(username_param(&serde_json::json!(["plain"])), "plain");
        assert_eq!(username_param(&serde_json::json!([])), "NULL", "no username named");
    }
}
