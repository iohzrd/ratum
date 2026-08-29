//! The DATUM client: one connection to the pool at a time, on its own thread.
//!
//! The wire format is `ratum::datum`; this module is the state around it: connect, the
//! handshake, the configuration the pool sends, coinbaser requests for jobs that need one, the
//! share queue, the pool's validation requests, and reconnection. The timing values are the C
//! gateway's (`datum_protocol.c`, `datum_gateway.c`).

use crate::config::Config;
use crate::job::Job;
use crate::tally::Tally;
use crate::template::Notify;
use log::{debug, error, info, warn};
use ratum::datum::client::Client;
use ratum::datum::framing::{self, Header};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::{
    ClientConfig, CoinbaserRequest, CoinbaserResponse, ShareResponse, ShareVerdict, server_subcmd,
};
use ratum::datum::share::{self, Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::validation::{self, ShortTxnList, Status, TxnBundle};
use ratum::header::HeaderV2;
use ratum::io::read_exact_deadline;
use ratum::target;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a coinbaser request waits for its response (`datum_protocol_coinbaser_fetch`).
pub const COINBASER_WAIT: Duration = Duration::from_secs(5);
/// A coinbaser is not requested for a coinbase value under this (`datum_protocol.c`).
pub const COINBASER_MIN_VALUE: u64 = 31_250_000;
/// A share sent this long after an accepted one with none accepted since ends the connection.
pub const SHARE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// A share sent this long after the previous one restarts the acceptance clock.
pub const SHARE_ACK_GRACE: Duration = Duration::from_secs(25);
const READ_POLL: Duration = Duration::from_millis(5);
/// Every mining message ends with this many random bytes at most (the C gateway pads each
/// with 1 to 80 or 1 to 100), so a message's length does not identify its contents.
const MINING_PAD_MAX: usize = 100;

/// The pool's 0x99 configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u32,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
}

impl PoolConfig {
    fn from_message(c: ClientConfig) -> Self {
        // The C gateway rounds a minimum difficulty that is not a power of two up to the
        // next one.
        let min_difficulty = target::pow2_ceil(c.min_difficulty);
        if min_difficulty != c.min_difficulty {
            warn!(
                "pool minimum difficulty {} is not a power of two; using {min_difficulty}",
                c.min_difficulty
            );
        }
        PoolConfig {
            payout_script: c.payout_script,
            prime_id: c.prime_id,
            coinbase_tag: c.coinbase_tag,
            min_difficulty,
        }
    }
}

/// The statistics the API reports.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub accepted: Tally,
    pub rejected: Tally,
    pub motd: String,
}

/// A share the stratum server queues for submission.
#[derive(Clone)]
pub struct QueuedShare {
    pub job: Arc<Job>,
    pub coinbase_id: u8,
    pub is_block: bool,
    pub subsidy_only: bool,
    pub quickdiff: bool,
    pub target_byte: u8,
    /// The header the miner produced.
    pub header: HeaderV2,
    pub username: String,
}

/// A request for a coinbaser, and the slot its response is written to.
pub struct CoinbaserRequestState {
    pub value: u64,
    pub prev_hash: [u8; 32],
    pub response: Mutex<Option<CoinbaserResponse>>,
    pub done: Condvar,
    /// Set when a newer request replaced this one; the waiter returns at once.
    pub superseded: AtomicBool,
}

/// What other threads share with the DATUM thread.
pub struct Shared {
    /// The configuration from the pool; `None` until it arrives and again after a disconnect.
    /// The thread is active (holds a connection past the configuration) exactly while this
    /// is `Some`.
    config: Mutex<Option<PoolConfig>>,
    /// The last minimum difficulty the pool sent, kept across a disconnect as the C gateway
    /// keeps `override_vardiff_min`, so vardiff does not fall under the pool's floor while
    /// reconnecting. Zero until a configuration has arrived.
    min_difficulty: AtomicU64,
    pub stats: Mutex<Stats>,
    queue: Mutex<VecDeque<QueuedShare>>,
    /// The most shares the queue holds; more are refused with an error, as the C gateway's
    /// `datum_queue_add_item` refuses them.
    queue_capacity: usize,
    coinbaser: Mutex<Option<Arc<CoinbaserRequestState>>>,
    /// The jobs by DATUM slot, for validation requests. Set by the job builder.
    pub slots: Mutex<Vec<Option<Arc<Job>>>>,
    /// The template thread's notifications: raised on the pool's blocknotify, a rebuild is
    /// requested when the pool's configuration arrives or the connection ends.
    pub notify: Arc<Notify>,
    /// Consecutive sessions that did not reach the configuration, which
    /// `pooled_mining_only` reads; a session that did resets it to one.
    pub failures: AtomicU32,
}

impl Shared {
    pub fn new(slots: usize, queue_capacity: usize, notify: Arc<Notify>) -> Self {
        Shared {
            config: Mutex::new(None),
            min_difficulty: AtomicU64::new(0),
            stats: Mutex::new(Stats::default()),
            queue: Mutex::new(VecDeque::new()),
            queue_capacity: queue_capacity.max(64),
            coinbaser: Mutex::new(None),
            slots: Mutex::new(vec![None; slots]),
            notify,
            failures: AtomicU32::new(0),
        }
    }

    /// Whether the thread holds a connection past the configuration.
    pub fn is_active(&self) -> bool {
        ratum::lock(&self.config).is_some()
    }

    pub fn pool_config(&self) -> Option<PoolConfig> {
        ratum::lock(&self.config).clone()
    }

    /// The connected pool's payout script.
    pub fn payout_script(&self) -> Option<Vec<u8>> {
        ratum::lock(&self.config).as_ref().map(|c| c.payout_script.clone())
    }

    /// The pool's minimum difficulty, or 0 before one has been received.
    pub fn min_difficulty(&self) -> u64 {
        self.min_difficulty.load(Ordering::Relaxed)
    }

    /// The pool's configuration arrived: the previous one, if any.
    fn set_config(&self, config: PoolConfig) -> Option<PoolConfig> {
        self.min_difficulty.store(config.min_difficulty, Ordering::Relaxed);
        ratum::lock(&self.config).replace(config)
    }

    /// The connection ended: the configuration, the coinbaser request awaiting a response
    /// and the queued shares are discarded. Whether the thread was active.
    fn disconnected(&self) -> bool {
        let was_active = ratum::lock(&self.config).take().is_some();
        if let Some(state) = ratum::lock(&self.coinbaser).take() {
            state.done.notify_all();
        }
        ratum::lock(&self.queue).clear();
        was_active
    }

    /// The job in a DATUM slot, for the pool's validation requests.
    fn slot(&self, index: u8) -> Result<Arc<Job>, (u8, Status)> {
        let slots = ratum::lock(&self.slots);
        if index as usize >= slots.len() {
            return Err((validation::JOB_INDEX_INVALID, Status::BadJobIndex));
        }
        slots[index as usize].clone().ok_or((index, Status::JobEmpty))
    }

    pub fn submit(&self, share: QueuedShare) {
        let mut q = ratum::lock(&self.queue);
        if q.len() >= self.queue_capacity {
            error!(
                "share queue full ({} shares waiting for the pool); share from {:?} not queued",
                q.len(),
                share.username
            );
            return;
        }
        q.push_back(share);
    }

    /// Ask the pool for the payout split of a job and wait up to `COINBASER_WAIT` for it.
    /// `None` when the pool is not connected, did not respond, or responded for another value.
    /// A newer request replaces this one as the request awaiting a response.
    pub fn fetch_coinbaser(&self, value: u64, prev_hash: [u8; 32]) -> Option<CoinbaserResponse> {
        if !self.is_active() || value < COINBASER_MIN_VALUE {
            return None;
        }
        let state = Arc::new(CoinbaserRequestState {
            value,
            prev_hash,
            response: Mutex::new(None),
            done: Condvar::new(),
            superseded: AtomicBool::new(false),
        });
        if let Some(old) = ratum::lock(&self.coinbaser).replace(Arc::clone(&state)) {
            old.superseded.store(true, Ordering::SeqCst);
            old.done.notify_all();
        }
        let guard = ratum::lock(&state.response);
        let (guard, _) = state
            .done
            .wait_timeout_while(guard, COINBASER_WAIT, |r| {
                r.is_none() && !state.superseded.load(Ordering::SeqCst)
            })
            .unwrap_or_else(|p| p.into_inner());
        let response = guard.clone();
        drop(guard);
        {
            let mut waiting = ratum::lock(&self.coinbaser);
            if waiting.as_ref().is_some_and(|w| Arc::ptr_eq(w, &state)) {
                *waiting = None;
            }
        }
        match response {
            Some(r) if r.value == value => Some(r),
            Some(r) => {
                warn!("coinbaser responded for {} sats, not the {value} requested", r.value);
                None
            }
            None if state.superseded.load(Ordering::SeqCst) => {
                debug!("coinbaser request superseded by a newer template's");
                None
            }
            None => {
                warn!("coinbaser request timed out after {}s", COINBASER_WAIT.as_secs());
                None
            }
        }
    }
}

#[derive(Clone)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub pool_sign_pk: [u8; 32],
    pub pool_box_pk: [u8; 32],
    pub global_timeout: Duration,
    /// `SHARE_ACK_TIMEOUT` and `SHARE_ACK_GRACE`; fields so a test can shorten them.
    pub share_ack_timeout: Duration,
    pub share_ack_grace: Duration,
    pub user_agent: String,
    /// `datum.pool_pass_full_users`, `datum.pool_pass_workers` and `mining.pool_address`:
    /// what `wire_username` sends the pool for a miner's username.
    pub pass_full_users: bool,
    pub pass_workers: bool,
    pub pool_address: String,
}

impl Settings {
    /// The settings `datum.*` and `mining.pool_address` give; `datum.pool_pubkey` has been
    /// checked by `Config::parse`.
    pub fn from_config(config: &Config) -> Self {
        let (pool_sign_pk, pool_box_pk) =
            parse_pool_pubkey(&config.datum.pool_pubkey).expect("validated");
        Settings {
            host: config.datum.pool_host.clone(),
            port: config.datum.pool_port,
            pool_sign_pk,
            pool_box_pk,
            global_timeout: Duration::from_secs(config.datum.protocol_global_timeout),
            share_ack_timeout: SHARE_ACK_TIMEOUT,
            share_ack_grace: SHARE_ACK_GRACE,
            user_agent: user_agent(),
            pass_full_users: config.datum.pool_pass_full_users,
            pass_workers: config.datum.pool_pass_workers,
            pool_address: config.mining.pool_address.clone(),
        }
    }
}

/// The username a share is sent under (`datum_protocol.c`): the gateway's own address when
/// neither pass flag is set or the miner sent none; the miner's own username when full
/// usernames pass and it does not begin with `.`; otherwise the gateway's address with the
/// miner's username appended as `.worker`. At most `share::MAX_USERNAME` bytes.
pub fn wire_username(settings: &Settings, username: &str) -> String {
    let full = if (!settings.pass_full_users && !settings.pass_workers) || username.is_empty() {
        settings.pool_address.clone()
    } else if settings.pass_full_users && !username.starts_with('.') {
        username.to_string()
    } else {
        let dot = if username.starts_with('.') { "" } else { "." };
        format!("{}{dot}{username}", settings.pool_address)
    };
    let mut end = full.len().min(share::MAX_USERNAME);
    while !full.is_char_boundary(end) {
        end -= 1;
    }
    full[..end].to_string()
}

/// Parse `datum.pool_pubkey`: 128 hex characters, the Ed25519 key then the X25519 key.
pub fn parse_pool_pubkey(s: &str) -> Result<([u8; 32], [u8; 32]), String> {
    if s.len() != 128 {
        return Err(format!("pool_pubkey must be 128 hex characters, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("pool_pubkey is not hex: {e}"))?;
    Ok((bytes[..32].try_into().unwrap(), bytes[32..].try_into().unwrap()))
}

/// The user agent the hello carries: this crate's name and version, then the git commit.
pub fn user_agent() -> String {
    format!("ratum-gateway/{}/{}", env!("CARGO_PKG_VERSION"), ratum::GIT_COMMIT)
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("handshake: {0}")]
    Handshake(#[from] ratum::datum::handshake::Error),
    #[error("no message from the pool for {0:?}")]
    GlobalTimeout(Duration),
    #[error("no share accepted for {0:?}")]
    ShareAckTimeout(Duration),
    #[error("could not resolve {0}")]
    Resolve(String),
    #[error("connect timed out")]
    ConnectTimeout,
}

/// The protocol client thread: connect, run a session until it fails, report, return. The
/// caller (`run_forever`) reconnects.
struct Session<'a> {
    settings: &'a Settings,
    shared: &'a Shared,
    identity: &'a KeyPairs,
    stream: TcpStream,
    client: Client,
    last_server_msg: Instant,
    last_share_sent: Option<Instant>,
    last_share_accepted: Option<Instant>,
    /// Per slot: which job serial the pool has received, and which of its sections.
    sent_job: Vec<Option<SentSections>>,
    /// The coinbaser request this session has sent and is awaiting; a request is sent once.
    requested: Option<Arc<CoinbaserRequestState>>,
    /// Header bytes received so far of the frame being read.
    pending_header: Vec<u8>,
}

/// The sections the pool holds for the job in a slot (`server_has_job`,
/// `server_has_coinbase[8]`, `server_has_coinbase_empty` in the C gateway).
#[derive(Clone, Copy)]
struct SentSections {
    serial: u64,
    job: bool,
    coinbases: [bool; 8],
    subsidy_only: bool,
}

impl SentSections {
    fn new(serial: u64) -> Self {
        SentSections { serial, job: false, coinbases: [false; 8], subsidy_only: false }
    }

    /// Whether the pool holds `coinbase_id`'s section; marks it held.
    fn coinbase_known(&mut self, coinbase_id: u8) -> bool {
        let slot = if coinbase_id == share::COINBASE_ID_SUBSIDY_ONLY {
            &mut self.subsidy_only
        } else {
            &mut self.coinbases[coinbase_id as usize & 7]
        };
        std::mem::replace(slot, true)
    }
}

fn connect(settings: &Settings) -> Result<TcpStream, SessionError> {
    let target = format!("{}:{}", settings.host, settings.port);
    let addrs: Vec<_> = target
        .to_socket_addrs()
        .map_err(|e| SessionError::Resolve(format!("{target}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(SessionError::Resolve(target));
    }
    let mut last = SessionError::ConnectTimeout;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Err(e) => {
                debug!("connect to {addr} failed: {e}");
                last = SessionError::Io(e);
            }
        }
    }
    Err(last)
}

impl<'a> Session<'a> {
    fn open(
        settings: &'a Settings,
        shared: &'a Shared,
        identity: &'a KeyPairs,
    ) -> Result<Self, SessionError> {
        let mut stream = connect(settings)?;
        stream.set_read_timeout(Some(READ_POLL))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut client = Client::with_key_pairs(identity.clone(), KeyPairs::generate(), rand_u32());
        let hello = client.hello(&settings.pool_box_pk, &settings.user_agent);
        stream.write_all(&hello)?;
        stream.flush()?;

        // `read_handshake_response` takes the frame as sent and unmasks the header itself;
        // it is peeked here for the body's length only.
        let started = Instant::now();
        let mut frame = read_exact_deadline(&mut stream, 4, started, settings.global_timeout)?;
        let peeked = client.peek_handshake_header(frame[..].try_into().expect("four bytes"));
        if peeked.cmd_len > framing::MAX_CMD_DATA_SIZE {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "handshake frame too large").into()
            );
        }
        frame.extend(read_exact_deadline(
            &mut stream,
            peeked.cmd_len as usize,
            started,
            settings.global_timeout,
        )?);
        client.read_handshake_response(&frame, &settings.pool_sign_pk)?;
        info!("DATUM Server MOTD: {}", client.motd());

        let slots = ratum::lock(&shared.slots).len();
        Ok(Session {
            settings,
            shared,
            identity,
            stream,
            client,
            last_server_msg: Instant::now(),
            last_share_sent: None,
            last_share_accepted: None,
            sent_job: vec![None; slots],
            requested: None,
            pending_header: Vec::with_capacity(4),
        })
    }

    /// Send a mining message with random padding after it. A message over the protocol's
    /// size limit is logged and not sent, as the C gateway drops it; the connection stays.
    fn send_mining(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        let mut pad = [0u8; MINING_PAD_MAX];
        dryoc::rng::copy_randombytes(&mut pad);
        let pad_len = 1 + usize::from(pad[0]) % MINING_PAD_MAX;
        let mut padded = Vec::with_capacity(payload.len() + pad_len);
        padded.extend_from_slice(payload);
        padded.extend_from_slice(&pad[..pad_len]);
        let wire = match self.client.encrypt(framing::cmd::MINING, &padded) {
            Ok(w) => w,
            Err(ratum::datum::handshake::Error::TooLarge(n)) => {
                error!("mining message of {n} bytes exceeds the protocol limit; not sent");
                return Ok(());
            }
            Err(e) => return Err(io::Error::other(e.to_string()).into()),
        };
        self.stream.write_all(&wire)?;
        self.stream.flush()?;
        Ok(())
    }

    /// The next frame's header, accumulated across the short read timeout so the pending
    /// sends run between polls; `None` until four bytes have arrived.
    fn poll_header(&mut self) -> Result<Option<Header>, SessionError> {
        let mut byte = [0u8; 4];
        match self.stream.read(&mut byte[..4 - self.pending_header.len()]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => self.pending_header.extend_from_slice(&byte[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
        if self.pending_header.len() < 4 {
            return Ok(None);
        }
        let header = self.client.unmask_header(self.pending_header[..].try_into().unwrap());
        self.pending_header.clear();
        if header.cmd_len > framing::MAX_CMD_DATA_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds the protocol limit",
            )
            .into());
        }
        Ok(Some(header))
    }

    fn run(&mut self) -> Result<(), SessionError> {
        loop {
            if self.last_server_msg.elapsed() >= self.settings.global_timeout {
                return Err(SessionError::GlobalTimeout(self.settings.global_timeout));
            }
            if let (Some(sent), Some(acked)) = (self.last_share_sent, self.last_share_accepted)
                && sent > acked
                && sent.duration_since(acked) >= self.settings.share_ack_timeout
            {
                return Err(SessionError::ShareAckTimeout(self.settings.share_ack_timeout));
            }

            self.send_pending()?;

            let Some(header) = self.poll_header()? else { continue };
            // The global timeout covers a partly received body too, as the C main loop's
            // check does on every partial read.
            let body = read_exact_deadline(
                &mut self.stream,
                header.cmd_len as usize,
                self.last_server_msg,
                self.settings.global_timeout,
            )?;
            let plain = self.client.decrypt(header, &body).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not decrypt cmd {}: {e}", header.proto_cmd),
                )
            })?;
            self.last_server_msg = Instant::now();
            match header.proto_cmd {
                framing::cmd::HELLO_OR_PING => {}
                framing::cmd::INFO => {
                    let end = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
                    info!("DATUM Server message: {}", String::from_utf8_lossy(&plain[..end]));
                }
                framing::cmd::MINING => self.on_mining(header, &plain)?,
                other => warn!("unknown DATUM command {other}"),
            }
        }
    }

    fn on_mining(&mut self, header: Header, plain: &[u8]) -> Result<(), SessionError> {
        match plain.first().copied() {
            Some(server_subcmd::CONFIG) => {
                if !header.is_signed {
                    error!("pool configuration was not signed; ignored");
                    return Ok(());
                }
                match ClientConfig::decode(plain) {
                    Some(c) => self.on_config(PoolConfig::from_message(c)),
                    None => error!("malformed pool configuration; ignored"),
                }
            }
            Some(server_subcmd::COINBASER) => {
                let Some(state) = ratum::lock(&self.shared.coinbaser).clone() else {
                    warn!("coinbaser response with no request waiting");
                    return Ok(());
                };
                let r = match CoinbaserResponse::decode(plain) {
                    Some(r) => {
                        debug!(
                            "coinbaser response: {} sats, id {}, {} outputs",
                            r.value,
                            r.coinbaser_id,
                            r.outputs.len()
                        );
                        r
                    }
                    // The C gateway builds the job with no split rather than waiting out
                    // the request.
                    None => {
                        error!("malformed coinbaser response; the job pays the pool script alone");
                        CoinbaserResponse {
                            value: state.value,
                            coinbaser_id: 0,
                            outputs: Vec::new(),
                        }
                    }
                };
                *ratum::lock(&state.response) = Some(r);
                state.done.notify_all();
            }
            Some(server_subcmd::SHARE_RESPONSE) => match ShareResponse::decode(plain) {
                Some(r) => self.on_share_response(r),
                None => warn!("malformed share response"),
            },
            Some(server_subcmd::VALIDATION) => self.on_validation(plain)?,
            Some(server_subcmd::BLOCKNOTIFY) => {
                debug!("pool blocknotify");
                self.shared.notify.raise();
            }
            other => warn!("unknown DATUM mining sub-command {other:?}"),
        }
        Ok(())
    }

    fn on_config(&mut self, config: PoolConfig) {
        info!(
            "DATUM pool configuration: prime_id {:#010x}, tag {:?}, min diff {}, payout script {}",
            config.prime_id,
            config.coinbase_tag,
            config.min_difficulty,
            hex::encode(&config.payout_script)
        );
        let previous = self.shared.set_config(config.clone());
        if previous.is_none() {
            ratum::lock(&self.shared.stats).motd = self.client.motd().to_string();
        }
        // The jobs being served were built without this configuration (or with an older
        // one): rebuild them now rather than at the next poll.
        if previous.as_ref() != Some(&config) {
            self.shared.notify.rebuild();
        }
    }

    fn on_share_response(&mut self, r: ShareResponse) {
        let diff = if r.target_byte == 0xff {
            self.shared.min_difficulty().max(1)
        } else {
            target::diff_for_pot(r.target_byte)
        };
        let accepted =
            matches!(r.verdict, ShareVerdict::Accepted | ShareVerdict::AcceptedTentatively);
        {
            let mut st = ratum::lock(&self.shared.stats);
            if accepted { &mut st.accepted } else { &mut st.rejected }.add(diff);
        }
        let what = format!("job {} nonce {:08x} diff {diff}", r.job_id, r.nonce);
        match r.verdict {
            ShareVerdict::Accepted => debug!("DATUM share accepted: {what}"),
            ShareVerdict::AcceptedTentatively => {
                debug!("DATUM share accepted: {what} (tentatively)")
            }
            ShareVerdict::Rejected(reason) => {
                warn!("DATUM share rejected: {what}: {reason:?} ({})", reason as u16)
            }
            ShareVerdict::RejectedUnknown(code) => {
                warn!("DATUM share rejected: {what}: reason code {code} (not one this build names)")
            }
        }
        if accepted {
            self.last_share_accepted = Some(Instant::now());
        }
    }

    fn on_validation(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        let Some(&sub) = plain.get(1) else { return Ok(()) };
        let job_index = plain.get(2).copied();
        let lookup = job_index
            .ok_or((validation::JOB_INDEX_INVALID, Status::BadRequest))
            .and_then(|i| self.shared.slot(i));
        let response = match sub {
            validation::request::SHORT_TXN_LIST => {
                info!("pool requested the short transaction list of job {job_index:?}");
                match lookup {
                    Ok(job) => self.short_txn_list(&job),
                    Err((idx, status)) => ShortTxnList {
                        job_index: idx,
                        status,
                        txn_count: 0,
                        short_ids: vec![],
                        crosscheck: None,
                    },
                }
                .encode()
            }
            validation::request::TXNS | validation::request::BLOCK_TXNS => {
                let all = sub == validation::request::BLOCK_TXNS;
                let selector =
                    if all { validation::response::BLOCK_TXNS } else { validation::response::TXNS };
                let bundle = match lookup {
                    Ok(job) => {
                        let txns = &job.template.txns;
                        let ids = if all {
                            Some((0..txns.len()).collect())
                        } else {
                            requested_ids(plain, txns.len())
                        };
                        match ids {
                            Some(ids) => TxnBundle {
                                selector,
                                job_index: job.datum_slot,
                                status: Status::Ok,
                                txns: ids.iter().map(|&i| txns[i].raw.clone()).collect(),
                            },
                            None => TxnBundle {
                                selector,
                                job_index: job.datum_slot,
                                status: Status::BadRequest,
                                txns: vec![],
                            },
                        }
                    }
                    Err((idx, status)) => {
                        TxnBundle { selector, job_index: idx, status, txns: vec![] }
                    }
                };
                info!(
                    "pool requested {} of job {job_index:?}: sending {}",
                    if all { "the block transactions" } else { "transactions" },
                    bundle.txns.len()
                );
                bundle.encode()
            }
            other => {
                warn!("unknown validation request {other:#04x}");
                return Ok(());
            }
        };
        self.send_mining(&response)
    }

    fn short_txn_list(&self, job: &Job) -> ShortTxnList {
        let hashes = job.template.witness_hashes();
        if hashes.len() > validation::MAX_SHORT_LIST_TXNS as usize {
            return ShortTxnList {
                job_index: job.datum_slot,
                status: Status::TooManyTxns,
                txn_count: 0,
                short_ids: vec![],
                crosscheck: None,
            };
        }
        let key = validation::short_id_key(&self.identity.sign_pk, &self.settings.pool_sign_pk);
        ShortTxnList {
            job_index: job.datum_slot,
            status: Status::Ok,
            txn_count: hashes.len() as u16,
            short_ids: hashes.iter().map(|h| validation::short_id(h, &key)).collect(),
            crosscheck: if hashes.is_empty() {
                None
            } else {
                Some(validation::crosscheck(&hashes))
            },
        }
    }

    /// Send the pending coinbaser request and every queued share.
    fn send_pending(&mut self) -> Result<(), SessionError> {
        let request = ratum::lock(&self.shared.coinbaser).clone();
        if let Some(state) = request
            && !self.requested.as_ref().is_some_and(|r| Arc::ptr_eq(r, &state))
        {
            let req = CoinbaserRequest { value: state.value, prev_hash: state.prev_hash };
            debug!("coinbaser request: {} sats", state.value);
            self.send_mining(&req.encode())?;
            self.requested = Some(state);
        }
        let batch = std::mem::take(&mut *ratum::lock(&self.shared.queue));
        for share in batch {
            self.send_share(share)?;
        }
        Ok(())
    }

    /// The job and coinbase sections the pool does not yet hold for this share's job.
    fn sections_for(
        &mut self,
        share: &QueuedShare,
    ) -> (Option<JobSection>, Option<CoinbaseSection>) {
        let job = &share.job;
        let sent =
            self.sent_job[job.datum_slot as usize].get_or_insert(SentSections::new(job.serial));
        if sent.serial != job.serial {
            *sent = SentSections::new(job.serial);
        }
        let job_section = (!std::mem::replace(&mut sent.job, true)).then(|| JobSection {
            prev_hash: job.template.prev_hash,
            target_byte_index: job.target_pot_index as u16,
            nbits: job.template.nbits_bytes,
            coinbaser_id: job.coinbaser_id,
            height: job.template.height,
            coinbase_value: job.template.coinbase_value,
            txn_count: job.template.txns.len() as u32,
            txn_total_weight: job.template.totals.weight,
            txn_total_size: job.template.totals.size,
            txn_total_sigops: job.template.totals.sigops,
            merkle_branches: job.merkle_branches.clone(),
        });
        let coinbase_section = (!sent.coinbase_known(share.coinbase_id)).then(|| {
            let c = job.coinbase(share.coinbase_id).expect("checked by the caller");
            CoinbaseSection {
                coinbase_id: share.coinbase_id,
                coinb1: c.coinb1.clone(),
                coinb2: c.coinb2.clone(),
            }
        });
        (job_section, coinbase_section)
    }

    fn send_share(&mut self, share: QueuedShare) -> Result<(), SessionError> {
        let job = &share.job;
        // The slot must still hold this job; a share for a job that has been replaced in
        // its slot cannot be described to the pool.
        let current =
            ratum::lock(&self.shared.slots)[job.datum_slot as usize].as_ref().map(|j| j.serial);
        if current != Some(job.serial) {
            debug!("share for job {} whose DATUM slot was reused; not sent", job.serial);
            return Ok(());
        }
        let h = &share.header;
        let Some(extranonce) = share::share_extranonce(&h.extranonce) else {
            warn!("share header extranonce does not begin with four zero bytes; not sent");
            return Ok(());
        };
        if job.coinbase(share.coinbase_id).is_none() {
            warn!("share names coinbase {} which the job does not have", share.coinbase_id);
            return Ok(());
        }
        let (job_section, coinbase_section) = self.sections_for(&share);
        let blake2b = Blake2bSection::from_header(h);
        let submit = PowSubmit {
            job_id: job.datum_slot,
            coinbase_id: share.coinbase_id,
            is_block: share.is_block,
            subsidy_only: share.subsidy_only,
            quickdiff: share.quickdiff,
            target_byte: share.target_byte,
            ntime: blake2b.time_on_wire,
            nonce: h.nonce,
            version: ratum::header::V2_FLAG | h.version as u32,
            extranonce,
            username: wire_username(self.settings, &share.username),
            use_time_offset: h.flags & ratum::header::FLAG_USE_TIME_OFFSET != 0,
            job: job_section,
            coinbase: coinbase_section,
            blake2b,
        };
        debug!(
            "DATUM share: slot {} coinbase {} diff 2^{} user {:?}{}",
            job.datum_slot,
            share.coinbase_id,
            share.target_byte,
            share.username,
            if share.is_block { " BLOCK" } else { "" }
        );
        self.send_mining(&submit.encode())?;
        let now = Instant::now();
        if self
            .last_share_sent
            .is_none_or(|t| now.duration_since(t) > self.settings.share_ack_grace)
        {
            self.last_share_accepted = Some(now);
        }
        self.last_share_sent = Some(now);
        Ok(())
    }
}

/// The transaction indexes a `TXNS` request names, in order; `None` when the count is zero,
/// over the job's, or an index is.
fn requested_ids(plain: &[u8], txn_count: usize) -> Option<Vec<usize>> {
    let count = u16::from_le_bytes([*plain.get(3)?, *plain.get(4)?]) as usize;
    if count == 0 || count > txn_count {
        return None;
    }
    let ids: Vec<usize> = plain
        .get(5..5 + 2 * count)?
        .chunks(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        .collect();
    ids.iter().all(|&i| i < txn_count).then_some(ids)
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    dryoc::rng::copy_randombytes(&mut b);
    u32::from_le_bytes(b)
}

/// Run sessions until the process ends. After every session a rebuild is requested so the
/// template thread stops serving pooled jobs; `Shared::failures` counts consecutive sessions
/// that did not reach the configuration.
pub fn run_forever(settings: Settings, shared: Arc<Shared>, identity: KeyPairs) {
    loop {
        info!("connecting to DATUM pool {}:{}", settings.host, settings.port);
        let outcome = match Session::open(&settings, &shared, &identity) {
            Ok(mut session) => session.run(),
            Err(e) => Err(e),
        };
        let was_active = shared.disconnected();
        if let Err(e) = outcome {
            error!("DATUM connection ended: {e}");
        }
        if was_active {
            shared.failures.store(1, Ordering::Relaxed);
            shared.notify.rebuild();
        } else {
            shared.failures.fetch_add(1, Ordering::Relaxed);
        }
        let delay = Duration::from_millis(5000 + u64::from(rand_u32() % 15001));
        info!("reconnecting to the pool in {:.1}s", delay.as_secs_f64());
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(full: bool, workers: bool) -> Settings {
        Settings {
            host: String::new(),
            port: 0,
            pool_sign_pk: [0; 32],
            pool_box_pk: [0; 32],
            global_timeout: Duration::from_secs(60),
            share_ack_timeout: SHARE_ACK_TIMEOUT,
            share_ack_grace: SHARE_ACK_GRACE,
            user_agent: String::new(),
            pass_full_users: full,
            pass_workers: workers,
            pool_address: "bc1qpool".into(),
        }
    }

    #[test]
    fn wire_username_follows_the_c_gateway() {
        assert_eq!(wire_username(&settings(true, true), "bc1qminer.rig"), "bc1qminer.rig");
        assert_eq!(wire_username(&settings(true, true), ".rig"), "bc1qpool.rig");
        assert_eq!(wire_username(&settings(true, true), ""), "bc1qpool");
        assert_eq!(
            wire_username(&settings(false, true), "bc1qminer.rig"),
            "bc1qpool.bc1qminer.rig"
        );
        assert_eq!(wire_username(&settings(false, true), ".rig"), "bc1qpool.rig");
        assert_eq!(wire_username(&settings(false, false), "bc1qminer"), "bc1qpool");
        let long: String = "é".repeat(300);
        let sent = wire_username(&settings(true, true), &long);
        assert_eq!(sent.len(), 384);
        assert_eq!(sent.chars().count(), 192);
    }

    #[test]
    fn requested_ids_are_bounds_checked() {
        let mut plain = vec![0x50, validation::request::TXNS, 0, 2, 0, 1, 0, 3, 0];
        assert_eq!(requested_ids(&plain, 4), Some(vec![1, 3]));
        assert_eq!(requested_ids(&plain, 3), None, "index 3 is out of range");
        plain[3] = 0;
        assert_eq!(requested_ids(&plain, 4), None, "a count of zero");
        assert_eq!(requested_ids(&[0x50, 0x02, 0, 5, 0, 1], 4), None, "truncated");
    }
}

/// The session against a stand-in pool on a local socket: the handshake, the configuration,
/// the coinbaser, the share sections, the responses, the notifications and the timeouts.
#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::job::{Builder, COINBASE_SUBSIDY_ONLY, Job};
    use crate::template::Wake;
    use crate::template::tests::{config, template};
    use ratum::datum::framing::cmd;
    use ratum::datum::handshake::{Channel, Session as PoolSession, accept, open_hello};
    use ratum::datum::messages::{
        CoinbaseOutput, CoinbaserResponse, RejectReason, ShareResponse, client_subcmd,
    };
    use ratum::io::read_frame;
    use std::net::TcpListener;

    const TEST_DEADLINE: Duration = Duration::from_secs(10);

    /// The pool end of one connection, past the handshake.
    struct Pool {
        stream: TcpStream,
        session: PoolSession,
    }

    impl Pool {
        /// The next mining message's plaintext, or `None` when the gateway is gone.
        fn read_mining(&mut self) -> Option<Vec<u8>> {
            loop {
                let (header, body) = read_frame(
                    &mut self.stream,
                    |b| self.session.unmask_header(b),
                    Instant::now(),
                    TEST_DEADLINE,
                )
                .ok()?;
                let plain = self.session.decrypt(header, &body).expect("gateway frame decrypts");
                if header.proto_cmd == cmd::MINING {
                    return Some(plain);
                }
            }
        }

        fn share(&mut self) -> PowSubmit {
            let plain = self.read_mining().expect("a share");
            assert_eq!(plain[0], client_subcmd::SUBMIT_POW, "not a share: {plain:?}");
            PowSubmit::decode(&plain).expect("share decodes")
        }

        fn send(&mut self, payload: &[u8], signed: bool) {
            let wire = self.session.encrypt(cmd::MINING, payload, signed).unwrap();
            self.stream.write_all(&wire).unwrap();
        }

        fn answer(&mut self, share: &PowSubmit, verdict: ShareVerdict) {
            let r = ShareResponse {
                verdict,
                nonce: share.nonce,
                target_byte: share.target_byte,
                job_id: share.job_id,
            };
            self.send(&r.encode(), false);
        }
    }

    fn pool_config() -> PoolConfig {
        PoolConfig {
            payout_script: ratum::fixtures::p2wpkh(9),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
        }
    }

    fn config_payload(c: &PoolConfig) -> Vec<u8> {
        ClientConfig {
            payout_script: c.payout_script.clone(),
            prime_id: c.prime_id,
            coinbase_tag: c.coinbase_tag.clone(),
            min_difficulty: c.min_difficulty,
        }
        .encode()
        .unwrap()
    }

    /// A pool that accepts one gateway and hands it to `serve`, plus the settings a gateway
    /// reaches it with. `serve` returns when the test is done; dropping the stream ends the
    /// gateway's session.
    fn start_pool(
        serve: impl FnOnce(&mut Pool) + Send + 'static,
    ) -> (Settings, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let keys = KeyPairs::generate();
        let settings = Settings {
            host: "127.0.0.1".into(),
            port,
            pool_sign_pk: keys.sign_pk,
            pool_box_pk: keys.box_pk,
            global_timeout: TEST_DEADLINE,
            share_ack_timeout: SHARE_ACK_TIMEOUT,
            share_ack_grace: SHARE_ACK_GRACE,
            user_agent: "test".into(),
            pass_full_users: true,
            pass_workers: true,
            pool_address: "bc1qpool".into(),
        };
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            // The hello is read with the pre-handshake keys, before a session exists.
            let mut pre = Channel::before_handshake();
            let (header, body) =
                read_frame(&mut stream, |b| pre.unmask_header(b), Instant::now(), TEST_DEADLINE)
                    .expect("hello");
            let hello = open_hello(header, &body, &keys).expect("hello opens");
            let (response, session) = accept(hello, &keys, "test motd").unwrap();
            stream.write_all(&response).unwrap();
            let mut pool = Pool { stream, session };
            serve(&mut pool);
        });
        (settings, handle)
    }

    fn shared() -> (Arc<Shared>, Arc<Notify>) {
        let notify = Arc::new(Notify::default());
        (Arc::new(Shared::new(4, 64, Arc::clone(&notify))), notify)
    }

    /// Run a session against the pool until it ends; the error it ended with.
    fn run_session(
        settings: Settings,
        shared: Arc<Shared>,
    ) -> std::thread::JoinHandle<SessionError> {
        std::thread::spawn(move || {
            let identity = KeyPairs::generate();
            match Session::open(&settings, &shared, &identity) {
                Ok(mut s) => s.run().unwrap_err(),
                Err(e) => e,
            }
        })
    }

    fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let started = Instant::now();
        while !cond() {
            assert!(started.elapsed() < TEST_DEADLINE, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn job(shared: &Shared, slot: u8) -> Arc<Job> {
        let template = Arc::new(template());
        let mut builder = Builder::new(Arc::new(config()));
        let mut job = None;
        // The builder assigns slots in order; build until the wanted one.
        for _ in 0..=slot {
            job = Some(
                builder.build(Arc::clone(&template), false, Some(&pool_config()), None).unwrap(),
            );
        }
        let job = Arc::new(job.unwrap());
        assert_eq!(job.datum_slot, slot);
        ratum::lock(&shared.slots)[slot as usize] = Some(Arc::clone(&job));
        job
    }

    fn queued(job: &Arc<Job>, coinbase_id: u8, nonce: u32, username: &str) -> QueuedShare {
        let mut sia_nonce = [0u8; 8];
        sia_nonce[..4].copy_from_slice(&nonce.to_le_bytes());
        let header = job.header(coinbase_id, 10, [0u8; 16], sia_nonce, [0u8; 8]).unwrap();
        QueuedShare {
            job: Arc::clone(job),
            coinbase_id,
            is_block: false,
            subsidy_only: coinbase_id == COINBASE_SUBSIDY_ONLY,
            quickdiff: false,
            target_byte: 10,
            header,
            username: username.into(),
        }
    }

    #[test]
    fn the_configuration_arrives_and_a_rebuild_is_requested() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            std::thread::sleep(Duration::from_millis(200));
        });
        let (shared, notify) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        assert_eq!(shared.pool_config(), Some(pool_config()));
        assert_eq!(shared.min_difficulty(), 1024);
        assert_eq!(notify.wait(Duration::from_secs(1)), Wake::Rebuild);
        assert_eq!(ratum::lock(&shared.stats).motd, "test motd");
        pool.join().unwrap();
        assert!(matches!(session.join().unwrap(), SessionError::Io(_)));
    }

    #[test]
    fn an_unsigned_configuration_is_ignored() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), false);
            std::thread::sleep(Duration::from_millis(300));
        });
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        pool.join().unwrap();
        session.join().unwrap();
        assert!(!shared.is_active());
        assert_eq!(shared.pool_config(), None);
    }

    #[test]
    fn the_pools_blocknotify_raises_the_template_notification() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            p.send(&[server_subcmd::BLOCKNOTIFY], false);
            std::thread::sleep(Duration::from_millis(200));
        });
        let (shared, notify) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        // The configuration's rebuild request is folded into the block wake: a new tip
        // rebuilds every job anyway.
        assert_eq!(notify.wait(Duration::from_secs(1)), Wake::Block(None));
        assert_eq!(notify.wait(Duration::from_millis(50)), Wake::Timeout);
        pool.join().unwrap();
        session.join().unwrap();
    }

    #[test]
    fn sections_are_sent_once_per_slot_and_the_subsidy_only_coinbase_apart_from_id_seven() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            let first = p.share();
            assert!(first.job.is_some(), "the first share on a slot carries the job section");
            assert!(first.coinbase.is_some(), "and its coinbase");
            assert_eq!(first.coinbase.as_ref().unwrap().coinbase_id, 0);
            assert_eq!(first.username, "bc1qminer.rig");
            assert_eq!(first.nonce, 1);
            assert_eq!(first.blake2b.nonce_fields(), (1, 0));
            p.answer(&first, ShareVerdict::Accepted);
            let second = p.share();
            assert!(second.job.is_none(), "the pool holds the job section");
            assert!(second.coinbase.is_none(), "and coinbase 0");
            p.answer(&second, ShareVerdict::Rejected(RejectReason::HighHash));
            let subsidy = p.share();
            assert!(subsidy.job.is_none());
            assert_eq!(subsidy.coinbase.as_ref().map(|c| c.coinbase_id), Some(0xff));
            assert!(subsidy.subsidy_only);
            // A reason code this build does not name is still counted as a rejection.
            let mut r = ShareResponse {
                verdict: ShareVerdict::Rejected(RejectReason::HighHash),
                nonce: subsidy.nonce,
                target_byte: subsidy.target_byte,
                job_id: subsidy.job_id,
            }
            .encode();
            r[2] = 0xfe;
            r[3] = 0;
            p.send(&r, false);
            let seven = p.share();
            assert_eq!(
                seven.coinbase.as_ref().map(|c| c.coinbase_id),
                Some(5),
                "coinbase 5 is new to the pool"
            );
            let seven_again = p.share();
            assert!(seven_again.coinbase.is_none(), "and then known");
            let other_slot = p.share();
            assert!(other_slot.job.is_some(), "a job in another slot carries its section");
            assert_eq!(
                other_slot.username, "bc1qpool.rig",
                "a bare worker name is prefixed with the gateway's address"
            );
            std::thread::sleep(Duration::from_millis(200));
        });
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        let job0 = job(&shared, 0);
        let job1 = job(&shared, 1);
        shared.submit(queued(&job0, 0, 1, "bc1qminer.rig"));
        shared.submit(queued(&job0, 0, 2, "bc1qminer.rig"));
        shared.submit(queued(&job0, COINBASE_SUBSIDY_ONLY, 3, "bc1qminer.rig"));
        shared.submit(queued(&job0, 5, 4, "bc1qminer.rig"));
        shared.submit(queued(&job0, 5, 5, "bc1qminer.rig"));
        shared.submit(queued(&job1, 0, 6, ".rig"));
        pool.join().unwrap();
        session.join().unwrap();
        let st = ratum::lock(&shared.stats).clone();
        assert_eq!((st.accepted.count, st.rejected.count), (1, 2));
        assert_eq!(st.accepted.diff, 1024);
    }

    #[test]
    fn a_share_whose_slot_was_reused_is_not_sent() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            let only = p.share();
            assert_eq!(only.nonce, 2);
            std::thread::sleep(Duration::from_millis(200));
        });
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        let old = job(&shared, 0);
        let stale = queued(&old, 0, 1, "bc1qminer");
        // A newer job took slot 0 before the share was sent.
        let mut builder = Builder::new(Arc::new(config()));
        let mut newer =
            builder.build(Arc::clone(&old.template), false, Some(&pool_config()), None).unwrap();
        newer.serial = old.serial + 4;
        let newer = Arc::new(newer);
        ratum::lock(&shared.slots)[0] = Some(Arc::clone(&newer));
        shared.submit(stale);
        shared.submit(queued(&newer, 0, 2, "bc1qminer"));
        pool.join().unwrap();
        session.join().unwrap();
    }

    #[test]
    fn a_coinbaser_request_receives_a_response() {
        let (settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            let req = p.read_mining().expect("a coinbaser request");
            assert_eq!(req[0], client_subcmd::COINBASER_REQUEST);
            let value = u64::from_le_bytes(req[1..9].try_into().unwrap());
            assert_eq!(value, 5_000_000_000);
            let response = CoinbaserResponse {
                value,
                coinbaser_id: 3,
                outputs: vec![CoinbaseOutput { value: 1_000, script: ratum::fixtures::p2wpkh(1) }],
            };
            p.send(&response.encode().unwrap(), false);
            std::thread::sleep(Duration::from_millis(200));
        });
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        let response = shared.fetch_coinbaser(5_000_000_000, [0u8; 32]).expect("a response");
        assert_eq!(response.coinbaser_id, 3);
        assert_eq!(response.outputs.len(), 1);
        assert!(shared.fetch_coinbaser(1, [0u8; 32]).is_none(), "under the minimum value");
        pool.join().unwrap();
        session.join().unwrap();
    }

    #[test]
    fn shares_never_acknowledged_end_the_session() {
        let (mut settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            while p.read_mining().is_some() {}
        });
        settings.share_ack_timeout = Duration::from_millis(400);
        settings.share_ack_grace = Duration::from_millis(300);
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        wait_for("the configuration", || shared.is_active());
        let j = job(&shared, 0);
        for nonce in 0..20u32 {
            shared.submit(queued(&j, 0, nonce, "bc1qminer"));
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(matches!(session.join().unwrap(), SessionError::ShareAckTimeout(_)));
        pool.join().unwrap();
    }

    #[test]
    fn a_silent_pool_ends_the_session_after_the_global_timeout() {
        let (mut settings, pool) = start_pool(|p| {
            p.send(&config_payload(&pool_config()), true);
            std::thread::sleep(Duration::from_secs(2));
        });
        settings.global_timeout = Duration::from_millis(500);
        let (shared, _) = shared();
        let session = run_session(settings, Arc::clone(&shared));
        assert!(matches!(session.join().unwrap(), SessionError::GlobalTimeout(_)));
        pool.join().unwrap();
    }
}
