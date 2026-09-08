use crate::config::Config;
use crate::job::{Abw, Job, PoolConfig};
use crate::tally::Tally;
use crate::template::Notify;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::abw::{self, Activation, AssignmentNotice, Candidate, Reveal};
use ratum::datum::client::Client;
use ratum::datum::framing::{self, Header};
use ratum::datum::handshake::{KeyPairs, PUBKEY_LEN};
use ratum::datum::messages::{
    ClientConfig, ClientConfigV3, CoinbaserRequest, CoinbaserResponse, MigrationRequest,
    ResumeToken, ShareResponse, ShareVerdict, server_subcmd,
};
use ratum::datum::share::{self, Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::validation::{
    self, ParentFetchReply, ParentStatus, ShortTxnList, Status, TxnBundle,
};
use ratum::header::HeaderV2;
use ratum::io::read_exact_deadline;
use ratum::poll::PolledSocket;
use ratum::target;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const COINBASER_WAIT: Duration = Duration::from_secs(5);
pub const COINBASER_MIN_VALUE: u64 = 31_250_000;
pub const SHARE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
pub const SHARE_ACK_GRACE: Duration = Duration::from_secs(25);
const HANDSHAKE_READ_POLL: Duration = Duration::from_millis(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MINING_PAD_MAX: usize = 100;
const MIN_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
struct AbwSlots {
    keys: [Option<[u8; 32]>; abw::ASSIGNMENT_SLOTS as usize],
    active: Option<u8>,
}

impl AbwSlots {
    fn assignment(&self) -> Option<Abw> {
        let slot = self.active?;
        Some(Abw { slot, key_hash: self.keys[slot as usize]? })
    }

    fn holds(&self, a: Abw) -> bool {
        self.keys[a.slot as usize] == Some(a.key_hash)
    }

    fn install(&mut self, slot: u8, key_hash: [u8; 32], active: bool) {
        self.keys[slot as usize] = Some(key_hash);
        if active {
            self.active = Some(slot);
        }
    }

    fn activate(&mut self, slot: u8) -> bool {
        if self.keys[slot as usize].is_none() {
            return false;
        }
        self.active = Some(slot);
        true
    }

    fn reveal(&mut self, slot: u8, xor_key: &[u8; 16]) -> bool {
        if let Some(hash) = self.keys[slot as usize]
            && !abw::key_matches_hash(xor_key, &hash)
        {
            return false;
        }
        self.keys[slot as usize] = None;
        if self.active == Some(slot) {
            self.active = None;
        }
        true
    }
}

fn rounded_min_difficulty(min_difficulty: u64) -> u64 {
    let rounded = target::pow2_ceil(min_difficulty);
    if rounded != min_difficulty {
        warn!("pool minimum difficulty {min_difficulty} is not a power of two; using {rounded}");
    }
    rounded
}

impl PoolConfig {
    fn from_message(c: ClientConfig) -> Self {
        PoolConfig {
            payout_script: c.payout_script,
            prime_id: u64::from(c.prime_id),
            coinbase_tag: c.coinbase_tag,
            min_difficulty: rounded_min_difficulty(c.min_difficulty),
            protocol_v3: false,
            abw_disabled: false,
        }
    }

    fn from_message_v3(c: ClientConfigV3) -> Self {
        PoolConfig {
            payout_script: c.payout_script,
            prime_id: c.prime_id,
            coinbase_tag: c.coinbase_tag,
            min_difficulty: rounded_min_difficulty(c.min_difficulty),
            protocol_v3: true,
            abw_disabled: c.abw_disabled,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub accepted: Tally,
    pub rejected: Tally,
    pub motd: String,
}

#[derive(Clone)]
pub struct QueuedShare {
    pub job: Arc<Job>,
    pub coinbase_id: u8,
    pub is_block: bool,
    pub subsidy_only: bool,
    pub quickdiff: bool,
    pub target_byte: u8,
    pub header: HeaderV2,
    pub username: String,
}

pub struct CoinbaserRequestState {
    pub value: u64,
    pub prev_hash: [u8; 32],
    pub response: Mutex<Option<CoinbaserResponse>>,
    pub done: Condvar,
    pub superseded: AtomicBool,
}

pub struct Shared {
    config: Mutex<Option<PoolConfig>>,
    min_difficulty: AtomicU64,
    pub stats: Mutex<Stats>,
    queue: Mutex<VecDeque<QueuedShare>>,
    queue_capacity: usize,
    coinbaser: Mutex<Option<Arc<CoinbaserRequestState>>>,
    pub slots: Mutex<Vec<Option<Arc<Job>>>>,
    abw: Mutex<AbwSlots>,
    resume_token: Mutex<Option<ResumeToken>>,
    node: Option<ratum::rpc::Client>,
    pub notify: Arc<Notify>,
    pub failures: AtomicU32,
    waker: Mutex<Option<Arc<Waker>>>,
}

impl Shared {
    pub fn new(
        slots: usize,
        queue_capacity: usize,
        notify: Arc<Notify>,
        node: Option<ratum::rpc::Client>,
    ) -> Self {
        Shared {
            config: Mutex::new(None),
            min_difficulty: AtomicU64::new(0),
            stats: Mutex::new(Stats::default()),
            queue: Mutex::new(VecDeque::new()),
            queue_capacity: queue_capacity.max(MIN_QUEUE_CAPACITY),
            coinbaser: Mutex::new(None),
            slots: Mutex::new(vec![None; slots]),
            abw: Mutex::new(AbwSlots::default()),
            resume_token: Mutex::new(None),
            node,
            notify,
            failures: AtomicU32::new(0),
            waker: Mutex::new(None),
        }
    }

    fn wake(&self) {
        if let Some(w) = ratum::lock(&self.waker).as_ref()
            && let Err(e) = w.wake()
        {
            debug!("could not wake the DATUM session thread: {e}");
        }
    }

    pub fn require_abw(&self) -> bool {
        ratum::lock(&self.config).as_ref().is_some_and(|c| c.protocol_v3 && !c.abw_disabled)
    }

    pub fn abw_assignment(&self) -> Option<Abw> {
        ratum::lock(&self.abw).assignment()
    }

    pub fn resume_token(&self) -> Option<ResumeToken> {
        *ratum::lock(&self.resume_token)
    }

    pub fn is_active(&self) -> bool {
        ratum::lock(&self.config).is_some()
    }

    pub fn pool_config(&self) -> Option<PoolConfig> {
        ratum::lock(&self.config).clone()
    }

    pub fn payout_script(&self) -> Option<Vec<u8>> {
        ratum::lock(&self.config).as_ref().map(|c| c.payout_script.clone())
    }

    pub fn min_difficulty(&self) -> u64 {
        self.min_difficulty.load(Ordering::Relaxed)
    }

    fn set_config(&self, config: PoolConfig) -> Option<PoolConfig> {
        self.min_difficulty.store(config.min_difficulty, Ordering::Relaxed);
        ratum::lock(&self.config).replace(config)
    }

    fn disconnected(&self) -> bool {
        *ratum::lock(&self.waker) = None;
        let was_active = ratum::lock(&self.config).take().is_some();
        if let Some(state) = ratum::lock(&self.coinbaser).take() {
            state.done.notify_all();
        }
        ratum::lock(&self.queue).clear();
        *ratum::lock(&self.abw) = AbwSlots::default();
        was_active
    }

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
        drop(q);
        self.wake();
    }

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
        self.wake();
        let guard = ratum::lock(&state.response);
        let (guard, _) = state
            .done
            .wait_timeout_while(guard, COINBASER_WAIT, |r| {
                r.is_none() && !state.superseded.load(Ordering::SeqCst)
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    pub share_ack_timeout: Duration,
    pub share_ack_grace: Duration,
    pub user_agent: String,
    pub pass_full_users: bool,
    pub pass_workers: bool,
    pub pool_address: String,
    pub protocol_v3: bool,
}

impl Settings {
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
            protocol_v3: config.datum.protocol_v3,
        }
    }
}

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

pub fn parse_pool_pubkey(s: &str) -> Result<([u8; PUBKEY_LEN], [u8; PUBKEY_LEN]), String> {
    const HEX_CHARS: usize = 2 * (2 * PUBKEY_LEN);
    if s.len() != HEX_CHARS {
        return Err(format!("pool_pubkey must be {HEX_CHARS} hex characters, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("pool_pubkey is not hex: {e}"))?;
    let (sign, boxed) = bytes.split_at(PUBKEY_LEN);
    Ok((sign.try_into().unwrap(), boxed.try_into().unwrap()))
}

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

struct Session<'a> {
    settings: &'a Settings,
    shared: &'a Shared,
    identity: &'a KeyPairs,
    socket: PolledSocket,
    client: Client,
    last_server_msg: Instant,
    last_share_sent: Option<Instant>,
    last_share_accepted: Option<Instant>,
    sent_job: Vec<Option<SentSections>>,
    requested: Option<Arc<CoinbaserRequestState>>,
    pending_header: Vec<u8>,
}

const COINBASE_SLOTS: usize = 8;

#[derive(Clone, Copy)]
struct SentSections {
    serial: u64,
    job: bool,
    coinbases: [bool; COINBASE_SLOTS],
    subsidy_only: bool,
}

impl SentSections {
    fn new(serial: u64) -> Self {
        SentSections { serial, job: false, coinbases: [false; COINBASE_SLOTS], subsidy_only: false }
    }

    fn coinbase_known(&mut self, coinbase_id: u8) -> bool {
        let slot = if coinbase_id == share::COINBASE_ID_SUBSIDY_ONLY {
            &mut self.subsidy_only
        } else {
            &mut self.coinbases[coinbase_id as usize % COINBASE_SLOTS]
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
        stream.set_read_timeout(Some(HANDSHAKE_READ_POLL))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let mut client =
            Client::with_key_pairs(identity.clone(), KeyPairs::generate(), ratum::rand::u32());
        let hello = if settings.protocol_v3 {
            let token = shared.resume_token();
            client.hello_resumable(&settings.pool_box_pk, &settings.user_agent, token.as_ref())
        } else {
            client.hello(&settings.pool_box_pk, &settings.user_agent)
        };
        stream.write_all(&hello)?;
        stream.flush()?;

        let started = Instant::now();
        let mut frame = read_exact_deadline(
            &mut stream,
            framing::HEADER_LEN,
            started,
            settings.global_timeout,
        )?;
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

        let socket = PolledSocket::new(stream)?;
        *ratum::lock(&shared.waker) = Some(Arc::new(socket.waker()?));

        let slots = ratum::lock(&shared.slots).len();
        Ok(Session {
            settings,
            shared,
            identity,
            socket,
            client,
            last_server_msg: Instant::now(),
            last_share_sent: None,
            last_share_accepted: None,
            sent_job: vec![None; slots],
            requested: None,
            pending_header: Vec::with_capacity(framing::HEADER_LEN),
        })
    }

    fn send_mining(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        let pad = ratum::rand::bytes::<MINING_PAD_MAX>();
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
        self.socket.write_all(&wire, WRITE_TIMEOUT)?;
        Ok(())
    }

    /// Reads one frame body, sharing the session's global timeout with every other read
    /// since the last message from the pool.
    fn read_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let left = self.settings.global_timeout.saturating_sub(self.last_server_msg.elapsed());
        let mut buf = vec![0u8; n];
        self.socket.read_exact(&mut buf, left, left)?;
        Ok(buf)
    }

    fn poll_header(&mut self) -> Result<Option<Header>, SessionError> {
        let mut byte = [0u8; framing::HEADER_LEN];
        match self.socket.read(&mut byte[..framing::HEADER_LEN - self.pending_header.len()])? {
            Some(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Some(n) => self.pending_header.extend_from_slice(&byte[..n]),
            None => {}
        }
        if self.pending_header.len() < framing::HEADER_LEN {
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

            if !self.socket.readable() {
                let timeout =
                    self.settings.global_timeout.saturating_sub(self.last_server_msg.elapsed());
                self.socket.wait(Some(timeout))?;
                continue;
            }
            let Some(header) = self.poll_header()? else { continue };
            let body = self.read_body(header.cmd_len as usize)?;
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
                self.on_config_message(plain);
            }
            Some(server_subcmd::MIGRATION) => {
                if !header.is_signed {
                    error!("migration request was not signed; ignored");
                    return Ok(());
                }
                log_migration_request(plain);
            }
            Some(abw::subcmd::ASSIGNMENT_NOTICE) => self.on_abw_notice(plain),
            Some(abw::subcmd::ACTIVATION) => self.on_abw_activation(plain),
            Some(abw::subcmd::REVEAL) => self.on_abw_reveal(plain),
            Some(abw::subcmd::CANDIDATE_RECEIPT) => {
                if let Ok(c) = Candidate::decode(plain, abw::subcmd::CANDIDATE_RECEIPT) {
                    debug!("ABW candidate receipt for slot {}", c.slot);
                }
            }
            Some(abw::subcmd::CANDIDATE_RELEASE) => {}
            Some(server_subcmd::COINBASER) => self.on_coinbaser_response(plain),
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

    fn on_coinbaser_response(&mut self, plain: &[u8]) {
        let Some(state) = ratum::lock(&self.shared.coinbaser).clone() else {
            warn!("coinbaser response with no request waiting");
            return;
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
            None => {
                error!("malformed coinbaser response; the job pays the pool script alone");
                CoinbaserResponse { value: state.value, coinbaser_id: 0, outputs: Vec::new() }
            }
        };
        *ratum::lock(&state.response) = Some(r);
        state.done.notify_all();
    }

    fn on_config_message(&mut self, plain: &[u8]) {
        if self.settings.protocol_v3
            && let Some(c) = ClientConfigV3::decode(plain)
        {
            *ratum::lock(&self.shared.resume_token) = Some(c.resume_token);
            self.on_config(PoolConfig::from_message_v3(c));
            return;
        }
        let Some(c) = ClientConfig::decode(plain) else {
            error!("malformed pool configuration; ignored");
            return;
        };
        if self.settings.protocol_v3 {
            warn!(
                "pool responded to the version 3 hello with a version 1 configuration; this \
                 session runs version 1 (no anti-block-withholding)"
            );
        }
        self.on_config(PoolConfig::from_message(c));
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
        if config.protocol_v3 {
            info!(
                "DATUM pool anti-block-withholding: {}",
                if config.abw_disabled { "disabled by the pool" } else { "enabled" }
            );
        }
        if previous.as_ref().is_some_and(|p| p.abw_disabled != config.abw_disabled) {
            *ratum::lock(&self.shared.abw) = AbwSlots::default();
        }
        if previous.as_ref() != Some(&config) {
            self.shared.notify.rebuild();
        }
    }

    fn on_abw_notice(&mut self, plain: &[u8]) {
        let notice = match AssignmentNotice::decode(plain) {
            Ok(n) => n,
            Err(e) => {
                error!("malformed ABW assignment notice: {e}");
                return;
            }
        };
        ratum::lock(&self.shared.abw).install(notice.slot, notice.key_hash, notice.active);
        debug!("ABW assignment for slot {} (active {})", notice.slot, notice.active);
        if notice.active {
            self.shared.notify.rebuild();
        }
    }

    fn on_abw_activation(&mut self, plain: &[u8]) {
        let act = match Activation::decode(plain) {
            Ok(a) => a,
            Err(e) => {
                error!("malformed ABW activation: {e}");
                return;
            }
        };
        if ratum::lock(&self.shared.abw).activate(act.slot) {
            debug!("ABW slot {} activated", act.slot);
            self.shared.notify.rebuild();
        } else {
            error!("ABW activation for slot {} that was not seeded", act.slot);
        }
    }

    fn on_abw_reveal(&mut self, plain: &[u8]) {
        let reveal = match Reveal::decode(plain) {
            Ok(r) => r,
            Err(e) => {
                error!("malformed ABW reveal: {e}");
                return;
            }
        };
        if !ratum::lock(&self.shared.abw).reveal(reveal.slot, &reveal.xor_key) {
            error!("ABW reveal for slot {} does not match its commitment; ignored", reveal.slot);
            return;
        }
        debug!("ABW slot {} revealed", reveal.slot);
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
        let Some(&sub) = plain.get(validation::SELECTOR_AT) else { return Ok(()) };
        let job_index = plain.get(validation::JOB_INDEX_AT).copied();
        let lookup = job_index
            .ok_or((validation::JOB_INDEX_INVALID, Status::BadRequest))
            .and_then(|i| self.shared.slot(i));
        let response = match sub {
            validation::request::SHORT_TXN_LIST => {
                info!("pool requested the short transaction list of job {job_index:?}");
                match lookup {
                    Ok(job) => self.short_txn_list(&job),
                    Err((idx, status)) => ShortTxnList::empty(idx, status),
                }
                .encode()
            }
            validation::request::TXNS | validation::request::BLOCK_TXNS => {
                let all = sub == validation::request::BLOCK_TXNS;
                let bundle = txn_bundle(lookup, plain, all);
                info!(
                    "pool requested {} of job {job_index:?}: sending {}",
                    if all { "the block transactions" } else { "transactions" },
                    bundle.txns.len()
                );
                bundle.encode()
            }
            validation::request::PARENT_FETCH => {
                if plain.len() != validation::PARENT_FETCH_REQUEST_LEN {
                    warn!("malformed parent fetch request ({} bytes)", plain.len());
                    return Ok(());
                }
                let idx = plain[validation::JOB_INDEX_AT];
                let parent_hash: [u8; 32] =
                    plain[validation::REQUEST_HEADER_LEN..].try_into().expect("32 bytes");
                let (status, block) = match lookup {
                    Ok(job) if job.template.prev_hash == parent_hash => {
                        self.fetch_parent(&job.template.prev_hash_hex)
                    }
                    _ => (ParentStatus::JobMismatch, Vec::new()),
                };
                info!(
                    "pool requested the parent block of job {idx}: {status:?}, {} bytes",
                    block.len()
                );
                ParentFetchReply { job_index: idx, status, parent_hash, block }.encode()
            }
            other => {
                warn!("unknown validation request {other:#04x}");
                return Ok(());
            }
        };
        self.send_mining(&response)
    }

    fn fetch_parent(&self, hash_hex: &str) -> (ParentStatus, Vec<u8>) {
        let Some(node) = &self.shared.node else { return (ParentStatus::Unavailable, Vec::new()) };
        match node.call("getblock", serde_json::json!([hash_hex, 0])) {
            Ok(serde_json::Value::String(hex)) => match hex::decode(&hex) {
                Ok(block)
                    if !block.is_empty() && block.len() <= validation::MAX_PARENT_FETCH_BLOCK =>
                {
                    (ParentStatus::Success, block)
                }
                _ => (ParentStatus::RpcFailed, Vec::new()),
            },
            Ok(_) => (ParentStatus::RpcFailed, Vec::new()),
            Err(e) => {
                warn!("getblock for the parent fetch failed: {e}");
                (ParentStatus::Unavailable, Vec::new())
            }
        }
    }

    fn short_txn_list(&self, job: &Job) -> ShortTxnList {
        let hashes = job.template.witness_hashes();
        if hashes.len() > validation::MAX_SHORT_LIST_TXNS as usize {
            return ShortTxnList::empty(job.datum_slot, Status::TooManyTxns);
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
        if self.settings.protocol_v3
            && (!self.shared.is_active()
                || (self.shared.require_abw() && self.shared.abw_assignment().is_none()))
        {
            return Ok(());
        }
        let batch = std::mem::take(&mut *ratum::lock(&self.shared.queue));
        for share in batch {
            self.send_share(share)?;
        }
        Ok(())
    }

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
            let c = job.coinbase(share.coinbase_id);
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
        let current =
            ratum::lock(&self.shared.slots)[job.datum_slot as usize].as_ref().map(|j| j.serial);
        if current != Some(job.serial) {
            debug!("share for job {} whose DATUM slot was reused; not sent", job.serial);
            return Ok(());
        }
        if let Some(a) = job.abw
            && !ratum::lock(&self.shared.abw).holds(a)
        {
            warn!(
                "share on ABW slot {} whose commitment this session does not hold (revealed, \
                 or seeded anew after a reconnect); not sent",
                a.slot
            );
            return Ok(());
        }
        let h = &share.header;
        let Some(extranonce) = share::share_extranonce(&h.extranonce) else {
            warn!("share header extranonce does not begin with four zero bytes; not sent");
            return Ok(());
        };
        let (job_section, coinbase_section) = self.sections_for(&share);
        let blake2b = Blake2bSection::from_header(h);
        let submit = PowSubmit {
            job_id: job.datum_slot,
            coinbase_id: share.coinbase_id,
            is_block: share.is_block,
            subsidy_only: share.subsidy_only,
            quickdiff: share.quickdiff,
            target_byte: share.target_byte,
            ntime: blake2b.time_fields().0,
            nonce: h.nonce,
            version: ratum::header::V2_FLAG | h.version as u32,
            extranonce,
            username: wire_username(self.settings, &share.username),
            use_time_offset: h.flags & ratum::header::FLAG_USE_TIME_OFFSET != 0,
            job: job_section,
            coinbase: coinbase_section,
            blake2b,
            abw_slot: job.abw.map(|a| a.slot),
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

fn log_migration_request(plain: &[u8]) {
    match MigrationRequest::decode(plain) {
        Some(MigrationRequest { target: Some(t) }) => warn!(
            "pool requested migration to {:?} port {} (pool key {}); not supported, staying \
             on the configured pool",
            t.host,
            t.port,
            &hex::encode(t.pubkey)[..16]
        ),
        Some(MigrationRequest { target: None }) => {
            warn!("pool requested a return to the configured pool; this gateway is on it")
        }
        None => error!("malformed migration request; ignored"),
    }
}

fn txn_bundle(lookup: Result<Arc<Job>, (u8, Status)>, plain: &[u8], all: bool) -> TxnBundle {
    let selector = if all { validation::response::BLOCK_TXNS } else { validation::response::TXNS };
    let job = match lookup {
        Ok(job) => job,
        Err((idx, status)) => return TxnBundle::empty(selector, idx, status),
    };
    let txns = &job.template.txns;
    let ids = if all { Some((0..txns.len()).collect()) } else { requested_ids(plain, txns.len()) };
    match ids {
        Some(ids) => TxnBundle {
            selector,
            job_index: job.datum_slot,
            status: Status::Ok,
            txns: ids.iter().map(|&i| txns[i].raw.clone()).collect(),
        },
        None => TxnBundle::empty(selector, job.datum_slot, Status::BadRequest),
    }
}

fn requested_ids(plain: &[u8], txn_count: usize) -> Option<Vec<usize>> {
    let mut c = ratum::cursor::Cursor::new(plain.get(validation::REQUEST_HEADER_LEN..)?);
    let count = usize::from(c.u16("index count").ok()?);
    if count == 0 || count > txn_count {
        return None;
    }
    let ids: Vec<usize> = c
        .take(count * size_of::<u16>(), "indexes")
        .ok()?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| usize::from(u16::from_le_bytes(*b)))
        .collect();
    ids.iter().all(|&i| i < txn_count).then_some(ids)
}

const RECONNECT_DELAY_MIN: Duration = Duration::from_secs(5);
const RECONNECT_DELAY_SPREAD: Duration = Duration::from_secs(15);

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
        let delay = RECONNECT_DELAY_MIN
            + Duration::from_millis(u64::from(
                ratum::rand::u32() % (RECONNECT_DELAY_SPREAD.as_millis() as u32 + 1),
            ));
        info!("reconnecting to the pool in {:.1}s", delay.as_secs_f64());
        std::thread::sleep(delay);
    }
}
