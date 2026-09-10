use super::{
    AbwSlots, CoinbaserRequestState, Pool, QueuedShare, Settings, validation, wire_username,
};
use crate::job::PoolConfig;
use log::{debug, error, info, warn};
use ratum::datum::abw::{self, Activation, AssignmentNotice, Candidate, Reveal};
use ratum::datum::client::Client;
use ratum::datum::framing::{self, Header};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::{
    ClientConfig, ClientConfigV3, CoinbaserRequest, CoinbaserResponse, MigrationRequest,
    ShareResponse, ShareVerdict, server_subcmd,
};
use ratum::datum::share::{self, Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::io::read_exact_deadline;
use ratum::poll::PolledSocket;
use ratum::target;
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SHARE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const SHARE_ACK_GRACE: Duration = Duration::from_secs(25);
const HANDSHAKE_READ_POLL: Duration = Duration::from_millis(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MINING_PAD_MAX: usize = 100;

pub(super) fn run(
    settings: &Settings,
    pool: &Pool,
    identity: &KeyPairs,
) -> Result<(), SessionError> {
    Session::open(settings, pool, identity).and_then(|mut session| session.run())
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
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
    pool: &'a Pool,
    identity: &'a KeyPairs,
    socket: PolledSocket,
    client: Client,
    last_server_msg: Instant,
    last_share_sent: Option<Instant>,
    last_share_accepted: Option<Instant>,
    sent_job: Vec<Option<SentSections>>,
    requested: Option<Arc<CoinbaserRequestState>>,
    pending_header: [u8; framing::HEADER_LEN],
    pending_header_len: usize,
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
        Self { serial, job: false, coinbases: [false; COINBASE_SLOTS], subsidy_only: false }
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
        pool: &'a Pool,
        identity: &'a KeyPairs,
    ) -> Result<Self, SessionError> {
        let mut stream = connect(settings)?;
        stream.set_read_timeout(Some(HANDSHAKE_READ_POLL))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let mut client =
            Client::with_key_pairs(identity.clone(), KeyPairs::generate(), ratum::rand::u32());
        let hello = if settings.protocol_v3 {
            let token = pool.resume_token();
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
        *ratum::lock(&pool.waker) = Some(Arc::new(socket.waker()?));

        let slots = ratum::lock(&pool.slots).len();
        Ok(Session {
            settings,
            pool,
            identity,
            socket,
            client,
            last_server_msg: Instant::now(),
            last_share_sent: None,
            last_share_accepted: None,
            sent_job: vec![None; slots],
            requested: None,
            pending_header: [0u8; framing::HEADER_LEN],
            pending_header_len: 0,
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

    fn read_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let left = self.settings.global_timeout.saturating_sub(self.last_server_msg.elapsed());
        let mut buf = vec![0u8; n];
        self.socket.read_exact(&mut buf, left, left)?;
        Ok(buf)
    }

    fn poll_header(&mut self) -> Result<Option<Header>, SessionError> {
        match self.socket.read(&mut self.pending_header[self.pending_header_len..])? {
            Some(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Some(n) => self.pending_header_len += n,
            None => {}
        }
        if self.pending_header_len < framing::HEADER_LEN {
            return Ok(None);
        }
        self.pending_header_len = 0;
        let header = self.client.unmask_header(self.pending_header);
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
                && sent.duration_since(acked) >= SHARE_ACK_TIMEOUT
            {
                return Err(SessionError::ShareAckTimeout(SHARE_ACK_TIMEOUT));
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
                self.pool.notify.raise();
            }
            other => warn!("unknown DATUM mining sub-command {other:?}"),
        }
        Ok(())
    }

    fn on_coinbaser_response(&self, plain: &[u8]) {
        let Some(state) = ratum::lock(&self.pool.coinbaser).clone() else {
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

    fn on_config_message(&self, plain: &[u8]) {
        if self.settings.protocol_v3
            && let Some(c) = ClientConfigV3::decode(plain)
        {
            *ratum::lock(&self.pool.resume_token) = Some(c.resume_token);
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

    fn on_config(&self, config: PoolConfig) {
        info!(
            "DATUM pool configuration: prime_id {:#010x}, tag {:?}, min diff {}, payout script {}",
            config.prime_id,
            config.coinbase_tag,
            config.min_difficulty,
            hex::encode(&config.payout_script)
        );
        let previous = self.pool.set_config(config.clone());
        if previous.is_none() {
            ratum::lock(&self.pool.stats).motd = self.client.motd().to_string();
        }
        if config.protocol_v3 {
            info!(
                "DATUM pool anti-block-withholding: {}",
                if config.abw_disabled { "disabled by the pool" } else { "enabled" }
            );
        }
        if previous.as_ref().is_some_and(|p| p.abw_disabled != config.abw_disabled) {
            *ratum::lock(&self.pool.abw) = AbwSlots::default();
        }
        if previous.as_ref() != Some(&config) {
            self.pool.notify.rebuild();
        }
    }

    fn on_abw_notice(&self, plain: &[u8]) {
        let Some(notice) = decoded("assignment notice", AssignmentNotice::decode(plain)) else {
            return;
        };
        ratum::lock(&self.pool.abw).install(notice.slot, notice.key_hash, notice.active);
        debug!("ABW assignment for slot {} (active {})", notice.slot, notice.active);
        if notice.active {
            self.pool.notify.rebuild();
        }
    }

    fn on_abw_activation(&self, plain: &[u8]) {
        let Some(act) = decoded("activation", Activation::decode(plain)) else { return };
        if ratum::lock(&self.pool.abw).activate(act.slot) {
            debug!("ABW slot {} activated", act.slot);
            self.pool.notify.rebuild();
        } else {
            error!("ABW activation for slot {} that was not seeded", act.slot);
        }
    }

    fn on_abw_reveal(&self, plain: &[u8]) {
        let Some(reveal) = decoded("reveal", Reveal::decode(plain)) else { return };
        if !ratum::lock(&self.pool.abw).reveal(reveal.slot, &reveal.xor_key) {
            error!("ABW reveal for slot {} does not match its commitment; ignored", reveal.slot);
            return;
        }
        debug!("ABW slot {} revealed", reveal.slot);
    }

    fn on_share_response(&mut self, r: ShareResponse) {
        let diff = if r.target_byte == ratum::datum::coinbase::POT_TARGET_PLACEHOLDER {
            self.pool.min_difficulty().max(1)
        } else {
            target::diff_for_pot(r.target_byte)
        };
        let accepted =
            matches!(r.verdict, ShareVerdict::Accepted | ShareVerdict::AcceptedTentatively);
        {
            let mut st = ratum::lock(&self.pool.stats);
            if accepted { &mut st.accepted } else { &mut st.rejected }.add(diff);
        }
        let what = format!("job {} nonce {:08x} diff {diff}", r.job_id, r.nonce);
        match r.verdict {
            ShareVerdict::Accepted => debug!("DATUM share accepted: {what}"),
            ShareVerdict::AcceptedTentatively => {
                debug!("DATUM share accepted: {what} (tentatively)");
            }
            ShareVerdict::Rejected(reason) => {
                warn!("DATUM share rejected: {what}: {reason:?} ({})", reason.code());
            }
            ShareVerdict::RejectedUnknown(code) => {
                warn!(
                    "DATUM share rejected: {what}: reason code {code} (not one this build names)"
                );
            }
        }
        if accepted {
            self.last_share_accepted = Some(Instant::now());
        }
    }

    fn on_validation(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        match validation::response_to(self.pool, self.settings, self.identity, plain) {
            Some(response) => self.send_mining(&response),
            None => Ok(()),
        }
    }

    fn send_pending(&mut self) -> Result<(), SessionError> {
        let request = ratum::lock(&self.pool.coinbaser).clone();
        if let Some(state) = request
            && !self.requested.as_ref().is_some_and(|r| Arc::ptr_eq(r, &state))
        {
            let req = CoinbaserRequest { value: state.value, prev_hash: state.prev_hash };
            debug!("coinbaser request: {} sats", state.value);
            self.send_mining(&req.encode())?;
            self.requested = Some(state);
        }
        if self.settings.protocol_v3
            && (!self.pool.is_active()
                || (self.pool.require_abw() && self.pool.abw_assignment().is_none()))
        {
            return Ok(());
        }
        let batch = std::mem::take(&mut *ratum::lock(&self.pool.queue));
        for share in &batch {
            self.send_share(share)?;
        }
        Ok(())
    }

    fn sections_for(
        &mut self,
        share: &QueuedShare,
    ) -> (Option<JobSection>, Option<CoinbaseSection>) {
        let job = &share.job;
        let sent = self.sent_job[job.datum_slot as usize]
            .get_or_insert_with(|| SentSections::new(job.serial));
        if sent.serial != job.serial {
            *sent = SentSections::new(job.serial);
        }
        let job_section = (!std::mem::replace(&mut sent.job, true)).then(|| JobSection {
            prev_hash: job.template.prev_hash,
            target_byte_index: job.pooled.pot_index as u16,
            nbits: job.template.nbits.to_le_bytes(),
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

    fn send_share(&mut self, share: &QueuedShare) -> Result<(), SessionError> {
        let job = &share.job;
        let current =
            ratum::lock(&self.pool.slots)[job.datum_slot as usize].as_ref().map(|j| j.serial);
        if current != Some(job.serial) {
            debug!("share for job {} whose DATUM slot was reused; not sent", job.serial);
            return Ok(());
        }
        if let Some(a) = job.abw
            && !ratum::lock(&self.pool.abw).holds(a)
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
        let (job_section, coinbase_section) = self.sections_for(share);
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
        if self.last_share_sent.is_none_or(|t| now.duration_since(t) > SHARE_ACK_GRACE) {
            self.last_share_accepted = Some(now);
        }
        self.last_share_sent = Some(now);
        Ok(())
    }
}

fn decoded<T>(what: &str, decoded: Result<T, abw::Error>) -> Option<T> {
    decoded.inspect_err(|e| error!("malformed ABW {what}: {e}")).ok()
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
            warn!("pool requested a return to the configured pool; this gateway is on it");
        }
        None => error!("malformed migration request; ignored"),
    }
}
