//! One gateway connection from its hello to its end: the handshake, the configuration and
//! assignments it opens with, and the frames it reads and dispatches.

mod assignments;
mod shares;

use crate::abw::AbwSlotState;
use crate::bounded::BoundedSet;
use crate::payout;
use crate::server::Server;
use crate::sessions::{SavedSession, V3Session};
use crate::verify::Verifier;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::bulk::{self, Reassembler};
use ratum::datum::framing::{self, FrameHeader, FrameRead, HeaderKeyRatchet};
use ratum::datum::handshake::{ProtocolVersion, ResumeToken};
use ratum::datum::messages::client_subcmd;
use ratum::datum::messages::coinbaser::CoinbaserRequest;
use ratum::datum::messages::validation;
use ratum::datum::server::{Hello, ServerChannel, accept, open_hello};
use ratum::lock;
use ratum::poll::{PolledSocket, WRITE_TIMEOUT};
use std::collections::VecDeque;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LOG_PAYLOAD_BYTES: usize = 16;
const LOG_HEX_CHARS: usize = 16;
/// How long a connection has from its acceptance to send its hello. It holds one of the
/// `--max-connections` slots meanwhile, so the deadline bounds what an idle connection costs.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_BODY_DEADLINE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const MAX_HELLO_FRAME_LEN: usize = 4 * 1024;
/// The largest frame a gateway may send while the pool has asked it for no job's
/// transactions: only a transaction list reply (0x50 0x92) reaches the protocol's 4 MiB, and
/// the pool sends the request it answers. The largest other message is a share carrying a
/// job section of 24 branches and a coinbase section at `MAX_COINBASE_SECTION_LEN`, about 34
/// KiB with its pad and MAC; a bulk fragment is 16 KiB.
const MAX_UNSOLICITED_FRAME_LEN: usize = 64 * 1024;
/// How long a connection is kept without a frame from the gateway. A gateway sends a coinbaser
/// request for every job it builds, about every 40 seconds with or without miners, so only a
/// connection that stopped serving goes this long without one.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// The coinbaser requests a gateway may send at once, and how many a second after that. A
/// gateway requests one a job; the budget bounds the splits (and the ledger reads building
/// them) one connection can make the pool produce.
const COINBASER_BURST: f64 = 16.0;
const COINBASER_PER_SEC: f64 = 1.0;

fn describe(header: FrameHeader, payload: &[u8]) -> String {
    let sub = payload.first().copied();
    let name = match (header.proto_cmd, sub) {
        (framing::cmd::MINING, Some(client_subcmd::COINBASER_REQUEST)) => "coinbaser request",
        (framing::cmd::MINING, Some(client_subcmd::SUBMIT_POW)) => "share submission",
        (framing::cmd::MINING, Some(validation::SUBCMD)) => "job validation response",
        (framing::cmd::MINING, _) => "mining (unknown sub-command)",
        (framing::cmd::BULK, _) => "bulk fragment",
        (framing::cmd::HELLO_OR_PING, _) => "ping",
        _ => "unknown",
    };
    let head = hex::encode(&payload[..payload.len().min(LOG_PAYLOAD_BYTES)]);
    format!("{name}: {} bytes [{head}...]", payload.len())
}

fn read_hello(
    socket: &mut PolledSocket,
    server: &Server,
    peer: std::net::SocketAddr,
    started_at: Instant,
) -> io::Result<Option<Hello>> {
    let (header, payload) = framing::read_frame(
        socket,
        |bytes| HeaderKeyRatchet::initial().unmask(bytes),
        MAX_HELLO_FRAME_LEN,
        started_at + HANDSHAKE_DEADLINE,
    )?;
    debug!(
        "[{peer}] hello header: cmd={} len={} signed={} encrypted_pubkey={}",
        header.proto_cmd, header.cmd_len, header.is_signed, header.is_encrypted_pubkey
    );
    match open_hello(header, &payload, &server.pool_keys) {
        Ok(hello) => Ok(Some(hello)),
        Err(e) => {
            warn!("[{peer}] hello rejected: {e}");
            Ok(None)
        }
    }
}

pub fn handle(stream: TcpStream, server: &Server) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    debug!("[{peer}] connected");
    let mut socket = PolledSocket::new(stream)?;

    let handshake_started_at = Instant::now();
    let Some(hello) = read_hello(&mut socket, server, peer, handshake_started_at)? else {
        return Ok(());
    };
    let protocol_version = hello.protocol_version;
    let client_sign_pk = hello.client.sign_pk;
    if server.settings.require_v3 && protocol_version == ProtocolVersion::V1 {
        warn!(
            "[{peer}] hello refused: agent {:?} uses the version 1 protocol (no DRS \
             extension) and this pool requires version 3 (--require-v3)",
            hello.user_agent
        );
        return Ok(());
    }
    info!(
        "[{peer}] hello ok: ua={:?} nk={:#010x} client={} session={} protocol_version={}",
        hello.user_agent,
        hello.nk,
        &hex::encode(hello.client.sign_pk)[..LOG_HEX_CHARS],
        &hex::encode(hello.session.sign_pk)[..LOG_HEX_CHARS],
        match protocol_version {
            ProtocolVersion::V1 => "v1",
            ProtocolVersion::V3 { .. } => "v3",
        },
    );

    let (response, channel): (Vec<u8>, ServerChannel) =
        match accept(hello, &server.pool_keys, &server.settings.motd) {
            Ok(v) => v,
            Err(e) => {
                error!("[{peer}] could not build handshake response: {e}");
                return Ok(());
            }
        };
    socket.write_all(&response, WRITE_TIMEOUT)?;
    debug!("[{peer}] handshake response sent ({} bytes)", response.len());

    let waker = Arc::new(socket.waker()?);
    server.node_state.add_waker(&waker);

    let mut conn = Connection {
        server,
        peer,
        opened_at: handshake_started_at,
        socket,
        waker,
        channel,
        verifier: Verifier::new(&server.share_policy),
        reported_unpayable: BoundedSet::new(shares::MAX_REPORTED_UNPAYABLE),
        held: Vec::new(),
        txn_requests: VecDeque::new(),
        warned: shares::WarnCounts::default(),
        coinbaser_budget: RequestBudget::full(COINBASER_BURST),
        last_frame_at: Instant::now(),
        last_send_at: Instant::now(),
        client_sign_pk,
        v3: None,
        resumed_from: None,
        proven: false,
        bulk: Reassembler::new(),
    };

    match protocol_version {
        ProtocolVersion::V1 => {
            conn.send_mining(&server.config_payload, true)?;
            debug!("[{peer}] sent v1 0x99 config ({} bytes, signed)", server.config_payload.len());
        }
        ProtocolVersion::V3 { resume } => conn.start_v3_session(resume.as_ref())?,
    }

    conn.run()
}

struct Connection<'a> {
    server: &'a Server,
    peer: std::net::SocketAddr,
    opened_at: Instant,
    socket: PolledSocket,
    waker: Arc<Waker>,
    channel: ServerChannel,
    verifier: Verifier<'a>,
    /// The unpayable identities already reported at warn level on this connection. One
    /// connection carries every miner on a gateway, so each bad username is named once
    /// rather than only the first; the set is bounded so a gateway sending many of them
    /// cannot fill the log.
    reported_unpayable: BoundedSet<String>,
    /// The shares waiting for their job's transactions, in the order they arrived.
    held: Vec<shares::HeldShare>,
    /// The requests for jobs' transactions not yet answered, in the order they were sent.
    txn_requests: VecDeque<shares::TxnRequest>,
    warned: shares::WarnCounts,
    coinbaser_budget: RequestBudget,
    last_frame_at: Instant,
    last_send_at: Instant,
    client_sign_pk: [u8; 32],
    v3: Option<V3Session>,
    /// The token of the saved session this connection holds a copy of, until `proven`
    /// removes that session from the store.
    resumed_from: Option<ResumeToken>,
    /// Whether a frame from the gateway has decrypted under the session keys, which a copy
    /// of its hello sent by another party cannot produce. The session is saved for resume
    /// only then.
    proven: bool,
    bulk: Reassembler,
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.server.node_state.remove_waker(&self.waker);
        if let Some(v3) = self.v3.take() {
            if self.proven {
                let session = SavedSession {
                    v3,
                    splits: self.verifier.take_splits(),
                    saved_at: Instant::now(),
                    connection_opened_at: self.opened_at,
                };
                lock(&self.server.sessions).save(self.client_sign_pk, session);
                debug!("[{}] session saved for resume", self.peer);
            } else {
                debug!(
                    "[{}] session not saved: no frame from the gateway decrypted on this \
                     connection",
                    self.peer
                );
            }
        }
        if !self.held.is_empty() {
            warn!(
                "[{}]      {} share(s) waiting for their jobs' transactions or parent were not \
                 answered before the connection closed, and are not credited; the hashes of \
                 those that verified are released so a gateway replaying them on its next \
                 connection can be credited",
                self.peer,
                self.held.len()
            );
            let mut accepted = lock(&self.server.accepted_hashes);
            for hash in self.held.iter().filter_map(shares::HeldShare::claimed_hash) {
                accepted.remove(&hash);
            }
        }
    }
}

impl Connection<'_> {
    fn send_frame(&mut self, cmd: u8, payload: &[u8], sign: bool) -> io::Result<()> {
        let wire = self
            .channel
            .encrypt(cmd, payload, sign)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.socket.write_all(&wire, WRITE_TIMEOUT)?;
        self.last_send_at = Instant::now();
        Ok(())
    }

    /// How long the loop may wait for a frame before something else is due: a keepalive, the
    /// idle limit, a transaction request's deadline, a held share's parent hold, or, while no
    /// share is held, a rotation or a reveal (which wait for the held shares to be answered).
    fn until_next_action(&self) -> Duration {
        let mut due =
            (self.last_send_at + KEEPALIVE_INTERVAL).min(self.last_frame_at + IDLE_TIMEOUT);
        if let Some(deadline) = self.txn_requests.iter().map(shares::TxnRequest::deadline).min() {
            due = due.min(deadline);
        }
        if let Some(until) = self.held.iter().filter_map(shares::HeldShare::parent_hold_until).min()
        {
            due = due.min(until);
        }
        if self.held.is_empty()
            && let Some(next) = self.abw().map(AbwSlotState::next_due)
        {
            due = due.min(next);
        }
        due.saturating_duration_since(Instant::now())
    }

    fn send_mining(&mut self, payload: &[u8], sign: bool) -> io::Result<()> {
        self.send_frame(framing::cmd::MINING, payload, sign)
    }

    fn start_v3_session(&mut self, resume: Option<&ResumeToken>) -> io::Result<()> {
        let peer = self.peer;
        let (mut v3, splits, resumed) = lock(&self.server.sessions).resume_or_start(
            self.client_sign_pk,
            resume,
            Instant::now(),
        );
        self.verifier.restore_splits(splits);
        v3.abw.connect(self.opened_at);
        let payload = self.server.config_payload_v3(&v3.token);
        let notices = v3.abw.notices();
        self.v3 = Some(v3);
        self.resumed_from = resume.filter(|_| resumed).copied();
        self.send_mining(&payload, true)?;
        debug!("[{peer}] sent v3 0x99 config ({} bytes, signed)", payload.len());
        match (resume.is_some(), resumed) {
            (true, true) => info!(
                "[{peer}] resume accepted: the session's ABW assignments continue and its \
                 replayed shares verify; the saved session is released by the first frame \
                 that decrypts"
            ),
            (true, false) => info!(
                "[{peer}] resume declined: no saved session under this gateway's key with \
                 the token it presented; new session"
            ),
            (false, _) => debug!("[{peer}] new version 3 session"),
        }
        for notice in &notices {
            self.send_mining(notice, false)?;
        }
        debug!("[{peer}] sent {} ABW assignment notice(s)", notices.len());
        Ok(())
    }

    fn send_keepalive(&mut self) -> io::Result<()> {
        self.send_frame(framing::cmd::HELLO_OR_PING, &[], false)?;
        debug!("[{}]   <- keepalive ping", self.peer);
        Ok(())
    }

    /// Records that a frame decrypted under the session keys: the connection is the
    /// gateway's own, so the saved session it resumed is removed from the store and the
    /// session is saved again when this connection closes.
    fn note_proven(&mut self) {
        if self.proven {
            return;
        }
        self.proven = true;
        if let Some(token) = self.resumed_from.take()
            && lock(&self.server.sessions).claim(self.client_sign_pk, &token)
        {
            debug!("[{}] the resumed session is released to this connection", self.peer);
        }
    }

    fn run(&mut self) -> io::Result<()> {
        let peer = self.peer;
        loop {
            self.notify_tip_change()?;
            self.expire_txn_requests()?;
            self.expire_parent_holds()?;
            self.answer_orphaned_held()?;
            if let Some(why) = self.abw().and_then(|abw| abw.rotation_due(Instant::now()))
                && self.may_rotate_or_reveal()?
            {
                self.rotate_abw(why)?;
            }
            self.send_due_reveals()?;
            if self.last_frame_at.elapsed() >= IDLE_TIMEOUT {
                info!("[{peer}] closing: no frame from the gateway in {}s", IDLE_TIMEOUT.as_secs());
                return Ok(());
            }
            if self.last_send_at.elapsed() >= KEEPALIVE_INTERVAL {
                self.send_keepalive()?;
            }

            if !self.socket.readable() {
                let timeout = self.until_next_action();
                self.socket.wait(Some(timeout))?;
                continue;
            }
            let max_len = if self.txn_requests.is_empty() {
                MAX_UNSOLICITED_FRAME_LEN
            } else {
                framing::MAX_CMD_LEN
            };
            let unmask = |bytes| self.channel.unmask_header(bytes);
            let read = framing::read_next_frame(
                &mut self.socket,
                unmask,
                max_len,
                FRAME_BODY_TIMEOUT,
                FRAME_BODY_DEADLINE,
            )?;
            let (header, body) = match read {
                FrameRead::Closed => {
                    debug!("[{peer}] disconnected");
                    return Ok(());
                }
                FrameRead::Empty => continue,
                FrameRead::Complete(header, body) => (header, body),
            };
            let plain = match self.channel.decrypt(header, &body) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[{peer}] could not decrypt cmd={}: {e}", header.proto_cmd);
                    return Ok(());
                }
            };
            self.last_frame_at = Instant::now();
            self.note_proven();
            debug!("[{peer}] {}", describe(header, &plain));

            let mining = match header.proto_cmd {
                framing::cmd::MINING => plain,
                framing::cmd::BULK => match self.on_bulk_fragment(&plain)? {
                    Some(reassembled) => reassembled,
                    None => continue,
                },
                _ => continue,
            };
            match mining.first().copied() {
                Some(client_subcmd::COINBASER_REQUEST) => self.on_coinbaser_request(&mining)?,
                Some(client_subcmd::SUBMIT_POW) => self.on_share(&mining)?,
                Some(validation::SUBCMD) => self.on_block_txns(&mining)?,
                _ => {}
            }
        }
    }

    fn on_bulk_fragment(&mut self, plain: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let peer = self.peer;
        let fragment = match bulk::Fragment::decode(plain) {
            Ok(f) => f,
            Err(e) => {
                warn!("[{peer}] malformed bulk fragment: {e}");
                return Ok(None);
            }
        };
        match self.bulk.accept(&fragment) {
            Ok((ack, done)) => {
                self.send_frame(framing::cmd::BULK, &ack.encode(), false)?;
                Ok(done)
            }
            Err(e) => {
                warn!("[{peer}] bulk fragment refused: {e}; acknowledged and discarded");
                self.bulk.reset();
                let ack = bulk::Ack {
                    id: fragment.id,
                    next_offset: fragment.offset.saturating_add(fragment.data.len() as u32),
                };
                self.send_frame(framing::cmd::BULK, &ack.encode(), false)?;
                Ok(None)
            }
        }
    }

    fn on_coinbaser_request(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let req = match CoinbaserRequest::decode(plain) {
            Ok(req) => req,
            Err(e) => {
                warn!("[{peer}] malformed coinbaser request: {e}");
                return Ok(());
            }
        };
        info!(
            "[{peer}]   -> coinbaser request: {} sats, prev {}",
            req.value,
            &hex::encode(req.prev_hash)[..LOG_HEX_CHARS]
        );
        if !self.coinbaser_budget.take(Instant::now(), COINBASER_BURST, COINBASER_PER_SEC) {
            warn!(
                "[{peer}]      coinbaser request not answered: more than {COINBASER_BURST} at \
                 once or {COINBASER_PER_SEC} a second"
            );
            return Ok(());
        }
        if !payout::value_is_plausible(self.server, peer, req.value) {
            return Ok(());
        }
        let coinbaser_id = self.verifier.next_coinbaser_id();
        let (dictated, payload) = payout::dictate(self.server, peer, req.value, coinbaser_id);
        let outputs = dictated.len();
        self.verifier.record_dictated(
            coinbaser_id,
            req.value,
            req.prev_hash,
            dictated,
            ratum::unix_now(),
        );
        self.send_mining(&payload, false)?;
        info!("[{peer}]   <- coinbaser response ({outputs} outputs, id {coinbaser_id})");
        Ok(())
    }
}
/// Requests allowed at a steady rate with a burst: `tokens` refill at `per_sec` up to the
/// burst, and each request takes one.
struct RequestBudget {
    tokens: f64,
    at: Instant,
}

impl RequestBudget {
    fn full(burst: f64) -> Self {
        Self { tokens: burst, at: Instant::now() }
    }

    fn take(&mut self, now: Instant, burst: f64, per_sec: f64) -> bool {
        let refill = now.saturating_duration_since(self.at).as_secs_f64() * per_sec;
        self.tokens = (self.tokens + refill).min(burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_request_budget_allows_its_burst_then_its_rate() {
        use super::RequestBudget;
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let mut budget = RequestBudget { tokens: 3.0, at: start };
        let taken = (0..5).filter(|_| budget.take(start, 3.0, 1.0)).count();
        assert_eq!(taken, 3, "the burst");
        assert!(!budget.take(start + Duration::from_millis(500), 3.0, 1.0));
        assert!(budget.take(start + Duration::from_millis(1000), 3.0, 1.0), "one a second");
        assert!(!budget.take(start + Duration::from_millis(1000), 3.0, 1.0));
    }
}
