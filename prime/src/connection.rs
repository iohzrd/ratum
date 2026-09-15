mod assignments;
mod blocks;
mod credit;
mod shares;

use crate::abw::AbwSlotState;
use crate::coinbaser;
use crate::server::Server;
use crate::sessions::{SavedSession, SessionState, StartedSession};
use crate::verify::{AcceptedShare, Verifier};
use credit::CreditState;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::bulk::{self, Reassembler};
use ratum::datum::framing::{self, FrameHeader, HeaderKeyRatchet};
use ratum::datum::handshake::{ProtocolVersion, ResumeToken};
use ratum::datum::messages::client_subcmd;
use ratum::datum::messages::coinbaser::CoinbaserRequest;
use ratum::datum::server::{Hello, ServerChannel, accept, open_hello};
use ratum::lock;
use ratum::poll::{Fill, PolledSocket, WRITE_TIMEOUT};
use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LOG_PAYLOAD_BYTES: usize = 16;
const LOG_HEX_CHARS: usize = 16;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);
const FRAME_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_BODY_DEADLINE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const MAX_HELLO_FRAME_LEN: usize = 4 * 1024;

fn describe(header: FrameHeader, payload: &[u8]) -> String {
    let sub = payload.first().copied();
    let name = match (header.proto_cmd, sub) {
        (framing::cmd::MINING, Some(client_subcmd::COINBASER_REQUEST)) => "coinbaser request",
        (framing::cmd::MINING, Some(client_subcmd::SUBMIT_POW)) => "share submission",
        (framing::cmd::MINING, Some(client_subcmd::VALIDATION)) => "job validation response",
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
    let left = || HANDSHAKE_DEADLINE.saturating_sub(started_at.elapsed());
    let mut rx = HeaderKeyRatchet::initial();
    let mut header_bytes = [0u8; framing::HEADER_LEN];
    socket.read_exact(&mut header_bytes, left(), left())?;
    let header = rx.unmask(header_bytes);
    debug!(
        "[{peer}] hello header: cmd={} len={} signed={} encrypted_pubkey={}",
        header.proto_cmd, header.cmd_len, header.is_signed, header.is_encrypted_pubkey
    );
    if header.cmd_len as usize > MAX_HELLO_FRAME_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hello frame too large"));
    }
    let mut payload = vec![0u8; header.cmd_len as usize];
    socket.read_exact(&mut payload, left(), left())?;
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
    if !agent_allowed(&server.allowed_agents, &hello.user_agent) {
        warn!(
            "[{peer}] hello refused: agent {:?} matches none of the allowed prefixes {:?}",
            hello.user_agent, server.allowed_agents
        );
        return Ok(());
    }
    let protocol_version = hello.protocol_version;
    let client_sign_pk = hello.client_sign_pk;
    if server.require_v3 && protocol_version == ProtocolVersion::V1 {
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
        &hex::encode(hello.client_sign_pk)[..LOG_HEX_CHARS],
        &hex::encode(hello.session_sign_pk)[..LOG_HEX_CHARS],
        match protocol_version {
            ProtocolVersion::V1 => "v1",
            ProtocolVersion::V3 { .. } => "v3",
        },
    );

    let (response, channel): (Vec<u8>, ServerChannel) =
        match accept(hello, &server.pool_keys, &server.motd) {
            Ok(v) => v,
            Err(e) => {
                error!("[{peer}] could not build handshake response: {e}");
                return Ok(());
            }
        };
    socket.write_all(&response, WRITE_TIMEOUT)?;
    debug!("[{peer}] handshake response sent ({} bytes)", response.len());

    let waker = Arc::new(socket.waker()?);
    server.node_view.add_waker(&waker);

    let mut conn = Connection {
        server,
        peer,
        opened_at: handshake_started_at,
        socket,
        waker,
        channel,
        verifier: Verifier::new(server.share_policy.clone(), Arc::clone(&server.accepted_hashes)),
        credit: CreditState::new(peer),
        last_coinbaser_id: 0,
        awaiting_txns: HashMap::new(),
        known_tip: None,
        known_next_bits: None,
        last_send_at: Instant::now(),
        client_sign_pk,
        v3: None,
        bulk: Reassembler::new(),
    };

    match protocol_version {
        ProtocolVersion::V1 => {
            conn.send_mining(&server.config_payload, true)?;
            debug!("[{peer}] sent v1 0x99 config ({} bytes, signed)", server.config_payload.len());
        }
        ProtocolVersion::V3 { resume } => conn.start_v3_session(client_sign_pk, resume.as_ref())?,
    }

    conn.run()
}

enum FrameHeaderRead {
    Complete,
    Idle,
    Closed,
}

struct V3Session {
    token: ResumeToken,
    abw: AbwSlotState,
}

struct Connection<'a> {
    server: &'a Server,
    peer: std::net::SocketAddr,
    opened_at: Instant,
    socket: PolledSocket,
    waker: Arc<Waker>,
    channel: ServerChannel,
    verifier: Verifier,
    credit: CreditState,
    last_coinbaser_id: u8,
    awaiting_txns: HashMap<u8, AcceptedShare>,
    known_tip: Option<[u8; 32]>,
    known_next_bits: Option<u32>,
    last_send_at: Instant,
    client_sign_pk: [u8; 32],
    v3: Option<V3Session>,
    bulk: Reassembler,
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.server.node_view.remove_waker(&self.waker);
        if let Some(v3) = self.v3.take() {
            let state = SessionState {
                token: v3.token,
                abw: v3.abw,
                splits: self.verifier.take_splits(),
                last_coinbaser_id: self.last_coinbaser_id,
            };
            let session = SavedSession {
                state,
                saved_at: Instant::now(),
                connection_opened_at: self.opened_at,
            };
            lock(&self.server.sessions).save(self.client_sign_pk, session);
            debug!("[{}] session saved for resume", self.peer);
        }
        for (job, a) in &self.awaiting_txns {
            error!(
                "[{}]   !! a block on job {job} was never relayed: its transactions did not \
                 arrive before the connection closed: {}",
                self.peer,
                hex::encode(a.rebuilt.block_hash)
            );
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

    fn until_next_action(&self) -> Duration {
        let mut due = self.last_send_at + KEEPALIVE_INTERVAL;
        if let Some(next) = self.abw().map(AbwSlotState::next_due) {
            due = due.min(next.max(self.opened_at + assignments::REPLAY_GRACE));
        }
        due.saturating_duration_since(Instant::now())
    }

    fn read_frame_header(
        &mut self,
        hdr: &mut [u8; framing::HEADER_LEN],
    ) -> io::Result<FrameHeaderRead> {
        let mut got = 0usize;
        let mut partial_since: Option<Instant> = None;
        loop {
            if !self.socket.readable() {
                let Some(since) = partial_since else { return Ok(FrameHeaderRead::Idle) };
                let left =
                    FRAME_HEADER_TIMEOUT.checked_sub(since.elapsed()).filter(|d| !d.is_zero());
                let Some(left) = left else {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "frame header partially received",
                    ));
                };
                self.socket.wait(Some(left))?;
                continue;
            }
            match self.socket.fill(hdr, &mut got)? {
                Fill::Closed => return Ok(FrameHeaderRead::Closed),
                Fill::Complete => return Ok(FrameHeaderRead::Complete),
                Fill::Partial => {}
            }
            if got > 0 {
                partial_since.get_or_insert_with(Instant::now);
            }
        }
    }

    fn read_frame_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.socket.read_exact(&mut buf, FRAME_BODY_TIMEOUT, FRAME_BODY_DEADLINE)?;
        Ok(buf)
    }

    fn send_mining(&mut self, payload: &[u8], sign: bool) -> io::Result<()> {
        self.send_frame(framing::cmd::MINING, payload, sign)
    }

    fn start_v3_session(
        &mut self,
        client_sign_pk: [u8; 32],
        resume: Option<&ResumeToken>,
    ) -> io::Result<()> {
        let peer = self.peer;
        let StartedSession { state, resumed } =
            self.server.resume_or_start(client_sign_pk, resume, Instant::now());
        self.verifier.restore_splits(state.splits);
        self.last_coinbaser_id = state.last_coinbaser_id;
        let payload = self.server.config_payload_v3(&state.token);
        self.v3 = Some(V3Session { token: state.token, abw: state.abw });
        let notices = self.with_abw(|abw| abw.notices()).expect("a version 3 session");
        self.send_mining(&payload, true)?;
        debug!("[{peer}] sent v3 0x99 config ({} bytes, signed)", payload.len());
        match (resume.is_some(), resumed) {
            (true, true) => info!(
                "[{peer}] resume accepted: the session's ABW assignments continue and its \
                 replayed shares verify"
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

    fn run(&mut self) -> io::Result<()> {
        let peer = self.peer;
        loop {
            self.notify_tip_change()?;
            if let Some(why) = self.abw().and_then(|abw| abw.rotation_due(Instant::now())) {
                self.rotate_abw(why)?;
            }
            self.send_due_reveals()?;
            if self.last_send_at.elapsed() >= KEEPALIVE_INTERVAL {
                self.send_keepalive()?;
            }

            if !self.socket.readable() {
                let timeout = self.until_next_action();
                self.socket.wait(Some(timeout))?;
                continue;
            }
            let mut hdr = [0u8; framing::HEADER_LEN];
            match self.read_frame_header(&mut hdr)? {
                FrameHeaderRead::Closed => {
                    debug!("[{peer}] disconnected");
                    return Ok(());
                }
                FrameHeaderRead::Idle => continue,
                FrameHeaderRead::Complete => {}
            }
            let header = self.channel.unmask_header(hdr);
            let body = self.read_frame_body(header.cmd_len as usize)?;
            let plain = match self.channel.decrypt(header, &body) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[{peer}] could not decrypt cmd={}: {e}", header.proto_cmd);
                    return Ok(());
                }
            };
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
                Some(client_subcmd::VALIDATION) => self.on_block_txns(&mining),
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
        let Some(req) = CoinbaserRequest::decode(plain) else {
            warn!("[{peer}] malformed coinbaser request");
            return Ok(());
        };
        info!(
            "[{peer}]   -> coinbaser request: {} sats, prev {}",
            req.value,
            &hex::encode(req.prev_hash)[..LOG_HEX_CHARS]
        );
        if !coinbaser::value_is_plausible(self.server, peer, req.value) {
            return Ok(());
        }
        self.last_coinbaser_id = coinbaser::next_id(self.last_coinbaser_id);
        let split = coinbaser::dictate(self.server, peer, req.value, self.last_coinbaser_id)?;
        self.verifier.record_dictated(self.last_coinbaser_id, split.dictated, ratum::unix_now());
        self.send_mining(&split.payload, false)?;
        info!(
            "[{peer}]   <- coinbaser response ({} outputs, id {})",
            split.response.outputs.len(),
            self.last_coinbaser_id
        );
        Ok(())
    }
}
fn agent_allowed(allowed: &[String], user_agent: &str) -> bool {
    allowed.is_empty() || allowed.iter().any(|p| user_agent.starts_with(p))
}

#[cfg(test)]
mod tests {
    #[test]
    fn agents_are_allowed_by_prefix_and_an_empty_list_allows_all() {
        use super::agent_allowed;
        let none: Vec<String> = Vec::new();
        assert!(agent_allowed(&none, "v0.4.1-beta/deadbeef"));
        let list = vec!["ratum-gateway/".to_string(), "v0.4.1-beta/fa61d81".to_string()];
        assert!(agent_allowed(&list, "ratum-gateway/0.1.7/1eb08f1"));
        assert!(agent_allowed(&list, "v0.4.1-beta/fa61d81"));
        assert!(!agent_allowed(&list, "v0.4.1-beta/a1fbb293"));
        assert!(!agent_allowed(&list, ""));
    }
}
