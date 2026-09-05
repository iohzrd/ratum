//! One gateway connection: the handshake, then the loop that reads its frames and
//! responds to its coinbaser requests, shares, and block transactions.

use crate::abw::AbwManager;
use crate::server::{
    Payability, Resolver, SavedSession, Server, SessionState, dictated_outputs, owed_for_block,
    unix_now,
};
use log::{debug, error, info, warn};
use ratum::datum::abw::raw_hash_le;
use ratum::datum::bulk::{self, Reassembler};
use ratum::datum::framing::{self, Header, KeyRatchet};
use ratum::datum::handshake::{Generation, Session, accept, open_hello};
use ratum::datum::messages::{
    AbwShareRef, CoinbaseOutput, CoinbaserRequest, CoinbaserResponse, RejectReason, ResumeToken,
    ShareResponse, ShareVerdict, blocknotify, client_subcmd,
};
use ratum::datum::share::PowSubmit;
use ratum::datum::validation::{self, TxnBundle};
use ratum::io::read_exact_deadline;
use ratum::{lock, rpc};
use ratum_prime::ledger;
use ratum_prime::verify::{Accepted, Rebuilt, Verifier};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How far the value on a coinbaser request may differ from this node's own before the split
/// is refused, as a factor either way.
///
/// This bounds the request only. What is enforced on a gateway is the job section it later
/// sends: `check_outputs` refuses any coinbase output that is neither a dictated one nor
/// the pool's, and requires the outputs to total that section's `coinbase_value`. If the
/// request claims less than the block pays, the total will not match; if it claims more, the
/// coinbase would have to overpay, which the node refuses. So this tolerance need not be
/// narrow.
const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

/// Read a frame body of `n` bytes off a connection past its handshake.
///
/// The socket's read timeout is `IDLE_POLL` once the handshake is complete, so a body that
/// arrives in more than one segment (routine over anything but loopback for frames up to 4 MiB)
/// would make a plain `read_exact` return `WouldBlock` and close the connection. This
/// accumulates the body across those short timeouts, returning `Err(TimedOut)` only after
/// `BODY_TIMEOUT` with no progress, the same tolerance `read_header` gives a partially received
/// header.
fn read_body(s: &mut TcpStream, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut got = 0usize;
    let mut idle_since = Instant::now();
    let started = Instant::now();
    while got < n {
        // An absolute cap in addition to the no-progress timeout below: a gateway sending one
        // byte per interval shorter than `BODY_TIMEOUT` resets `idle_since` on every byte and
        // could hold the connection (and its `--max-connections` slot) indefinitely.
        // `BODY_DEADLINE` bounds the whole frame; on a private link even a 4 MiB frame arrives
        // well within it.
        if started.elapsed() > BODY_DEADLINE {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "frame body exceeded its deadline",
            ));
        }
        match s.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-frame",
                ));
            }
            Ok(k) => {
                got += k;
                idle_since = Instant::now();
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if idle_since.elapsed() > BODY_TIMEOUT {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "frame body stalled"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn describe(header: Header, payload: &[u8]) -> String {
    let sub = payload.first().copied();
    let name = match (header.proto_cmd, sub) {
        (framing::cmd::MINING, Some(0x10)) => "coinbaser request",
        (framing::cmd::MINING, Some(0x27)) => "share submission",
        (framing::cmd::MINING, Some(0x50)) => "job validation response",
        (framing::cmd::MINING, _) => "mining (unknown sub-command)",
        (framing::cmd::BULK, _) => "bulk fragment",
        (framing::cmd::HELLO_OR_PING, _) => "ping",
        _ => "unknown",
    };
    let head: Vec<String> = payload.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("{name}: {} bytes [{}...]", payload.len(), head.join(""))
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// An absolute cap on the whole handshake, across both handshake reads. `HANDSHAKE_TIMEOUT`
/// is the per-read socket timeout, which `read_exact`'s internal loop resets on every byte, so
/// a peer sending one byte per interval shorter than it holds a connection slot indefinitely.
/// This bounds the header read plus the hello payload read together.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_DEADLINE: Duration = Duration::from_secs(120);
const IDLE_POLL: Duration = Duration::from_millis(100);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// The largest hello frame the pool will read from an unauthenticated peer. A hello carries
/// four 32-byte keys, a short user agent, up to 200 padding bytes, a signature and a
/// sealed-box overhead: about 700 bytes. Bounding it here
/// keeps a peer that has not yet authenticated from making the pool allocate the full 4 MiB
/// a `cmd_len` can name, per connection slot. The margin above the real size allows for
/// a later hello format, since the hello carries only a user-agent string and no protocol
/// version field to negotiate.
const MAX_HELLO_FRAME: usize = 4 * 1024;

pub(crate) fn handle(mut stream: TcpStream, server: &Server) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    debug!("[{peer}] connected");

    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    let handshake_started = Instant::now();
    let mut rx = KeyRatchet::hello();
    let header_bytes = read_exact_deadline(&mut stream, 4, handshake_started, HANDSHAKE_DEADLINE)?;
    let header = rx.unmask(header_bytes.try_into().unwrap());
    debug!(
        "[{peer}] hello header: cmd={} len={} signed={} encrypted_pubkey={}",
        header.proto_cmd, header.cmd_len, header.is_signed, header.is_encrypted_pubkey
    );
    if header.cmd_len as usize > MAX_HELLO_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hello frame too large"));
    }
    let payload = read_exact_deadline(
        &mut stream,
        header.cmd_len as usize,
        handshake_started,
        HANDSHAKE_DEADLINE,
    )?;

    let hello = match open_hello(header, &payload, &server.pool_keys) {
        Ok(h) => h,
        Err(e) => {
            warn!("[{peer}] hello rejected: {e}");
            return Ok(());
        }
    };
    if !agent_allowed(&server.allowed_agents, &hello.user_agent) {
        warn!(
            "[{peer}] hello refused: agent {:?} matches none of the allowed prefixes {:?}",
            hello.user_agent, server.allowed_agents
        );
        return Ok(());
    }
    // The hello's DRS extension is the sole generation discriminator, read before `accept`
    // consumes the hello. A v1 gateway sends none and gets the version 1 configuration; a
    // version 3 gateway sends one and gets version 3 plus an ABW assignment. The long-term
    // signing key, which the hello is signed with, keys the session a later hello resumes.
    let generation = hello.generation;
    let client_key = hello.client_sign_pk;
    if server.require_v3 && generation == Generation::V1 {
        warn!(
            "[{peer}] hello refused: agent {:?} uses the version 1 protocol (no DRS \
             extension) and this pool requires version 3 (--require-v3)",
            hello.user_agent
        );
        return Ok(());
    }
    info!(
        "[{peer}] hello ok: ua={:?} nk={:#010x} client={} session={} generation={}",
        hello.user_agent,
        hello.nk,
        &hex::encode(hello.client_sign_pk)[..16],
        &hex::encode(hello.session_sign_pk)[..16],
        match generation {
            Generation::V1 => "v1",
            Generation::V3 { .. } => "v3",
        },
    );

    let (response, session): (Vec<u8>, Session) =
        match accept(hello, &server.pool_keys, &server.motd) {
            Ok(v) => v,
            Err(e) => {
                error!("[{peer}] could not build handshake response: {e}");
                return Ok(());
            }
        };
    stream.write_all(&response)?;
    stream.flush()?;
    debug!("[{peer}] handshake response sent ({} bytes)", response.len());

    let mut conn = Connection {
        server,
        peer,
        opened: handshake_started,
        stream,
        session,
        verifier: Verifier::with_replay_guard(server.policy.clone(), Arc::clone(&server.replay)),
        credited: HashMap::new(),
        reported_unpayable: HashSet::new(),
        coinbaser_id: 0,
        awaiting_txns: HashMap::new(),
        known_tip: None,
        known_next_bits: None,
        last_send: Instant::now(),
        client_key,
        v3: None,
        bulk: Reassembler::new(),
    };

    match generation {
        Generation::V1 => {
            conn.send_mining(&server.config_payload, true)?;
            debug!("[{peer}] sent v1 0x99 config ({} bytes, signed)", server.config_payload.len());
        }
        Generation::V3 { resume } => {
            // The connection holds the session before the config is sent, so a failed send
            // still saves it for a resume.
            let (state, resumed) =
                server.resume_or_start(client_key, resume.as_ref(), Instant::now());
            // The splits the resumed session dictated: the gateway's replayed shares and its
            // shares on the jobs it still holds pay them, and its next split must not take
            // an id one of those jobs names.
            conn.verifier.restore_splits(state.splits);
            conn.coinbaser_id = state.coinbaser_id;
            let payload = server.config_payload_v3(&state.token);
            conn.v3 = Some(V3Session { token: state.token, abw: state.abw });
            let notices = conn.with_abw(|m| m.notices()).expect("a version 3 session");
            conn.send_mining(&payload, true)?;
            debug!("[{peer}] sent v3 0x99 config ({} bytes, signed)", payload.len());
            match (resume.is_some(), resumed) {
                (true, true) => info!(
                    "[{peer}] resume accepted: the session's ABW assignments continue and \
                     its replayed shares verify"
                ),
                (true, false) => info!(
                    "[{peer}] resume declined: no saved session under this gateway's key \
                     with the token it presented; new session"
                ),
                (false, _) => debug!("[{peer}] new version 3 session"),
            }
            // The gateway builds no work until it holds an active assignment. A resumed
            // gateway cleared its active slot on reconnect and is sent every seeded slot
            // again; the reveals it may not have received follow once its replayed shares
            // are answered (`AbwManager::resumed`).
            for notice in &notices {
                conn.send_mining(notice, false)?;
            }
            debug!("[{peer}] sent {} ABW assignment notice(s)", notices.len());
        }
    }

    conn.stream.set_read_timeout(Some(IDLE_POLL))?;
    conn.run()
}

const MAX_CREDITED_NAMES: usize = 4096;

/// A checked share's outcome: the verdict, any follow-up frame to send (a block's
/// transaction request), and the raw PoW hash when one was computed.
type ShareOutcome = (ShareVerdict, Option<Vec<u8>>, Option<[u8; 32]>);

/// What a version 3 session holds while its connection is open: the token the gateway
/// resumes it with and its anti-block-withholding slots. The splits the session dictated
/// live in the verifier and the coinbaser id on the connection meanwhile; `Drop` gathers
/// all four into the `SessionState` it saves.
struct V3Session {
    token: ResumeToken,
    abw: AbwManager,
}

/// One gateway connection past its handshake: the channel, the verifier holding its jobs,
/// and the blocks waiting on their transactions.
struct Connection<'a> {
    server: &'a Server,
    peer: std::net::SocketAddr,
    /// When the connection was accepted; a saved session records it as `held_since`.
    opened: Instant,
    stream: TcpStream,
    session: Session,
    verifier: Verifier,
    credited: HashMap<String, u64>,
    /// The identities this connection has already reported as unpayable, so the reason is
    /// logged at warn once rather than on every share. Bounded by `MAX_CREDITED_NAMES`.
    reported_unpayable: HashSet<String>,
    coinbaser_id: u8,
    awaiting_txns: HashMap<u8, Accepted>,
    known_tip: Option<[u8; 32]>,
    /// The last `next_bits` value passed to the verifier, which derives the network target from
    /// it. The watcher
    /// can publish a tip with `next_bits` still `None` (its `getblocktemplate` failed) and set
    /// the bits on a later poll without the tip hash changing, so this is tracked separately
    /// from `known_tip` to set the target again when the template arrives after its tip.
    known_next_bits: Option<u32>,
    /// When a frame was last sent to the gateway, to pace the keepalive.
    last_send: Instant,
    /// The gateway's long-term signing key: what a saved session is stored under.
    client_key: [u8; 32],
    /// The version 3 session's state that outlives the connection; `None` on a v1 session,
    /// where headers are built with a zero key and shares carry no slot.
    v3: Option<V3Session>,
    /// Reassembles the bulk-framed (command 6) replies a version 3 gateway sends for large
    /// validation responses.
    bulk: Reassembler,
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        // A version 3 session is kept for `SESSION_KEEP`, so the gateway's next hello, with
        // the token, continues its ABW slots and its replayed shares verify.
        if let Some(v3) = self.v3.take() {
            let state = SessionState {
                token: v3.token,
                abw: v3.abw,
                splits: self.verifier.take_splits(),
                coinbaser_id: self.coinbaser_id,
            };
            let session = SavedSession { state, saved_at: Instant::now(), held_since: self.opened };
            lock(&self.server.sessions).save(self.client_key, session);
            debug!("[{}] session saved for resume", self.peer);
        }
        // A block whose transactions never arrived is discarded with the connection. The
        // gateway has already submitted it to its own node, but log the hash at error so the
        // operator knows the pool did not relay it.
        for (job, a) in &self.awaiting_txns {
            error!(
                "[{}]   !! a block on job {job} was never relayed: its transactions did not \
                 arrive before the connection closed: {}",
                self.peer,
                hex::encode(a.work.block_hash)
            );
        }
    }
}

impl Connection<'_> {
    fn send_frame(&mut self, cmd: u8, payload: &[u8], sign: bool) -> io::Result<()> {
        let wire = self
            .session
            .encrypt(cmd, payload, sign)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.stream.write_all(&wire)?;
        self.stream.flush()?;
        self.last_send = Instant::now();
        Ok(())
    }

    fn send_mining(&mut self, payload: &[u8], sign: bool) -> io::Result<()> {
        self.send_frame(framing::cmd::MINING, payload, sign)
    }

    /// The anti-block-withholding slots of a version 3 session; `None` on a v1 session.
    fn abw(&self) -> Option<&AbwManager> {
        self.v3.as_ref().map(|v| &v.abw)
    }

    /// Run `f` on a version 3 session's slots, then mirror their keys into the verifier: the
    /// one path a change to the slots reaches the share checks by. `None` on a v1 session,
    /// where `f` does not run.
    fn with_abw<R>(&mut self, f: impl FnOnce(&mut AbwManager) -> R) -> Option<R> {
        let manager = &mut self.v3.as_mut()?.abw;
        let r = f(manager);
        let keys = manager.keys();
        self.verifier.set_abw_keys(Some(keys));
        Some(r)
    }

    /// Send a protocol ping so a connection with no shares or tip changes still produces a
    /// frame inside the gateway's `datum_protocol_global_timeout` (default 60 s). The gateway's
    /// handler for proto_cmd 1 (`datum_protocol_ping_response`) does nothing, but it sets
    /// `latest_server_msg_tsms` on every frame it decrypts (and, when signed, verifies), before
    /// dispatching by command.
    fn send_keepalive(&mut self) -> io::Result<()> {
        self.send_frame(framing::cmd::HELLO_OR_PING, &[], false)?;
        debug!("[{}]   <- keepalive ping", self.peer);
        Ok(())
    }

    /// Notify the verifier and the gateway of a change of the node's tip.
    fn notify_tip_change(&mut self) -> io::Result<()> {
        let current = lock(&self.server.node_view.tip).map(|t| t.hash);
        let next_bits = *lock(&self.server.node_view.next_bits);
        if current != self.known_tip {
            // A tip change replaces a tip the connection already recorded; the first
            // observation at startup (None to Some) establishes the baseline and must not
            // rotate the assignment the session was seeded with.
            let tip_replaced = self.known_tip.is_some();
            self.known_tip = current;
            self.verifier.set_tip(current, unix_now());
            // The watcher publishes the template's bits before the tip hash, so the bits read
            // here belong to this tip. The verifier refuses a job on the tip that claims an
            // easier target than the node's own next block.
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            if current.is_some() {
                // A tip change already invalidates the work on the active assignment; the
                // rotation precedes the blocknotify so the gateway holds an active
                // assignment before it builds work.
                if tip_replaced {
                    self.rotate_on_tip()?;
                }
                self.send_mining(&blocknotify(), false)?;
                debug!("[{}]   <- blocknotify (new tip)", self.peer);
            }
        } else if next_bits != self.known_next_bits {
            // The template arrived after the tip it belongs to: the watcher's first
            // `getblocktemplate` at this tip failed (`next_bits` was `None`) and a later poll
            // succeeded without the tip hash changing. Set the network target again so a block
            // found on this tip is recognized and relayed; until now `tip_next_target` was
            // `None` for the whole tip and nothing on it could be a block.
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            debug!("[{}]   next target set for the current tip", self.peer);
        }
        Ok(())
    }

    /// Rotate the assignment on a new tip, unless the active slot is too young
    /// (`AbwManager::tip_rotation_allowed`). The new tip makes the gateway's jobs on the
    /// slot stale either way, so a retired slot goes quiet at once.
    fn rotate_on_tip(&mut self) -> io::Result<()> {
        match self.abw() {
            Some(m) if m.tip_rotation_allowed(Instant::now()) => self.rotate_abw("new tip"),
            Some(_) => {
                debug!(
                    "[{}]   the active ABW slot is too young to rotate on the new tip",
                    self.peer
                );
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Seed and activate the next ABW slot and retire the active one (`AbwManager::rotate`);
    /// `why` is logged. Nothing on a v1 session.
    fn rotate_abw(&mut self, why: &str) -> io::Result<()> {
        let Some((reveals, notice)) = self.with_abw(|m| m.rotate(Instant::now())) else {
            return Ok(());
        };
        for r in &reveals {
            self.send_mining(&r.payload, false)?;
            if r.again {
                debug!("[{}]   <- sent the reveal of ABW slot {} again", self.peer, r.slot);
            } else {
                warn!(
                    "[{}]   <- revealed ABW slot {} early: the rotation reached it again \
                     before its reveal was due",
                    self.peer, r.slot
                );
            }
        }
        self.send_mining(&notice, false)?;
        debug!("[{}]   <- rotated the ABW assignment ({why})", self.peer);
        Ok(())
    }

    /// Reveal the slots retired for the session's reveal delay (`AbwManager::reveals_due`).
    /// Nothing on a v1 session.
    fn send_due_reveals(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if !self.abw().is_some_and(|m| m.reveal_due(now)) {
            return Ok(());
        }
        // Every share received before the reveal is answered first, and a block's receipt
        // precedes the reveal, however long the last iteration took (a node call that
        // retried, a large body): a due reveal waits for the socket to be drained.
        if !self.socket_drained()? {
            return Ok(());
        }
        let reveals = self.with_abw(|m| m.reveals_due(now)).unwrap_or_default();
        if reveals.is_empty() {
            return Ok(());
        }
        for r in &reveals {
            self.send_mining(&r.payload, false)?;
            if r.again {
                debug!(
                    "[{}]   <- sent the reveal of ABW slot {} again (resumed session)",
                    self.peer, r.slot
                );
            } else {
                debug!("[{}]   <- revealed the retired ABW slot {}", self.peer, r.slot);
            }
        }
        Ok(())
    }

    /// Whether nothing the gateway sent is waiting to be read: a non-blocking peek at the
    /// socket. The read timeout (`IDLE_POLL`) is a separate socket option and stays.
    fn socket_drained(&mut self) -> io::Result<bool> {
        self.stream.set_nonblocking(true)?;
        let peeked = self.stream.peek(&mut [0u8; 1]);
        self.stream.set_nonblocking(false)?;
        match peeked {
            // Bytes waiting, or the peer closed (read next, as `Framing::Closed`).
            Ok(_) => Ok(false),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// The 0xA5 receipt for `work` on a version 3 session, when the share named a slot.
    fn send_abw_receipt(&mut self, s: &PowSubmit, work: &Rebuilt) -> io::Result<()> {
        let Some(slot) = s.abw_slot.filter(|_| self.v3.is_some()) else { return Ok(()) };
        self.send_mining(&AbwManager::receipt(slot, work.raw_hash), false)?;
        debug!("[{}]   <- ABW receipt for the block on slot {slot}", self.peer);
        Ok(())
    }

    fn run(&mut self) -> io::Result<()> {
        let peer = self.peer;
        loop {
            self.notify_tip_change()?;
            if let Some(why) = self.abw().and_then(|m| m.rotation_due(Instant::now())) {
                self.rotate_abw(why)?;
            }
            self.send_due_reveals()?;

            let mut hdr = [0u8; 4];
            match read_header(&mut self.stream, &mut hdr)? {
                Framing::Closed => {
                    debug!("[{peer}] disconnected");
                    return Ok(());
                }
                Framing::Idle => {
                    if self.last_send.elapsed() >= KEEPALIVE_INTERVAL {
                        self.send_keepalive()?;
                    }
                    continue;
                }
                Framing::HeaderRead => {}
            }
            let header = self.session.unmask_header(hdr);
            if header.cmd_len as usize > framing::MAX_CMD_DATA_SIZE as usize {
                warn!(
                    "[{peer}] cmd_len {} exceeds MAX_CMD_DATA_SIZE; closing the connection",
                    header.cmd_len
                );
                return Ok(());
            }
            let body = read_body(&mut self.stream, header.cmd_len as usize)?;
            let plain = match self.session.decrypt(header, &body) {
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

    /// One bulk fragment (command 6): acknowledge it, and on the final fragment return the
    /// reassembled command-5 payload for the same dispatch a single frame would take.
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
                // The C sender advances only on an ack at the offset it advanced to and
                // never resends, so a refused fragment is acknowledged at that offset and
                // the transfer discarded; unacknowledged, its bulk queue would not move again
                // for the session.
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
            &hex::encode(req.prev_hash)[..16]
        );
        if let Some(reference) = *lock(&self.server.node_view.coinbase_value) {
            let low = (reference as f64 / COINBASE_VALUE_TOLERANCE) as u64;
            let high = (reference as f64 * COINBASE_VALUE_TOLERANCE) as u64;
            if req.value < low || req.value > high {
                warn!(
                    "[{peer}]      refusing a split for {} sats: this node's template pays \
                     {reference} sats",
                    req.value
                );
                return Ok(());
            }
        }
        let (dictated, shares, work) = dictated_outputs(self.server, req.value);
        let paid: u64 = dictated.iter().map(|(_, o)| o.value).sum();
        let outputs: Vec<CoinbaseOutput> = dictated.iter().map(|(_, o)| o.clone()).collect();
        info!(
            "[{peer}]      paying {} miners {} of {} sats from a window of {shares} shares ({work} work)",
            outputs.len(),
            paid,
            req.value,
        );
        self.coinbaser_id = self.coinbaser_id.wrapping_add(1);
        if self.coinbaser_id == 0 {
            // Id 0 marks a job built with no coinbaser applied, so a response never uses it.
            self.coinbaser_id = 1;
        }
        let coinbaser_id = self.coinbaser_id;
        let mut response = CoinbaserResponse { value: req.value, coinbaser_id, outputs };
        let removed = response.retain_payable();
        if removed != 0 {
            warn!("[{peer}]      removed {removed} unpayable outputs from the split");
        }
        let payload = loop {
            match response.encode() {
                Ok(p) => break p,
                Err(e) if response.outputs.len() > 1 => {
                    let removed = response.outputs.pop();
                    warn!(
                        "[{peer}]      split too large ({e}); removed an output of {} sats",
                        removed.map_or(0, |o| o.value)
                    );
                }
                Err(e) => {
                    error!("[{peer}]      could not build the split ({e}); paying the pool");
                    response.outputs = vec![CoinbaseOutput {
                        value: req.value,
                        script: self.server.policy.payout_script.clone(),
                    }];
                    break response.encode().map_err(|e| io::Error::other(e.to_string()))?;
                }
            }
        };
        // The identity each remaining output pays, recorded with the split so an output a
        // block's coinbase leaves out is owed to the identity the split named. The trimming
        // above only removes outputs, so each remaining one is the next of `dictated` with
        // its value and script; matched by position rather than by script, since two
        // identities (a bech32 address in both cases) can name one script. An output the
        // fallback added names none.
        let mut rest = dictated.iter();
        let identities: Vec<String> = response
            .outputs
            .iter()
            .map(|o| {
                rest.by_ref()
                    .find(|(_, d)| d.value == o.value && d.script == o.script)
                    .map_or_else(String::new, |(identity, _)| identity.clone())
            })
            .collect();
        self.verifier.record_dictated(&response, identities, unix_now());
        self.send_mining(&payload, false)?;
        info!(
            "[{peer}]   <- coinbaser response ({} outputs, id {coinbaser_id})",
            response.outputs.len()
        );
        Ok(())
    }

    fn on_share(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        // The three fields (nonce, target byte, job id) the response echoes back with the verdict,
        // and any follow-up frame
        // the verdict calls for (a block's transaction request).
        let (verdict, nonce, target_byte, job_id, pending, raw_hash) =
            match PowSubmit::decode(plain) {
                Ok(s) => {
                    debug!("[{peer}]   -> share {}", describe_share(&s));
                    // The gateway retains a proof per share until the slot's reveal.
                    self.with_abw(AbwManager::note_share);
                    let (verdict, pending, raw_hash) = self.check_share(&s, unix_now())?;
                    (
                        verdict,
                        s.nonce,
                        s.target_byte,
                        s.job_id,
                        pending,
                        raw_hash.map(|h| (s.abw_slot, h)),
                    )
                }
                Err(e) => {
                    warn!("[{peer}]   !! could not decode share: {e}");
                    if matches!(
                        e,
                        ratum::datum::share::Error::BadBlake2bSection
                            | ratum::datum::share::Error::MissingBlake2bSection
                            | ratum::datum::share::Error::BadExtranonceSize(_)
                    ) {
                        warn!(
                            "[{peer}]      a share this pool cannot read indicates a gateway \
                         built against a different revision of the protocol (an upstream \
                         DATUM gateway sends no BLAKE2b section); the pool and the gateway \
                         are released together"
                        );
                    }
                    // The fields the response echoes, from the fixed prefix when that much
                    // decoded: the C gateway retires the share's replay entry by them, and
                    // would replay the share on every reconnect otherwise.
                    let (job_id, target_byte, nonce) =
                        PowSubmit::prefix(plain).unwrap_or((0, 0xff, 0));
                    (
                        ShareVerdict::Rejected(Verifier::reason_for_decode_error(&e)),
                        nonce,
                        target_byte,
                        job_id,
                        None,
                        None,
                    )
                }
            };
        // On a version 3 session, echo the exact reference (slot + raw hash) so the gateway
        // removes exactly the one replay entry, not the ambiguous (nonce, PoT, job) triple.
        // Present only when the share rebuilt far enough to have a raw hash and named a slot.
        let abw_ref = match raw_hash {
            Some((Some(slot), hash)) if self.v3.is_some() => {
                Some(AbwShareRef { slot, raw_pow_hash: raw_hash_le(&hash) })
            }
            _ => None,
        };
        let response = ShareResponse { verdict, nonce, target_byte, job_id, abw_ref };
        self.send_mining(&response.encode(), false)?;
        if let Some(request) = pending {
            self.send_mining(&request, false)?;
            info!("[{peer}]   <- requested the block's transactions (0x50 0x12)");
        }
        Ok(())
    }

    /// Verify one decoded share and act on the verdict: credit an accepted one and relay it
    /// if it is a block, or log a rejected one. Returns the verdict, any follow-up frame,
    /// and the raw PoW hash when the share verified far enough to have one (for the exact
    /// ABW reference).
    fn check_share(&mut self, s: &PowSubmit, now: u64) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        match self.verifier.verify(s, now) {
            Ok(a) => {
                let raw_hash = Some(a.work.raw_hash);
                let mut pending = None;
                let candidate = self.verifier.block_candidate(&a.work);
                if a.is_block {
                    warn!(
                        "[{peer}]   ** BLOCK at height {}: {}",
                        a.work.height,
                        hex::encode(a.work.block_hash)
                    );
                } else if candidate {
                    info!(
                        "[{peer}]      share meets its job's bits {:#010x} but not the node's \
                         next target; not relayed",
                        a.work.job_bits
                    );
                }
                // Mark a block handled to the gateway's disclosure audit: without a receipt
                // for a block it retained, its reveal-time check sets a permanent CRITICAL
                // failure and closes the connection. The audit classifies by the job's own
                // bits, so the receipt also covers a share the pool does not relay.
                if candidate {
                    self.send_abw_receipt(s, &a.work)?;
                }
                if a.is_block {
                    if relay_or_request_txns(peer, &self.server.node, &a, s.subsidy_only) {
                        if let Some(prev) = self.awaiting_txns.insert(s.job_id, a.clone()) {
                            error!(
                                "[{peer}]   !! a block on job {} was still awaiting its \
                                 transactions and is abandoned: {}",
                                s.job_id,
                                hex::encode(prev.work.block_hash)
                            );
                        }
                        pending = Some(validation::request_block_txns(s.job_id));
                    }
                } else if s.is_block {
                    warn!(
                        "[{peer}]   !! gateway flagged a block but the hash does not meet the \
                         network target"
                    );
                }
                // Every accepted block enters the ledger's block history, whoever found it
                // and however its coinbase paid: the stats interface renders the list and
                // derives the luck figure from it.
                if a.is_block {
                    self.record_found_block(&a, s, now);
                }
                // What the pool's payout script received on a block that is owed to the
                // window is recorded as owed by the pool. A coinbase that left dictated
                // outputs out (they did not fit the miner's coinbase) names them exactly, from
                // the split the pool dictated for the job. A coinbase that paid the window
                // nothing on a job with no recorded split (a subsidy-only job, or a coinbase
                // built with no split) is recorded from the split a coinbaser would dictate
                // now. Taken before `record_and_credit` adds the block's own share; the window
                // is read at acceptance, so it also holds shares credited after this job was
                // served, an approximation of the split a coinbaser serving the job would have
                // fixed.
                if a.is_block {
                    if !a.work.unpaid.is_empty() {
                        self.record_unpaid_outputs(&a, now);
                    } else if a.work.paid_to_split == 0 {
                        self.record_owed_block(&a, now);
                    }
                }
                // A share is credited to an identity only if the coinbase can pay it. The
                // check is here, after the relay above, so a block is still submitted, and
                // before the credit, so work is never counted for an identity whose amount
                // would be paid to the pool as the coinbase remainder instead. The share's
                // hash stays in the `ReplayGuard`: the verdict depends on the username, which
                // a resend of the same share would carry again.
                if self.is_unpayable(&s.username) {
                    return Ok((
                        ShareVerdict::Rejected(RejectReason::BadUsername),
                        pending,
                        raw_hash,
                    ));
                }
                // Credit after arranging relay, and never let a ledger write error close the
                // connection: the block relay above and any pending transaction fetch must
                // outlive it. On failure the share is not credited and `record_and_credit`
                // removed its hash from the `ReplayGuard`, so a resend can be credited once
                // the store recovers.
                if let Err(e) = self.record_and_credit(s, &a, now) {
                    error!(
                        "[{peer}]   !! could not record the share to the ledger ({e}); it is \
                         not credited and its hash was removed from the ReplayGuard so a \
                         resend can be credited"
                    );
                }
                Ok((ShareVerdict::Accepted, pending, raw_hash))
            }
            Err(reason) => {
                debug!("[{peer}]   <- rejected: {reason:?}");
                if s.is_block
                    && let Ok(w) = self.verifier.reconstruct(s, now)
                {
                    warn!(
                        "[{peer}]   !! pool built header {} coinbase {}",
                        hex::encode(w.header),
                        hex::encode(&w.coinbase_tx)
                    );
                }
                // A version 3 gateway retains a proof for this share too: the exact
                // reference retires its replay entry, and a block it refused for (a
                // duplicate, say) needs the receipt, or the reveal audit finds an unhandled
                // block, sets the permanent CRITICAL failure and closes the connection.
                let mut raw_hash = None;
                if self.v3.is_some()
                    && let Some(work) = self.verifier.rebuild_refused(s)
                {
                    raw_hash = Some(work.raw_hash);
                    if self.verifier.block_candidate(&work) {
                        warn!(
                            "[{peer}]   ** the refused share ({reason:?}) meets a block \
                             target: sending the ABW receipt so the gateway counts it handled"
                        );
                        self.send_abw_receipt(s, &work)?;
                    }
                }
                Ok((ShareVerdict::Rejected(reason), None, raw_hash))
            }
        }
    }

    /// Record the accepted block in the ledger's block history; see `ledger::FoundBlock`.
    /// The difficulty and cumulative work are read at acceptance, before
    /// `record_and_credit` adds the block's own share, so the difference between
    /// consecutive records is exactly the work between them.
    fn record_found_block(&self, a: &Accepted, s: &PowSubmit, now: u64) {
        let difficulty = lock(&self.server.node_view.tip).map_or(0.0, |t| t.difficulty);
        let mut l = lock(&self.server.ledger);
        let block = ledger::FoundBlock {
            at: now,
            height: a.work.height,
            block_hash: a.work.block_hash,
            paid_to_split: a.work.paid_to_split,
            paid_to_pool: a.work.paid_to_pool,
            finder: ledger::identity_of(&s.username).to_string(),
            tag: a.work.tag_secondary.clone(),
            difficulty,
            cumulative_work: l.cumulative_work(),
        };
        if let Err(e) = l.record_block(block) {
            error!(
                "[{}]   !! could not record the block to the ledger's history ({e}); the \
                 block itself was already relayed",
                self.peer
            );
        }
    }

    /// Compute and record what the pool owes the window for a block whose coinbase paid it
    /// nothing; see `ledger::OwedBlock`. The amounts are logged either way, so a ledger
    /// write failure loses the record's durability but never the numbers.
    fn record_owed_block(&self, a: &Accepted, now: u64) {
        let peer = self.peer;
        let value = a.work.paid_to_pool;
        let Some(owed) = owed_for_block(self.server, a.work.height, a.work.block_hash, value, now)
        else {
            warn!(
                "[{peer}]   ** the block's {value} sats went to the pool's payout script and \
                 the window names nobody to owe them to"
            );
            return;
        };
        warn!(
            "[{peer}]   ** the block's coinbase paid the window nothing; the pool's payout \
             script received {value} sats of which {} are owed to {} identit{}:",
            owed.total,
            owed.entries.len(),
            if owed.entries.len() == 1 { "y" } else { "ies" },
        );
        for (identity, sats) in &owed.entries {
            warn!("[{peer}]   **   {identity} {sats} sats");
        }
        warn!(
            "[{peer}]   ** recorded as owed by block hash {}; after paying it from the pool's \
             wallet, run: ratum-prime --settle-block {} (with --ledger or --data-dir, pool \
             stopped)",
            hex::encode(a.work.block_hash),
            hex::encode(a.work.block_hash),
        );
        if let Err(e) = lock(&self.server.ledger).record_owed(owed) {
            error!(
                "[{peer}]   !! could not record the owed split to the ledger ({e}); the \
                 amounts above are in this log only"
            );
        }
    }

    /// Record what the pool owes the window for a block whose coinbase left dictated outputs
    /// out (`Rebuilt::unpaid`): the gateway paid their value to the pool's payout script as
    /// its remainder (an output did not fit the miner's coinbase size class), so the pool
    /// holds it for those identities. Exact, from the split the pool dictated for the job;
    /// `record_owed_block` approximates for a job with no recorded split. The total is capped
    /// at what the payout script received beyond the operator fee, for a job whose coinbase
    /// value fell short of the value the split was dictated for; the amounts are then scaled
    /// down in proportion.
    fn record_unpaid_outputs(&self, a: &Accepted, now: u64) {
        let peer = self.peer;
        let value = a.work.paid_to_split.saturating_add(a.work.paid_to_pool);
        let fee = self.server.payout.fee_on(value);
        let available = a.work.paid_to_pool.saturating_sub(fee);
        let mut entries = self.verifier.unpaid_outputs(&a.work);
        let dictated: u64 = entries.iter().map(|(_, sats)| *sats).sum();
        if dictated > available {
            warn!(
                "[{peer}]   ** the coinbase left out {dictated} sats of dictated outputs but the \
                 pool's payout script received only {available} sats beyond the fee; the owed \
                 amounts are scaled down to what it received"
            );
            for (_, sats) in &mut entries {
                *sats = (u128::from(*sats) * u128::from(available) / u128::from(dictated)) as u64;
            }
            entries.retain(|(_, sats)| *sats > 0);
        }
        let total: u64 = entries.iter().map(|(_, sats)| *sats).sum();
        if total == 0 {
            return;
        }
        warn!(
            "[{peer}]   ** the block's coinbase left out {} of the dictated outputs; the pool's \
             payout script received {} sats of which {total} are owed to {} identit{}:",
            a.work.unpaid.len(),
            a.work.paid_to_pool,
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
        );
        for (identity, sats) in &entries {
            warn!("[{peer}]   **   {identity} {sats} sats");
        }
        warn!(
            "[{peer}]   ** recorded as owed by block hash {}; after paying it from the pool's \
             wallet, run: ratum-prime --settle-block {} (with --ledger or --data-dir, pool \
             stopped)",
            hex::encode(a.work.block_hash),
            hex::encode(a.work.block_hash),
        );
        let owed = ledger::OwedBlock {
            at: now,
            height: a.work.height,
            block_hash: a.work.block_hash,
            total,
            settled_at: None,
            entries,
        };
        if let Err(e) = lock(&self.server.ledger).record_owed(owed) {
            error!(
                "[{peer}]   !! could not record the owed outputs to the ledger ({e}); the \
                 amounts above are in this log only"
            );
        }
    }

    /// Whether the identity that `username` credits to cannot be paid a coinbase output. When
    /// it cannot, the share is rejected with `BadUsername` instead of credited. The reason is
    /// logged at warn the first time this connection sees the identity, since every later
    /// share from the same name produces the same rejection.
    ///
    /// Only a definite answer from the node rejects. `Payability::Unknown` (the node could not
    /// be reached) is treated as payable, so an RPC outage does not reject shares from
    /// identities that are valid.
    fn is_unpayable(&mut self, username: &str) -> bool {
        let identity = ledger::identity_of(username);
        let Payability::Unpayable(why) =
            Resolver::payability(&self.server.resolver, &self.server.node, identity)
        else {
            return false;
        };
        let first = self.reported_unpayable.len() < MAX_CREDITED_NAMES
            && self.reported_unpayable.insert(identity.to_string());
        if first {
            warn!(
                "[{}]   <- rejecting shares from {identity:?}, which cannot be paid: {why}. \
                 The gateway sends the miner's own stratum username when \
                 pool_pass_full_users is set; that username must be an address this chain's \
                 node accepts, optionally followed by '.workername'.",
                self.peer
            );
        } else {
            debug!("[{}]   <- rejected: {identity:?} cannot be paid ({why})", self.peer);
        }
        true
    }

    /// Write an accepted share to the ledger, re-sizing the window to the current network
    /// difficulty first, and add it to this connection's per-username tally.
    fn record_and_credit(&mut self, s: &PowSubmit, a: &Accepted, now: u64) -> io::Result<()> {
        let peer = self.peer;
        let identity = ledger::identity_of(&s.username).to_string();
        let network = lock(&self.server.node_view.tip).map(|t| t.difficulty);
        {
            let mut l = lock(&self.server.ledger);
            if let Some(d) = network {
                let w = ledger::window_for_difficulty(
                    d,
                    self.server.payout.window_multiple,
                    self.server.payout.window_floor,
                );
                if w != l.window() {
                    let re_read = l.set_window(w);
                    if re_read != 0 {
                        info!(
                            "[{peer}]      difficulty rose; the wider window \
                             re-read {re_read} share(s) from the ledger"
                        );
                    }
                }
            }
            if let Err(e) = l.record(
                now,
                &identity,
                a.work.difficulty,
                &a.work.block_hash,
                &a.work.tag_secondary,
            ) {
                // verify() already recorded this hash in the shared `ReplayGuard`. The credit
                // failed, so remove it: a resend must be creditable once the write problem
                // clears, rather than refused as a duplicate. Drop the ledger lock first, since
                // the `ReplayGuard` lock is taken without it elsewhere.
                drop(l);
                lock(&self.server.replay).remove(&a.work.block_hash);
                return Err(e);
            }
            let removed = l.take_removed();
            if removed != 0 {
                info!(
                    "[{peer}]      ledger retention removed {removed} \
                     share(s) past --ledger-keep"
                );
            }
        }
        let room = self.credited.len() < MAX_CREDITED_NAMES;
        let total = if let Some(t) = self.credited.get_mut(&s.username) {
            *t = t.saturating_add(a.work.difficulty);
            *t
        } else if room {
            self.credited.insert(s.username.clone(), a.work.difficulty);
            a.work.difficulty
        } else {
            a.work.difficulty
        };
        debug!(
            "[{peer}]   <- accepted diff={} hash={} height={} split={} pool={} sats; {} credited {}",
            a.work.difficulty,
            hex::encode(a.work.block_hash),
            a.work.height,
            a.work.paid_to_split,
            a.work.paid_to_pool,
            s.username,
            total,
        );
        Ok(())
    }

    fn on_block_txns(&mut self, plain: &[u8]) {
        let peer = self.peer;
        match plain.get(1).copied() {
            Some(validation::response::BLOCK_TXNS) => {
                match TxnBundle::decode(plain, validation::response::BLOCK_TXNS) {
                    Ok(bundle) => {
                        info!(
                            "[{peer}]   -> block transactions: job {} {} {} txns",
                            bundle.job_index,
                            bundle.status,
                            bundle.txns.len()
                        );
                        match self.awaiting_txns.remove(&bundle.job_index) {
                            Some(a) if bundle.status == validation::Status::Ok => {
                                match block_matches_header(&a, &bundle.txns) {
                                    Ok(()) => {
                                        let block = ratum::bitcoin::serialize_block(
                                            &a.work.header,
                                            &a.work.coinbase_tx,
                                            &bundle.txns,
                                        );
                                        submit(peer, &self.server.node, &block);
                                    }
                                    Err(why) => error!(
                                        "[{peer}]      not relaying job {}: {why}",
                                        bundle.job_index
                                    ),
                                }
                            }
                            Some(_) => {
                                error!("[{peer}]      cannot assemble the block: {}", bundle.status)
                            }
                            None => warn!(
                                "[{peer}]      transactions for job {} that nothing is waiting on",
                                bundle.job_index
                            ),
                        }
                    }
                    Err(e) => error!("[{peer}]   !! bad block response: {e}"),
                }
            }
            other => warn!("[{peer}]   !! unhandled 0x50 response {other:?}"),
        }
    }
}

enum Framing {
    /// A complete frame header was read.
    HeaderRead,
    Idle,
    Closed,
}

/// Reads a frame header, distinguishing a connection that sent nothing from one that
/// stopped partway through a header. Only the latter is a timeout.
fn read_header(stream: &mut TcpStream, hdr: &mut [u8; 4]) -> io::Result<Framing> {
    let mut got = 0usize;
    let mut partial_since: Option<Instant> = None;
    while got < hdr.len() {
        match stream.read(&mut hdr[got..]) {
            Ok(0) => return Ok(Framing::Closed),
            Ok(n) => {
                got += n;
                partial_since.get_or_insert_with(Instant::now);
            }
            Err(e)
                if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
                    && got == 0 =>
            {
                return Ok(Framing::Idle);
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if partial_since.is_some_and(|t| t.elapsed() > HEADER_TIMEOUT) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "frame header partially received",
                    ));
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(Framing::HeaderRead)
}

fn block_matches_header(a: &Accepted, txns: &[Vec<u8>]) -> Result<(), String> {
    let committed = ratum::header::HeaderV2::deserialize(&a.work.header)
        .ok_or_else(|| "the header does not deserialize".to_string())?
        .merkle_root;

    let mut ids = Vec::with_capacity(txns.len() + 1);
    ids.push(ratum::bitcoin::sha256d(&a.work.coinbase_tx));
    for (i, raw) in txns.iter().enumerate() {
        match ratum::bitcoin::txid(raw) {
            Ok(id) => ids.push(id),
            Err(e) => return Err(format!("transaction {i} does not decode: {e}")),
        }
    }
    let count = ids.len();
    let (built, mutated) = ratum::bitcoin::merkle_root_of(&ids).ok_or("no transactions")?;
    if mutated {
        return Err(format!(
            "{count} transactions form a mutated merkle tree (duplicate hashes); \
             the node would reject the block"
        ));
    }
    if built != committed {
        return Err(format!(
            "{count} transactions have merkle root {}, but the header commits to {}",
            hex::encode(ratum::bitcoin::reversed(&built)),
            hex::encode(ratum::bitcoin::reversed(&committed))
        ));
    }
    Ok(())
}

/// Submit the block to the node, or return `true` when the block's transactions must be requested
/// from the gateway before it can be submitted.
fn relay_or_request_txns(
    peer: std::net::SocketAddr,
    node: &rpc::Client,
    a: &Accepted,
    subsidy_only: bool,
) -> bool {
    let template_txns = a.work.txn_count;
    if !subsidy_only && template_txns != 0 {
        info!("[{peer}]      block has {template_txns} more transactions; requesting them");
        return true;
    }
    submit(peer, node, &ratum::bitcoin::serialize_block(&a.work.header, &a.work.coinbase_tx, &[]));
    false
}

/// How many times to submit a block, and how long to wait between attempts. A block is
/// relayable for seconds, not minutes, so the count is small; a node rejection or a credential
/// error is not retried, only a network or node-busy error.
const SUBMIT_ATTEMPTS: usize = 3;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_millis(500);

fn submit(peer: std::net::SocketAddr, node: &rpc::Client, block: &[u8]) {
    debug!("[{peer}]      block ({} bytes): {}", block.len(), hex::encode(block));
    for attempt in 1..=SUBMIT_ATTEMPTS {
        match node.submit_block(block) {
            Ok(None) => {
                info!("[{peer}]      submitted: node accepted the block");
                return;
            }
            Ok(Some(reason)) => {
                // The node parsed the block and rejected it as invalid; a retry cannot
                // change that.
                warn!("[{peer}]      submitted: node rejected the block ({reason:?})");
                return;
            }
            Err(e) if e.is_unauthorized() => {
                error!(
                    "[{peer}]      could not relay: the node refused the pool's RPC credential \
                     ({e}); if the node has restarted, its cookie has changed"
                );
                break;
            }
            Err(e) => {
                warn!("[{peer}]      could not relay (attempt {attempt}/{SUBMIT_ATTEMPTS}): {e}");
                if attempt < SUBMIT_ATTEMPTS {
                    std::thread::sleep(SUBMIT_RETRY_DELAY);
                }
            }
        }
    }
    // The gateway has already submitted this block to its own node, but log the hex at error
    // so the pool operator can resubmit it with submitblock if the gateway's own submission
    // also failed.
    error!(
        "[{peer}]      stopped relaying the block after {SUBMIT_ATTEMPTS} attempts; resubmit with \
         submitblock: {}",
        hex::encode(block)
    );
}

fn describe_share(s: &PowSubmit) -> String {
    let sections = match (&s.job, &s.coinbase) {
        (Some(j), Some(c)) => format!(
            " +job(h={} {} branches) +coinbase(id={} {}+{}B)",
            j.height,
            j.merkle_branches.len(),
            c.coinbase_id,
            c.coinb1.len(),
            c.coinb2.len()
        ),
        (Some(j), None) => format!(" +job(h={} {} branches)", j.height, j.merkle_branches.len()),
        (None, Some(c)) => format!(" +coinbase(id={})", c.coinbase_id),
        (None, None) => String::new(),
    };
    format!(
        "job={} cb={} diff={} nonce={:08x} ntime={:08x} user={:?}{}{}{}",
        s.job_id,
        s.coinbase_id,
        s.difficulty(),
        s.nonce,
        s.ntime,
        s.username,
        if s.is_block { " is_block" } else { "" },
        if s.quickdiff { " quickdiff" } else { "" },
        sections
    )
}

/// Whether a hello's user agent matches the allowed prefixes; an empty list allows every
/// agent. A prefix match, not equality, so a list entry names a build family
/// ("ratum-gateway/") or one exact build ("ratum-gateway/0.1.7/1eb08f1").
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

    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// A peer that sends fewer than `n` bytes and then holds the connection gets `TimedOut` at
    /// the deadline, not the socket read timeout on every byte.
    #[test]
    fn read_exact_deadline_times_out_on_a_slow_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&[0x01]).unwrap();
            // Hold the connection open past the reader's deadline without sending the rest.
            std::thread::sleep(Duration::from_millis(600));
            drop(c);
        });
        let (mut server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let started = Instant::now();
        let r = read_exact_deadline(&mut server, 4, started, Duration::from_millis(200));
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2), "it returns near the deadline");
        sender.join().unwrap();
    }

    /// The whole read still succeeds when the bytes arrive in time, even split across reads.
    #[test]
    fn read_exact_deadline_reads_all_bytes_when_they_arrive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&[1, 2]).unwrap();
            std::thread::sleep(Duration::from_millis(60));
            c.write_all(&[3, 4, 5, 6]).unwrap();
        });
        let (mut server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let got =
            read_exact_deadline(&mut server, 4, Instant::now(), Duration::from_secs(5)).unwrap();
        assert_eq!(got, vec![1, 2, 3, 4]);
        sender.join().unwrap();
    }
}
