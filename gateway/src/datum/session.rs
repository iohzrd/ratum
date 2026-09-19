//! One DATUM connection from its handshake to its end: the frames it reads, the pool messages it
//! dispatches, and the timeouts that close it.

mod assignments;
mod shares;

use super::{
    COINBASER_WAIT, PendingCoinbaser, abw_disabled, user_agent, validation_replies,
    with_rounded_min_difficulty,
};
use crate::config::DatumConfig;
use crate::gateway::Gateway;
use crate::publish;
use log::{debug, error, info, warn};
use ratum::datum::channel;
use ratum::datum::client::ClientChannel;
use ratum::datum::framing::{self, FrameHeader, FrameRead, MAX_MINING_PAD_LEN};
use ratum::datum::handshake::{ProtocolVersion, ResumeToken};
use ratum::datum::keys::{KeyPairs, PublicKeys};
use ratum::datum::messages::abw::{self, CandidateRef};
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::config::ClientConfig;
use ratum::datum::messages::migration::MigrationRequest;
use ratum::datum::messages::server_subcmd;
use ratum::datum::messages::share_response::ShareResponse;
use ratum::datum::messages::validation;
use ratum::poll::{PolledSocket, WRITE_TIMEOUT};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SHARE_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs one DATUM connection to its end. `resume_token` is the token the last version 3
/// configuration carried, sent in the hello and replaced by the one this connection receives.
pub(super) fn run(
    gateway: &Gateway,
    pool_pubkey: PublicKeys,
    identity: &KeyPairs,
    resume_token: &mut Option<ResumeToken>,
) -> Result<(), SessionError> {
    Session::open(gateway, pool_pubkey, identity, resume_token)
        .and_then(|mut session| session.run())
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("channel: {0}")]
    Channel(#[from] channel::Error),
    #[error("no message from the pool for {0:?}")]
    GlobalTimeout(Duration),
    #[error("no share accepted for {0:?}")]
    ShareAckTimeout(Duration),
    #[error("could not resolve {0}")]
    Resolve(String),
    #[error("malformed pool configuration: {0}")]
    BadConfig(String),
}

struct Session<'a> {
    gateway: &'a Gateway,
    identity: &'a KeyPairs,
    resume_token: &'a mut Option<ResumeToken>,
    pool_sign_pk: [u8; 32],
    global_timeout: Duration,
    socket: PolledSocket,
    channel: ClientChannel,
    last_server_message_at: Instant,
    last_share_sent_at: Option<Instant>,
    last_share_accepted_at: Option<Instant>,
    sent_sections: Vec<Option<shares::SentSections>>,
    /// The newest coinbaser request sent and not yet answered, with the template whose job it
    /// is for. Sending a request replaces the one held, since only the newest template's
    /// work is served.
    awaiting_coinbaser: Option<PendingCoinbaser>,
}

fn connect(d: &DatumConfig) -> Result<TcpStream, SessionError> {
    let target = format!("{}:{}", d.pool_host, d.pool_port);
    let addrs =
        target.to_socket_addrs().map_err(|e| SessionError::Resolve(format!("{target}: {e}")))?;
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Err(e) => {
                debug!("connect to {addr} failed: {e}");
                last = Some(e);
            }
        }
    }
    Err(last.map_or(SessionError::Resolve(target), SessionError::Io))
}

impl<'a> Session<'a> {
    fn open(
        gateway: &'a Gateway,
        pool_pubkey: PublicKeys,
        identity: &'a KeyPairs,
        resume_token: &'a mut Option<ResumeToken>,
    ) -> Result<Self, SessionError> {
        let pool = &gateway.pool;
        let config = &gateway.config;
        let global_timeout = config.protocol_global_timeout();
        let mut socket = PolledSocket::new(connect(&config.datum)?)?;
        let mut channel = ClientChannel::with_key_pairs(
            identity.clone(),
            KeyPairs::generate(),
            ratum::rand::u32(),
        );
        let protocol_version = if config.datum.protocol_v3 {
            ProtocolVersion::V3 { resume: *resume_token }
        } else {
            ProtocolVersion::V1
        };
        let hello = channel.hello(&pool_pubkey.box_pk, &user_agent(), protocol_version);
        socket.write_all(&hello, WRITE_TIMEOUT)?;

        let (header, body) = framing::read_frame(
            &mut socket,
            |bytes| channel.unmask_header(bytes),
            framing::MAX_CMD_LEN,
            Instant::now() + global_timeout,
        )?;
        channel.read_handshake_response(header, &body, &pool_pubkey.sign_pk)?;
        info!("DATUM Server MOTD: {}", channel.motd());

        pool.session().waker = Some(socket.waker()?);

        let slots = config.datum.protocol_job_slots;
        Ok(Session {
            gateway,
            identity,
            resume_token,
            pool_sign_pk: pool_pubkey.sign_pk,
            global_timeout,
            socket,
            channel,
            last_server_message_at: Instant::now(),
            last_share_sent_at: None,
            last_share_accepted_at: None,
            sent_sections: vec![None; slots],
            awaiting_coinbaser: None,
        })
    }

    fn send_mining(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        let pad = ratum::rand::bytes::<MAX_MINING_PAD_LEN>();
        let pad_len = 1 + usize::from(pad[0]) % MAX_MINING_PAD_LEN;
        let mut padded = Vec::with_capacity(payload.len() + pad_len);
        padded.extend_from_slice(payload);
        padded.extend_from_slice(&pad[..pad_len]);
        let wire = match self.channel.encrypt(framing::cmd::MINING, &padded) {
            Ok(w) => w,
            Err(channel::Error::TooLarge(n)) => {
                error!("mining message of {n} bytes exceeds the protocol limit; not sent");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        self.socket.write_all(&wire, WRITE_TIMEOUT)?;
        Ok(())
    }

    fn run(&mut self) -> Result<(), SessionError> {
        loop {
            if self.last_server_message_at.elapsed() >= self.global_timeout {
                return Err(SessionError::GlobalTimeout(self.global_timeout));
            }
            if let (Some(sent), Some(acked)) =
                (self.last_share_sent_at, self.last_share_accepted_at)
                && sent > acked
                && sent.duration_since(acked) >= SHARE_ACK_TIMEOUT
            {
                return Err(SessionError::ShareAckTimeout(SHARE_ACK_TIMEOUT));
            }

            self.send_pending()?;
            if let Some(unanswered) =
                self.awaiting_coinbaser.take_if(|p| p.requested_at.elapsed() >= COINBASER_WAIT)
            {
                warn!("coinbaser request timed out after {}s", COINBASER_WAIT.as_secs());
                publish::on_coinbaser(self.gateway, &unanswered, None);
            }

            let left = self.global_timeout.saturating_sub(self.last_server_message_at.elapsed());
            if !self.socket.readable() {
                self.socket.wait(Some(self.until_coinbaser_due(left)))?;
                continue;
            }
            let unmask = |bytes| self.channel.unmask_header(bytes);
            let read = framing::read_next_frame(
                &mut self.socket,
                unmask,
                framing::MAX_CMD_LEN,
                left,
                left,
            )?;
            let (header, body) = match read {
                FrameRead::Closed => {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                FrameRead::Empty => continue,
                FrameRead::Complete(header, body) => (header, body),
            };
            let plain = self.channel.decrypt(header, &body)?;
            self.last_server_message_at = Instant::now();
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

    fn on_mining(&mut self, header: FrameHeader, plain: &[u8]) -> Result<(), SessionError> {
        match plain.first().copied() {
            Some(server_subcmd::CONFIG) => {
                if !header.is_signed {
                    error!("pool configuration was not signed; ignored");
                    return Ok(());
                }
                self.on_config_message(plain)?;
            }
            Some(server_subcmd::MIGRATION) => {
                if !header.is_signed {
                    error!("migration request was not signed; ignored");
                    return Ok(());
                }
                log_migration_request(plain);
            }
            Some(abw::subcmd::ASSIGNMENT_NOTICE) => self.on_abw_notice(plain),
            Some(abw::subcmd::REVEAL) => self.on_abw_reveal(plain),
            Some(abw::subcmd::CANDIDATE_RECEIPT) => {
                if let Ok(c) = CandidateRef::decode_candidate(plain, abw::subcmd::CANDIDATE_RECEIPT)
                {
                    debug!("ABW candidate receipt for slot {}", c.slot);
                }
            }
            // The pool releases a candidate only to say it will not be referenced
            // again; the gateway keeps no per-candidate state, so there is nothing to undo.
            Some(abw::subcmd::CANDIDATE_RELEASE) => {}
            Some(server_subcmd::COINBASER) => self.on_coinbaser_response(plain),
            Some(server_subcmd::SHARE_RESPONSE) => match ShareResponse::decode(plain) {
                Ok(r) => self.on_share_response(r),
                Err(e) => warn!("malformed share response: {e}"),
            },
            Some(validation::SUBCMD) => self.on_validation(plain)?,
            Some(server_subcmd::BLOCKNOTIFY) => {
                debug!("pool blocknotify");
                self.gateway.template_waker.raise();
            }
            other => warn!("unknown DATUM mining sub-command {other:?}"),
        }
        Ok(())
    }

    /// How long until the request held, if any, reaches `COINBASER_WAIT`, so the loop does
    /// not sleep past that deadline.
    fn until_coinbaser_due(&self, left: Duration) -> Duration {
        match &self.awaiting_coinbaser {
            Some(p) => left.min(COINBASER_WAIT.saturating_sub(p.requested_at.elapsed())),
            None => left,
        }
    }

    /// Serves the work for the template the answered request was made for. The response is
    /// paired with its request by coinbase value, so a late answer to a request a newer
    /// template already replaced is not applied to that newer template.
    fn on_coinbaser_response(&mut self, plain: &[u8]) {
        let (waiting, split) = match CoinbaserResponse::decode(plain) {
            Ok(r) => {
                debug!(
                    "coinbaser response: {} sats, id {}, {} outputs",
                    r.value,
                    r.coinbaser_id,
                    r.outputs.len()
                );
                let Some(waiting) = self.awaiting_coinbaser.take_if(|p| p.value == r.value) else {
                    debug!(
                        "coinbaser response for {} sats matches no waiting request (a newer \
                         request replaced it); not used",
                        r.value
                    );
                    return;
                };
                (waiting, Some(r))
            }
            Err(e) => {
                let Some(waiting) = self.awaiting_coinbaser.take() else {
                    error!("malformed coinbaser response ({e}) with no request waiting");
                    return;
                };
                error!("malformed coinbaser response ({e}); the job pays the pool script alone");
                let empty =
                    CoinbaserResponse { value: waiting.value, coinbaser_id: 0, outputs: vec![] };
                (waiting, Some(empty))
            }
        };
        publish::on_coinbaser(self.gateway, &waiting, split);
    }

    /// A configuration that does not decode ends the session, which then reconnects: without
    /// one the session serves no pooled work, and the pool's keepalives would hold it open.
    fn on_config_message(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        let c = ClientConfig::decode(plain).map_err(|e| SessionError::BadConfig(e.to_string()))?;
        match (c.v3, self.gateway.config.datum.protocol_v3) {
            (Some(v3), true) => *self.resume_token = Some(v3.resume_token),
            (Some(_), false) => {
                error!("pool answered the version 1 hello with a version 3 configuration; ignored");
                return Ok(());
            }
            (None, true) => warn!(
                "pool responded to the version 3 hello with a version 1 configuration; this \
                 session runs version 1 (no anti-block-withholding)"
            ),
            (None, false) => {}
        }
        self.on_config(with_rounded_min_difficulty(c));
        Ok(())
    }

    fn on_config(&self, config: ClientConfig) {
        info!(
            "DATUM pool configuration: prime_id {:#010x}, tag {:?}, min diff {}, payout script {}",
            config.prime_id,
            config.coinbase_tag,
            config.min_difficulty,
            hex::encode(&config.payout_script)
        );
        let mut s = self.gateway.pool.session();
        let previous = s.config.replace(config.clone());
        if previous.is_none() {
            s.motd = self.channel.motd().to_string();
        }
        if previous.as_ref().is_some_and(|p| abw_disabled(p) != abw_disabled(&config)) {
            s.abw = Default::default();
        }
        drop(s);
        if config.v3.is_some() {
            info!(
                "DATUM pool anti-block-withholding: {}",
                if abw_disabled(&config) { "disabled by the pool" } else { "enabled" }
            );
        }
        if previous.as_ref() != Some(&config) {
            self.gateway.template_waker.rebuild();
        }
    }

    fn on_validation(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        match validation_replies::response_to(
            self.gateway,
            &self.pool_sign_pk,
            self.identity,
            plain,
        ) {
            Some(response) => self.send_mining(&response),
            None => Ok(()),
        }
    }
}

fn log_migration_request(plain: &[u8]) {
    match MigrationRequest::decode(plain) {
        Ok(MigrationRequest::Redirect(t)) => warn!(
            "pool requested migration to {:?} port {} (pool key {}); not supported, staying \
             on the configured pool",
            t.host,
            t.port,
            &t.pubkey.to_hex()[..16]
        ),
        Ok(MigrationRequest::ReturnHome) => {
            warn!("pool requested a return to the configured pool; this gateway is on it");
        }
        Err(e) => error!("malformed migration request ({e}); ignored"),
    }
}
