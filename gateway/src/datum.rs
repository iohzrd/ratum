//! The gateway's end of the DATUM protocol: what it holds about the pool across connections, and
//! the loop that opens a connection again after every disconnect.

pub mod abw;
mod session;
mod validation_replies;

use crate::gateway::Gateway;
use crate::job::Job;
use crate::stratum::notify_id::NotifyPrefix;
use crate::tally::ShareTallies;
use crate::template::Template;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::keys::{KeyPairs, PublicKeys};
use ratum::datum::messages::config::ClientConfig;
use ratum::header::BlockHeaderV2;
use ratum::{lock, target};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MIN_QUEUE_CAPACITY: usize = 64;
const FAILURES_BEFORE_SHUTDOWN: u32 = 2;

/// The least time between two log lines `RepeatedEvent` lets through for one event.
const REPEATED_EVENT_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Counts one event that can recur once per share, so it is logged at its first occurrence
/// and then at most once per `REPEATED_EVENT_LOG_INTERVAL`, each later line carrying the count
/// since the line before.
#[derive(Default)]
struct RepeatedEvent {
    last_logged_at: Option<Instant>,
    since_last_line: u64,
}

impl RepeatedEvent {
    /// Counts one occurrence. Returns the occurrences to report, this one included, when a
    /// line is due: 1 for an occurrence after more than an interval without a line.
    fn occurred(&mut self, now: Instant) -> Option<u64> {
        self.since_last_line += 1;
        if self
            .last_logged_at
            .is_some_and(|t| now.saturating_duration_since(t) < REPEATED_EVENT_LOG_INTERVAL)
        {
            return None;
        }
        self.last_logged_at = Some(now);
        Some(std::mem::take(&mut self.since_last_line))
    }
}

/// The value under which the pool dictates no split, so no request is made for it.
const MIN_COINBASER_VALUE: u64 = 31_250_000;

/// How long a coinbaser request waits for its answer before the job is built without a split.
pub const COINBASER_WAIT: Duration = Duration::from_secs(5);

/// A coinbaser request the template thread left for the session thread to send, carrying the
/// template the job answering it is built from. Holding them together is what makes a
/// response impossible to apply to another template: a newer template's request replaces
/// this one, so only the newest template's request is ever held.
pub struct PendingCoinbaser {
    pub value: u64,
    pub prev_hash: [u8; 32],
    pub template: Arc<Template>,
    /// Whether the template started a new block, which decides what an unanswered request
    /// does: on a new block the priority job stays the work served, otherwise a job with no
    /// split is built.
    pub new_block: bool,
    pub requested_at: Instant,
}

/// The pool's configuration with its minimum difficulty rounded up to a power of two.
fn with_rounded_min_difficulty(c: ClientConfig) -> ClientConfig {
    let rounded = target::pow2_ceil(c.min_difficulty);
    if rounded != c.min_difficulty {
        warn!(
            "pool minimum difficulty {} is not a power of two; using {rounded}",
            c.min_difficulty
        );
    }
    ClientConfig { min_difficulty: rounded, ..c }
}

pub fn abw_disabled(c: &ClientConfig) -> bool {
    c.v3.is_some_and(|v3| v3.abw_disabled)
}

#[derive(Clone)]
pub struct QueuedShare {
    pub job: Arc<Job>,
    pub prefix: NotifyPrefix,
    pub is_block: bool,
    pub target_byte: u8,
    pub header: BlockHeaderV2,
    pub username: String,
}

/// What one DATUM connection has told the gateway, reset as a whole when it closes.
#[derive(Default)]
struct SessionView {
    config: Option<ClientConfig>,
    motd: String,
    abw: abw::AbwAssignments,
    coinbaser_request: Option<PendingCoinbaser>,
    waker: Option<Waker>,
    /// Shares not sent because their anti-block-withholding commitment is not held.
    abw_unheld: RepeatedEvent,
}

/// Whether new work must commit to an anti-block-withholding assignment, and which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbwState {
    NotRequired,
    Awaiting,
    Assigned(abw::AbwAssignment),
}

/// What the gateway holds about the pool between and across DATUM connections: the
/// connection's own view under one lock, and what outlives a connection (the share tallies
/// and the queued shares) beside it.
pub struct PoolState {
    session: Mutex<SessionView>,
    tallies: Mutex<ShareTallies>,
    queue: Mutex<VecDeque<QueuedShare>>,
    queue_capacity: usize,
    /// Shares not queued because the queue was full.
    queue_full: Mutex<RepeatedEvent>,
}

impl PoolState {
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            session: Mutex::new(SessionView::default()),
            tallies: Mutex::new(ShareTallies::default()),
            queue: Mutex::new(VecDeque::new()),
            queue_capacity: queue_capacity.max(MIN_QUEUE_CAPACITY),
            queue_full: Mutex::new(RepeatedEvent::default()),
        }
    }

    fn session(&self) -> MutexGuard<'_, SessionView> {
        lock(&self.session)
    }

    fn wake(&self) {
        if let Some(w) = self.session().waker.as_ref()
            && let Err(e) = w.wake()
        {
            debug!("could not wake the DATUM session thread: {e}");
        }
    }

    pub fn abw_state(&self) -> AbwState {
        let s = self.session();
        if !s.config.as_ref().is_some_and(|c| c.v3.is_some() && !abw_disabled(c)) {
            return AbwState::NotRequired;
        }
        s.abw.assignment().map_or(AbwState::Awaiting, AbwState::Assigned)
    }

    pub fn motd(&self) -> String {
        self.session().motd.clone()
    }

    pub fn tallies(&self) -> ShareTallies {
        lock(&self.tallies).clone()
    }

    fn tally(&self, accepted: bool, diff: u64) {
        let mut t = lock(&self.tallies);
        if accepted { &mut t.accepted } else { &mut t.rejected }.add(diff);
    }

    pub fn is_active(&self) -> bool {
        self.session().config.is_some()
    }

    pub fn pool_config(&self) -> Option<ClientConfig> {
        self.session().config.clone()
    }

    /// The pool's minimum share difficulty; 0 while no pool configuration is held.
    pub fn min_difficulty(&self) -> u64 {
        self.session().config.as_ref().map_or(0, |c| c.min_difficulty)
    }

    /// Leaves a coinbaser request for the session thread to send, replacing any request an
    /// older template left unsent. Returns whether one was left: under
    /// `MIN_COINBASER_VALUE` the pool dictates no split, and with no pool configuration
    /// received there is no session to send it on.
    pub fn request_coinbaser(&self, template: &Arc<Template>, new_block: bool) -> bool {
        if template.coinbase_value < MIN_COINBASER_VALUE {
            return false;
        }
        let mut s = self.session();
        if s.config.is_none() {
            return false;
        }
        s.coinbaser_request = Some(PendingCoinbaser {
            value: template.coinbase_value,
            prev_hash: template.prev_hash,
            template: Arc::clone(template),
            new_block,
            requested_at: Instant::now(),
        });
        drop(s);
        self.wake();
        true
    }

    /// Resets the connection's view, dropping any coinbaser request it had not yet sent.
    /// Returns whether the connection had received a pool configuration.
    fn clear_after_disconnect(&self) -> bool {
        let closed = std::mem::take(&mut *self.session());
        lock(&self.queue).clear();
        closed.config.is_some()
    }

    fn take_queued_shares(&self) -> VecDeque<QueuedShare> {
        std::mem::take(&mut *lock(&self.queue))
    }

    pub fn queue_share(&self, share: QueuedShare) {
        let mut q = lock(&self.queue);
        if q.len() >= self.queue_capacity {
            match lock(&self.queue_full).occurred(Instant::now()) {
                Some(1) => error!(
                    "share queue full ({} shares waiting for the pool); share from {:?} not queued",
                    q.len(),
                    share.username
                ),
                Some(n) => error!(
                    "share queue full ({} shares waiting for the pool); {n} shares not queued \
                     since the last report",
                    q.len()
                ),
                None => {}
            }
            return;
        }
        q.push_back(share);
        drop(q);
        self.wake();
    }
}

pub fn user_agent() -> String {
    format!("ratum-gateway/{}/{}", env!("CARGO_PKG_VERSION"), crate::GIT_COMMIT)
}

const RECONNECT_DELAY_MIN: Duration = Duration::from_secs(5);
const RECONNECT_DELAY_SPREAD: Duration = Duration::from_secs(15);

/// Connects to the pool again after every disconnect. With `datum.pooled_mining_only` set,
/// new stratum connections are refused from startup and from each disconnect until a
/// session receives the pool's configuration, and every stratum client is disconnected on
/// the second failed attempt in a row (a session that received a configuration counts as
/// the first).
pub fn run_forever(gateway: &Gateway, pool_pubkey: PublicKeys, identity: KeyPairs) {
    let pool = &gateway.pool;
    let d = &gateway.config.datum;
    let mut failures = 0u32;
    let mut resume_token = None;
    loop {
        info!("connecting to DATUM pool {}:{}", d.pool_host, d.pool_port);
        let outcome = session::run(gateway, pool_pubkey, &identity, &mut resume_token);
        let was_active = pool.clear_after_disconnect();
        if let Err(e) = outcome {
            error!("DATUM connection ended: {e}");
        }
        failures = if was_active { 1 } else { failures.saturating_add(1) };
        if d.pooled_mining_only && failures == FAILURES_BEFORE_SHUTDOWN {
            warn!(
                "The DATUM pool is unreachable and datum.pooled_mining_only is set: disconnecting stratum clients until it is reached again"
            );
            gateway.stratum.shutdown_all();
        }
        if was_active {
            gateway.template_waker.rebuild();
        }
        let delay = RECONNECT_DELAY_MIN
            + Duration::from_millis(u64::from(
                ratum::rand::u32() % (RECONNECT_DELAY_SPREAD.as_millis() as u32 + 1),
            ));
        info!("reconnecting to the pool in {:.1}s", delay.as_secs_f64());
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_event_is_reported_first_and_then_once_per_interval_with_its_count() {
        let mut e = RepeatedEvent::default();
        let start = Instant::now();
        assert_eq!(e.occurred(start), Some(1));
        for i in 1..=5 {
            assert_eq!(e.occurred(start + Duration::from_secs(i)), None);
        }
        let due = start + REPEATED_EVENT_LOG_INTERVAL;
        assert_eq!(e.occurred(due), Some(6), "the five held back and this one");
        assert_eq!(e.occurred(due + Duration::from_secs(1)), None);
        let quiet = due + 3 * REPEATED_EVENT_LOG_INTERVAL;
        assert_eq!(e.occurred(quiet), Some(2), "the one held back is carried to the next line");
        assert_eq!(e.occurred(quiet + 2 * REPEATED_EVENT_LOG_INTERVAL), Some(1));
    }
}
