mod session;
mod validation;

use crate::config::Config;
use crate::job::{Abw, Job, PoolConfig};
use crate::tally::Tally;
use crate::template::Notify;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::abw;
use ratum::datum::handshake::{KeyPairs, PUBKEY_LEN};
use ratum::datum::messages::{ClientConfig, ClientConfigV3, CoinbaserResponse, ResumeToken};
use ratum::datum::share;
use ratum::datum::validation::{JOB_INDEX_INVALID, Status};
use ratum::header::HeaderV2;
use ratum::target;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const COINBASER_WAIT: Duration = Duration::from_secs(5);
const COINBASER_MIN_VALUE: u64 = 31_250_000;
const MIN_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
pub(in crate::datum) struct AbwSlots {
    keys: [Option<[u8; 32]>; abw::ASSIGNMENT_SLOTS as usize],
    active: Option<u8>,
}

impl AbwSlots {
    fn assignment(&self) -> Option<Abw> {
        let slot = self.active?;
        Some(Abw { slot, key_hash: self.keys[slot as usize]? })
    }

    pub(in crate::datum) fn holds(&self, a: Abw) -> bool {
        self.keys[a.slot as usize] == Some(a.key_hash)
    }

    pub(in crate::datum) fn install(&mut self, slot: u8, key_hash: [u8; 32], active: bool) {
        self.keys[slot as usize] = Some(key_hash);
        if active {
            self.active = Some(slot);
        }
    }

    pub(in crate::datum) fn activate(&mut self, slot: u8) -> bool {
        if self.keys[slot as usize].is_none() {
            return false;
        }
        self.active = Some(slot);
        true
    }

    pub(in crate::datum) fn reveal(&mut self, slot: u8, xor_key: &abw::XorKey) -> bool {
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
    pub(in crate::datum) fn from_message(c: ClientConfig) -> Self {
        Self {
            payout_script: c.payout_script,
            prime_id: u64::from(c.prime_id),
            coinbase_tag: c.coinbase_tag,
            min_difficulty: rounded_min_difficulty(c.min_difficulty),
            protocol_v3: false,
            abw_disabled: false,
        }
    }

    pub(in crate::datum) fn from_message_v3(c: ClientConfigV3) -> Self {
        Self {
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

pub struct Pool {
    pub(in crate::datum) config: Mutex<Option<PoolConfig>>,
    min_difficulty: AtomicU64,
    pub stats: Mutex<Stats>,
    pub(in crate::datum) queue: Mutex<VecDeque<QueuedShare>>,
    queue_capacity: usize,
    pub(in crate::datum) coinbaser: Mutex<Option<Arc<CoinbaserRequestState>>>,
    pub slots: Mutex<Vec<Option<Arc<Job>>>>,
    pub(in crate::datum) abw: Mutex<AbwSlots>,
    pub(in crate::datum) resume_token: Mutex<Option<ResumeToken>>,
    pub(in crate::datum) node: Option<ratum::rpc::Client>,
    pub notify: Arc<Notify>,
    pub failures: AtomicU32,
    pub(in crate::datum) waker: Mutex<Option<Arc<Waker>>>,
}

impl Pool {
    pub fn new(
        slots: usize,
        queue_capacity: usize,
        notify: Arc<Notify>,
        node: Option<ratum::rpc::Client>,
    ) -> Self {
        Self {
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

    pub(in crate::datum) fn set_config(&self, config: PoolConfig) -> Option<PoolConfig> {
        self.min_difficulty.store(config.min_difficulty, Ordering::Relaxed);
        ratum::lock(&self.config).replace(config)
    }

    fn disconnected(&self) -> bool {
        *ratum::lock(&self.waker) = None;
        let was_active = ratum::lock(&self.config).take().is_some();
        let waiting = ratum::lock(&self.coinbaser).take();
        if let Some(state) = waiting {
            state.done.notify_all();
        }
        ratum::lock(&self.queue).clear();
        *ratum::lock(&self.abw) = AbwSlots::default();
        was_active
    }

    pub(in crate::datum) fn slot(&self, index: u8) -> Result<Arc<Job>, (u8, Status)> {
        let slots = ratum::lock(&self.slots);
        if index as usize >= slots.len() {
            return Err((JOB_INDEX_INVALID, Status::BadJobIndex));
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
        let superseded = ratum::lock(&self.coinbaser).replace(Arc::clone(&state));
        if let Some(old) = superseded {
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
        Self {
            host: config.datum.pool_host.clone(),
            port: config.datum.pool_port,
            pool_sign_pk,
            pool_box_pk,
            global_timeout: Duration::from_secs(config.datum.protocol_global_timeout),
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

const RECONNECT_DELAY_MIN: Duration = Duration::from_secs(5);
const RECONNECT_DELAY_SPREAD: Duration = Duration::from_secs(15);

pub fn run_forever(settings: Settings, pool: Arc<Pool>, identity: KeyPairs) {
    loop {
        info!("connecting to DATUM pool {}:{}", settings.host, settings.port);
        let outcome = session::run(&settings, &pool, &identity);
        let was_active = pool.disconnected();
        if let Err(e) = outcome {
            error!("DATUM connection ended: {e}");
        }
        if was_active {
            pool.failures.store(1, Ordering::Relaxed);
            pool.notify.rebuild();
        } else {
            pool.failures.fetch_add(1, Ordering::Relaxed);
        }
        let delay = RECONNECT_DELAY_MIN
            + Duration::from_millis(u64::from(
                ratum::rand::u32() % (RECONNECT_DELAY_SPREAD.as_millis() as u32 + 1),
            ));
        info!("reconnecting to the pool in {:.1}s", delay.as_secs_f64());
        std::thread::sleep(delay);
    }
}
