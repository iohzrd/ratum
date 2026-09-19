//! The stratum server: the listener, the connected clients, and the conditions under which a new
//! connection is refused.

mod connection;
pub mod notify_id;

use crate::config::Config;
use crate::gateway::Gateway;
use crate::seen_shares::SeenShareHashes;
use crate::tally::ShareTallies;
use connection::{Connection, Disconnect};
use log::{debug, info, warn};
use mio::Waker;
use ratum::lock;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HASHRATE_WINDOW_VALID: Duration = Duration::from_secs(3 * ratum::SECS_PER_MINUTE);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default)]
pub struct ClientStats {
    pub peer: String,
    pub user_agent: String,
    pub username: String,
    /// When `mining.subscribe` was answered; none until it is, which is what `subscribed`
    /// reads.
    pub subscribed_at: Option<Instant>,
    pub current_diff: u64,
    pub shares: ShareTallies,
    pub last_accepted_at: Option<Instant>,
    /// The rate the last completed window measured and the instant it ended, written
    /// together by `roll_window`, so no reader divides one window's work by another's
    /// length.
    pub hashrate: Option<(Instant, f64)>,
}

impl ClientStats {
    pub fn subscribed(&self) -> bool {
        self.subscribed_at.is_some()
    }

    /// Hashes per second over the last completed window, while that window is recent.
    pub fn hashrate_hs(&self) -> Option<f64> {
        self.hashrate.filter(|(at, _)| at.elapsed() <= HASHRATE_WINDOW_VALID).map(|(_, hs)| hs)
    }
}

pub struct ClientEntry {
    /// The connection's identity, fixed at construction. It is outside `stats` so the
    /// registry can be keyed by it without locking every client to read one id.
    pub unique_id: u64,
    pub kill_requested: AtomicBool,
    pub stats: Mutex<ClientStats>,
    waker: Waker,
}

impl ClientEntry {
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            debug!("could not wake a stratum connection thread: {e}");
        }
    }

    fn request_kill(&self) {
        self.kill_requested.store(true, Ordering::Relaxed);
        self.wake();
    }
}

#[derive(Default)]
pub struct ClientsSummary {
    pub connections: usize,
    pub subscribed: usize,
    pub hashrate_hs: f64,
}

/// The stratum side of the gateway: the connected clients and the duplicate-share table.
pub struct State {
    clients: Mutex<HashMap<u64, Arc<ClientEntry>>>,
    seen_share_hashes: Mutex<SeenShareHashes>,
    next_unique_id: AtomicU64,
    /// The connections accepted whose thread has not ended, which `stratum.max_clients`
    /// bounds: counted at acceptance, before the thread registers the connection in
    /// `clients`, so a burst of connections accepted faster than their threads register
    /// cannot pass the bound.
    accepted: AtomicUsize,
    pub listening: AtomicBool,
}

/// One accepted connection counted in `State::accepted`, counted back when dropped: when the
/// connection's thread ends, or with the thread's closure when the thread cannot start.
struct AcceptedSlot(Arc<Gateway>);

impl AcceptedSlot {
    fn take(gateway: &Arc<Gateway>, max_clients: usize) -> Option<Self> {
        gateway
            .stratum
            .accepted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max_clients).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(gateway)))
    }
}

impl Drop for AcceptedSlot {
    fn drop(&mut self) {
        self.0.stratum.accepted.fetch_sub(1, Ordering::AcqRel);
    }
}

impl State {
    pub fn new(config: &Config) -> Self {
        let seen_share_hashes =
            SeenShareHashes::new(config.shares_in_stale_window(), config.stale_window());
        Self {
            clients: Mutex::new(HashMap::new()),
            seen_share_hashes: Mutex::new(seen_share_hashes),
            next_unique_id: AtomicU64::new(1),
            accepted: AtomicUsize::new(0),
            listening: AtomicBool::new(false),
        }
    }

    /// Wakes every connection to serve the job just installed.
    pub fn wake_all(&self) {
        for c in lock(&self.clients).values() {
            c.wake();
        }
    }

    pub fn summary(&self) -> ClientsSummary {
        let mut s = ClientsSummary::default();
        for c in lock(&self.clients).values() {
            let st = lock(&c.stats);
            s.connections += 1;
            s.subscribed += usize::from(st.subscribed());
            s.hashrate_hs += st.hashrate_hs().unwrap_or(0.0);
        }
        s
    }

    pub fn client_stats(&self) -> Vec<(u64, ClientStats)> {
        self.client_stats_where(|_| true)
    }

    /// Each client's id and a copy of its stats, for the clients `keep` accepts.
    pub fn client_stats_where(
        &self,
        keep: impl Fn(&ClientStats) -> bool,
    ) -> Vec<(u64, ClientStats)> {
        lock(&self.clients)
            .values()
            .filter_map(|c| {
                let st = lock(&c.stats);
                keep(&st).then(|| (c.unique_id, st.clone()))
            })
            .collect()
    }

    pub fn shutdown_all(&self) {
        info!("Disconnecting all stratum clients");
        for c in lock(&self.clients).values() {
            c.request_kill();
        }
    }

    pub fn kill_client(&self, unique_id: u64) -> bool {
        match lock(&self.clients).get(&unique_id) {
            Some(c) => {
                c.request_kill();
                true
            }
            None => false,
        }
    }
}

#[derive(Default)]
struct ConnectionRefusals {
    count: u64,
    last_logged_at: Option<Instant>,
}

impl ConnectionRefusals {
    fn note(&mut self) -> Option<u64> {
        self.count += 1;
        if self.last_logged_at.is_none_or(|t| t.elapsed() >= REFUSAL_LOG_INTERVAL) {
            self.last_logged_at = Some(Instant::now());
            Some(self.count)
        } else {
            None
        }
    }
}

/// Starts the listener on its own thread. A listener that cannot bind ends the process:
/// without it the gateway serves no miner.
pub fn spawn_listener(gateway: Arc<Gateway>) {
    ratum::thread::spawn("stratum-listener", move || {
        if let Err(e) = listen(gateway) {
            crate::fatal(format!("stratum listener: {e}"));
        }
    });
}

fn listen(gateway: Arc<Gateway>) -> io::Result<()> {
    let s = &gateway.config.stratum;
    let listener =
        ratum::net::bind_first(&s.listen_addr, s.listen_port, |a: &str| ratum::net::listen(a))
            .map_err(io::Error::other)?;
    info!("Stratum V1 Server Init complete: listening on {}", listener.local_addr()?);
    gateway.stratum.listening.store(true, Ordering::Relaxed);
    let mut pool_refusals = ConnectionRefusals::default();
    let mut share_refusals = ConnectionRefusals::default();
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                std::thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
        };
        if gateway.config.datum.pooled_mining_only && !gateway.pool.is_active() {
            if let Some(refused) = pool_refusals.note() {
                warn!(
                    "Refusing stratum connections while the pool is unreachable and datum.pooled_mining_only is set ({refused} refused)"
                );
            }
            continue;
        }
        if let Some(share) = gateway.over_network_share() {
            if let Some(refused) = share_refusals.note() {
                warn!(
                    "Refusing stratum connections: this gateway's miners measure {:.2}% of the network's hashrate, above the stratum.max_network_share_bps limit of {:.2}% ({refused} refused). Connected miners keep mining; point new ones at another gateway.",
                    share * 100.0,
                    gateway.config.max_network_share().unwrap_or_default() * 100.0
                );
            }
            continue;
        }
        let Some(slot) = AcceptedSlot::take(&gateway, s.max_clients) else {
            debug!("refusing a connection: {} clients connected", s.max_clients);
            continue;
        };
        let gateway = Arc::clone(&gateway);
        ratum::thread::spawn_or_warn("stratum-client", move || {
            let _slot = slot;
            match Connection::run(gateway, stream) {
                Ok(()) | Err(Disconnect::Io(_) | Disconnect::Killed | Disconnect::Idle(_)) => {}
                Err(e @ Disconnect::Protocol(_)) => info!("Stratum client connection closed: {e}"),
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::test_gateway;

    fn add_client(gateway: &Gateway, hashrate_hs: f64) -> mio::Poll {
        let poll = mio::Poll::new().unwrap();
        let waker = mio::Waker::new(poll.registry(), mio::Token(0)).unwrap();
        let unique_id = gateway.stratum.next_unique_id.fetch_add(1, Ordering::Relaxed);
        lock(&gateway.stratum.clients).insert(
            unique_id,
            Arc::new(ClientEntry {
                unique_id,
                kill_requested: AtomicBool::new(false),
                waker,
                stats: Mutex::new(ClientStats {
                    subscribed_at: Some(Instant::now()),
                    hashrate: Some((Instant::now(), hashrate_hs)),
                    ..Default::default()
                }),
            }),
        );
        poll
    }

    #[test]
    fn without_an_estimate_no_share_refuses_a_connection() {
        let gateway = test_gateway(|c| c.stratum.max_network_share_bps = 500);
        let _poll = add_client(&gateway, 1e21);
        assert!(gateway.network_share().is_none(), "no estimate has been read");
        assert!(gateway.over_network_share().is_none(), "so no connection is refused");
    }

    #[test]
    fn a_gateway_over_the_limit_refuses_and_one_under_it_does_not() {
        let gateway = test_gateway(|c| c.stratum.max_network_share_bps = 500);
        let _poll = add_client(&gateway, 6e16);
        gateway.mining_info.set_network_hashps(1e18);
        let share = gateway.over_network_share().expect("6% is over the 5% limit");
        assert!((share - 0.06).abs() < 1e-6, "share {share}");

        gateway.mining_info.set_network_hashps(2e18);
        assert!(gateway.over_network_share().is_none(), "3% is under the 5% limit");
        let share = gateway.network_share().expect("an estimate has been read");
        assert!((share - 0.03).abs() < 1e-6, "share {share}");
    }

    #[test]
    fn a_gateway_exactly_at_the_limit_is_not_refused() {
        let gateway = test_gateway(|c| c.stratum.max_network_share_bps = 500);
        let _poll = add_client(&gateway, 5e16);
        gateway.mining_info.set_network_hashps(1e18);
        let share = gateway.network_share().expect("an estimate has been read");
        let limit = gateway.config.max_network_share().expect("the configured limit");
        assert!((share - limit).abs() < 1e-6, "share {share}");
        assert!(
            gateway.over_network_share().is_none(),
            "a connection is refused above the limit, not at it"
        );
    }

    #[test]
    fn the_limit_is_the_configured_share_and_defaults_to_ten_percent() {
        let gateway = test_gateway(|_| {});
        assert_eq!(
            gateway.config.stratum.max_network_share_bps,
            crate::config::DEFAULT_MAX_NETWORK_SHARE_BPS
        );
        assert_eq!(gateway.config.max_network_share(), Some(0.1));

        for (bps, over) in [(500, true), (600, false), (1_000, false), (100, true)] {
            let gateway = test_gateway(|c| c.stratum.max_network_share_bps = bps);
            let _poll = add_client(&gateway, 6e16);
            gateway.mining_info.set_network_hashps(1e18);
            assert_eq!(
                gateway.over_network_share().is_some(),
                over,
                "6% of the network against a {bps} bps limit"
            );
        }
    }

    #[test]
    fn a_limit_of_zero_refuses_nothing() {
        let gateway = test_gateway(|c| c.stratum.max_network_share_bps = 0);
        let _poll = add_client(&gateway, 9e17);
        gateway.mining_info.set_network_hashps(1e18);
        assert_eq!(gateway.config.max_network_share(), None);
        let share = gateway.network_share().expect("the share is still reported");
        assert!((share - 0.9).abs() < 1e-6, "share {share}");
        assert!(gateway.over_network_share().is_none(), "but no connection is refused");
    }

    #[test]
    fn refusals_are_logged_once_per_interval() {
        let mut refusals = ConnectionRefusals::default();
        assert_eq!(refusals.note(), Some(1), "the first refusal is logged");
        assert_eq!(refusals.note(), None, "the second is counted and not logged");
        assert_eq!(refusals.note(), None);
        refusals.last_logged_at = Some(Instant::now() - REFUSAL_LOG_INTERVAL);
        assert_eq!(refusals.note(), Some(4), "the next interval logs the running total");
        assert_eq!(refusals.note(), None);
    }
}
