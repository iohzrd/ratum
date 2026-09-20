//! What the pool, the gateway and the test miner all build on: the Bitcoin primitives and the DATUM
//! wire formats the two sides are byte-coupled by, the sockets, HTTP server and node RPC client
//! they run on, and the units, clock and lock helpers below.

pub mod bitcoin;
pub mod datum;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod hashrate;
pub mod header;
pub mod http;
pub mod latest;
pub mod limits;
pub mod mining_info;
pub mod net;
pub mod nonce;
pub mod poll;
pub mod rand;
pub mod reader;
pub mod rpc;
pub(crate) mod siphash;
pub mod stratum_difficulty;
pub mod target;
pub mod thread;
pub mod username;

pub const SECS_PER_MINUTE: u64 = 60;
pub const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
pub const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;

pub const SATS_PER_BTC: f64 = 100_000_000.0;

/// An amount the node prints in BTC, in sats.
pub fn btc_to_sats(btc: f64) -> u64 {
    (btc * SATS_PER_BTC).round() as u64
}

pub fn sats_to_btc(sats: u64) -> f64 {
    sats as f64 / SATS_PER_BTC
}

pub(crate) const HASHES_PER_DIFFICULTY: f64 = (1u64 << 32) as f64;
pub const HASHES_PER_TERAHASH: f64 = 1e12;

pub const BASIS_POINTS_PER_UNIT: u64 = 10_000;

/// The version string a binary reports: its package version, which every crate inherits from
/// the workspace, and the commit its build script recorded. `env!` reads the environment of
/// the crate this expands in, so each binary reports its own build.
#[macro_export]
macro_rules! version {
    () => {
        concat!(env!("CARGO_PKG_VERSION"), " (", env!("RATUM_GIT_COMMIT"), ")")
    };
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        log::warn!("recovering a lock poisoned by a panicking thread");
        poisoned.into_inner()
    })
}
