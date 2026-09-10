pub mod bitcoin;
pub mod cursor;
pub mod datum;
#[cfg(feature = "test-support")]
pub mod fixtures;
pub mod hashrate;
pub mod header;
pub mod http;
pub mod io;
pub mod nonce;
pub mod poll;
pub mod rand;
pub mod rpc;
pub mod target;
pub mod thread;

pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("RATUM_GIT_COMMIT"), ")");
pub const GIT_COMMIT: &str = env!("RATUM_GIT_COMMIT");

pub const SECS_PER_MINUTE: u64 = 60;
pub const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
pub const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;

pub const SATS_PER_BTC: f64 = 100_000_000.0;

pub const HASHES_PER_DIFFICULTY: f64 = (1u64 << 32) as f64;
pub const HASHES_PER_TERAHASH: f64 = 1e12;

pub const BASIS_POINTS_PER_UNIT: u64 = 10_000;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        log::warn!("recovering a lock poisoned by a panicking thread");
        poisoned.into_inner()
    })
}
