pub mod bitcoin;
pub mod cursor;
pub mod datum;
#[cfg(feature = "test-support")]
pub mod fixtures;
pub mod header;
pub mod http;
pub mod io;
pub mod nonce;
pub mod rpc;
pub mod target;
pub mod web;

/// The package version and the git commit the binary was built from, as
/// `"0.1.0 (1d6a05be7c2f)"`. The commit is `"unknown"` when the source was not built from a
/// git checkout, and carries a `-dirty` suffix when a tracked file differed from the commit.
/// It is the `--version` output and the `version` field of the stats snapshot.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("RATUM_GIT_COMMIT"), ")");
/// The git commit alone, as `build.rs` recorded it.
pub const GIT_COMMIT: &str = env!("RATUM_GIT_COMMIT");

/// Seconds in a minute, an hour and a day: the units the uptime and history displays split a
/// duration into.
pub const SECS_PER_MINUTE: u64 = 60;
pub const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
pub const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;

/// One hundred percent in basis points. The fee rates both ends carry
/// (`datum.gateway_fee_bps` in the gateway, `--fee-bps` in the pool) are a numerator over
/// this.
pub const BASIS_POINTS_PER_UNIT: u64 = 10_000;

/// The lock, recovered if a panicking thread left it poisoned: the pool serves each
/// connection on its own thread, and a lock poisoned by one thread's panic must not stop the rest.
pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        log::warn!("recovering a lock poisoned by a panicking thread");
        poisoned.into_inner()
    })
}
