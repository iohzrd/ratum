pub mod bitcoin;
pub mod config;
pub mod cursor;
pub mod datum;
pub mod fixtures;
pub mod header;
pub mod ledger;
pub mod nonce;
pub mod rpc;
pub mod target;

/// The lock, recovered if a panicking thread left it poisoned: the pool serves each
/// connection on its own thread, and a lock poisoned by one thread's panic must not stop the rest.
pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| {
        log::warn!("recovering a lock poisoned by a panicking thread");
        poisoned.into_inner()
    })
}
