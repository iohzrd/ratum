//! Named threads: one that ends the process when the thread cannot start, one that logs that and
//! continues, one that reports it to the caller, and one that runs a body now and then once per
//! interval.

use std::io;
use std::time::Duration;

pub fn spawn(name: &str, body: impl FnOnce() + Send + 'static) {
    if let Err(e) = try_spawn(name, body) {
        panic!("could not start the {name} thread: {e}");
    }
}

/// Starts the thread, or logs at warn level and returns when it cannot be started. For work
/// the caller carries on without: the thread that does not start is the whole loss.
pub fn spawn_or_warn(name: &str, body: impl FnOnce() + Send + 'static) {
    if let Err(e) = try_spawn(name, body) {
        log::warn!("could not start the {name} thread: {e}");
    }
}

pub fn try_spawn(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new().name(name.to_string()).spawn(body).map(drop)
}

/// Runs `body` once now, then once per `every`, on a named thread.
pub(crate) fn spawn_repeating(name: &str, every: Duration, body: impl Fn() + Send + 'static) {
    body();
    spawn(name, move || {
        loop {
            std::thread::sleep(every);
            body();
        }
    });
}
