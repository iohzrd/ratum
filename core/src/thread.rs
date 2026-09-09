//! Starting a named thread. Every thread this workspace starts carries a name, so that a
//! panic message, a debugger or `ps -L` says which work the thread is doing.

use std::io;

/// Starts a named thread the program cannot run without. A failure to start it panics,
/// which the panic hook turns into an exit.
pub fn spawn(name: &str, body: impl FnOnce() + Send + 'static) {
    if let Err(e) = try_spawn(name, body) {
        panic!("could not start the {name} thread: {e}");
    }
}

/// Starts a named thread and detaches it, leaving the caller to decide what a failure to
/// start it means.
pub fn try_spawn(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new().name(name.to_string()).spawn(body).map(drop)
}
