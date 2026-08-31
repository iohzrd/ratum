//! SIGUSR1 as a block notification, what a `bitcoind -blocknotify` script sends the C
//! gateway (`kill -USR1 <pid>`). The handler writes one byte to a pipe (async-signal-safe);
//! a thread blocks on the read end and raises [`crate::template::Notify`], so the wake
//! happens immediately, not on the next poll. `/NOTIFY` on the API port stays the
//! transport-level equivalent. Unix only; the Windows build has no SIGUSR1.

use crate::template::Notify;
use log::{info, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

/// The write end of the self-pipe. `-1` until [`install`] creates it; the handler does
/// nothing before that. An `AtomicI32` because a signal handler may only touch
/// async-signal-safe state.
static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_usr1(_: libc::c_int) {
    let fd = PIPE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) on a valid fd is async-signal-safe; a full pipe drops the byte,
        // which collapses repeated signals into one wake, as intended.
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
}

/// Install the SIGUSR1 handler and start the thread that turns each signal into a block
/// notification on `notify`.
pub fn install(notify: Arc<Notify>) {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid two-element array for pipe(2).
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        warn!("could not create the SIGUSR1 pipe; SIGUSR1 is not handled");
        return;
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    PIPE_WRITE.store(write_fd, Ordering::Relaxed);
    // SAFETY: the handler only calls write(2) on an atomic-published fd.
    let installed = unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as libc::sighandler_t)
    };
    if installed == libc::SIG_ERR {
        warn!("could not install the SIGUSR1 handler; SIGUSR1 is not handled");
        return;
    }
    let spawned = std::thread::Builder::new().name("sigusr1".into()).spawn(move || {
        let mut buf = [0u8; 16];
        loop {
            // SAFETY: blocking read(2) on the pipe's read end; EINTR retries via the loop.
            let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                notify.raise();
            } else if n == 0 {
                return; // write end closed: process shutdown
            }
        }
    });
    match spawned {
        Ok(_) => info!("SIGUSR1 raises a block notification (blocknotify by signal)"),
        Err(e) => warn!("could not start the SIGUSR1 thread; SIGUSR1 is not handled: {e}"),
    }
}
