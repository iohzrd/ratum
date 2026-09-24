//! SIGUSR1 as a block notification, as the C gateway takes it (`blocknotify=kill -USR1 <pid>`), and
//! SIGHUP as a request to open the log file again. The SIGUSR1 handler writes one byte to a pipe and
//! a thread reading that pipe raises the template waker; the SIGHUP handler stores to an atomic the
//! logger reads. Neither handler does more than that write.

use crate::gateway::Gateway;
use log::{info, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_usr1(_: libc::c_int) {
    let fd = PIPE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
}

extern "C" fn on_hup(_: libc::c_int) {
    crate::logger::request_reopen();
}

fn handler(signum: libc::c_int, handler: extern "C" fn(libc::c_int)) -> bool {
    let installed = unsafe {
        libc::signal(signum, handler as extern "C" fn(libc::c_int) as libc::sighandler_t)
    };
    installed != libc::SIG_ERR
}

pub fn install(gateway: Arc<Gateway>) {
    install_hup();
    install_usr1(gateway);
}

/// SIGHUP reopens the log file, for a rotation performed outside the process. Installing the
/// handler also keeps the default action, which ends the process, from running.
fn install_hup() {
    if handler(libc::SIGHUP, on_hup) {
        info!("SIGHUP reopens the log file");
    } else {
        warn!("could not install the SIGHUP handler; SIGHUP is not handled");
    }
}

fn install_usr1(gateway: Arc<Gateway>) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        warn!("could not create the SIGUSR1 pipe; SIGUSR1 is not handled");
        return;
    }
    let [read_fd, write_fd] = fds;
    // Close-on-exec, so the restart a settings save performs (an exec) does not carry both
    // ends into the new process, which opens a pipe of its own.
    for fd in fds {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    PIPE_WRITE.store(write_fd, Ordering::Relaxed);
    if !handler(libc::SIGUSR1, on_usr1) {
        warn!("could not install the SIGUSR1 handler; SIGUSR1 is not handled");
        return;
    }
    let spawned = ratum::thread::try_spawn("sigusr1", move || {
        let mut buf = [0u8; 16];
        loop {
            let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                gateway.template_waker.raise();
            } else if n == 0 {
                return;
            }
        }
    });
    match spawned {
        Ok(()) => info!("SIGUSR1 raises a block notification (blocknotify by signal)"),
        Err(e) => warn!("could not start the SIGUSR1 thread; SIGUSR1 is not handled: {e}"),
    }
}
