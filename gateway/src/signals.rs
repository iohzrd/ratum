//! The signals the C gateway acts on: SIGUSR1 is a block notification (what a
//! `bitcoind -blocknotify` script sends it), SIGHUP reopens the log file. Each handler sets
//! a flag; `main`'s watch loop reads `BLOCK`, the logger reads `logger::REOPEN`. Also the
//! open-file limit check the C stratum server makes at startup.

use std::sync::atomic::{AtomicBool, Ordering};

/// Set by SIGUSR1; cleared by the reader.
pub static BLOCK: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_: libc::c_int) {
    BLOCK.store(true, Ordering::Relaxed);
}

extern "C" fn on_hup(_: libc::c_int) {
    crate::logger::REOPEN.store(true, Ordering::Relaxed);
}

pub fn install() {
    // SAFETY: the handlers only store to atomics, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_hup as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
}

/// The process's open-file limits, (soft, hard), or `None` if they cannot be read.
pub fn open_file_limits() -> Option<(u64, u64)> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `lim` is a valid, writable rlimit.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    // `rlim_t` is u64 on Linux and differs elsewhere; the cast is for the other platforms.
    #[allow(clippy::unnecessary_cast)]
    let limits = (lim.rlim_cur as u64, lim.rlim_max as u64);
    (rc == 0).then_some(limits)
}
