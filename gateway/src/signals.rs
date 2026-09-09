use crate::template::Notify;
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

pub fn install(notify: Arc<Notify>) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        warn!("could not create the SIGUSR1 pipe; SIGUSR1 is not handled");
        return;
    }
    let [read_fd, write_fd] = fds;
    PIPE_WRITE.store(write_fd, Ordering::Relaxed);
    let installed = unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as libc::sighandler_t)
    };
    if installed == libc::SIG_ERR {
        warn!("could not install the SIGUSR1 handler; SIGUSR1 is not handled");
        return;
    }
    let spawned = ratum::thread::try_spawn("sigusr1", move || {
        let mut buf = [0u8; 16];
        loop {
            let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                notify.raise();
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
