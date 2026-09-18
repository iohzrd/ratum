//! Process resource limits: the open file limit, which bounds how many sockets a process can
//! hold, and which a new process inherits at a soft value (1024 on most Linux systems) far under
//! the hard value the system permits.

/// Raises the soft RLIMIT_NOFILE to the hard limit and returns the (soft, hard) pair in force
/// afterwards, as `getrlimit` reports it. Returns None when the limit cannot be read, and the
/// pair unchanged when it cannot be raised. Always None on a platform other than unix.
#[cfg(unix)]
pub fn raise_open_file_limit() -> Option<(u64, u64)> {
    // SAFETY: getrlimit and setrlimit read and write the one struct passed, which lives on
    // this stack frame for the length of each call.
    let read = || {
        let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) } == 0).then_some(l)
    };
    let current = read()?;
    if current.rlim_cur < current.rlim_max {
        let raised = libc::rlimit { rlim_cur: current.rlim_max, rlim_max: current.rlim_max };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            log::debug!(
                "could not raise the open file limit from {} to {}: {}",
                current.rlim_cur,
                current.rlim_max,
                std::io::Error::last_os_error()
            );
        }
    }
    let after = read()?;
    // `rlim_t` is u64 on Linux and macOS and i64 on FreeBSD, whose RLIM_INFINITY is i64::MAX.
    #[allow(clippy::unnecessary_cast)]
    Some((after.rlim_cur as u64, after.rlim_max as u64))
}

#[cfg(not(unix))]
pub fn raise_open_file_limit() -> Option<(u64, u64)> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_soft_limit_is_raised_to_the_hard_limit() {
        let (soft, hard) = raise_open_file_limit().expect("the limit is readable");
        assert!(soft <= hard);
        assert_eq!(raise_open_file_limit(), Some((soft, hard)), "a second call changes nothing");
    }
}
