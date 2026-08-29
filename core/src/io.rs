//! Reads bounded by a wall-clock deadline, for sockets whose read timeout is a short poll:
//! `read_exact` restarts its timeout on every byte, so a peer sending one byte per interval
//! could hold a connection open indefinitely.

use crate::datum::framing::{self, Header};
use std::io::{self, Read};
use std::time::{Duration, Instant};

/// Read exactly `n` bytes, returning `Err(TimedOut)` once `started.elapsed()` exceeds
/// `deadline`. The caller passes one `started` shared across several reads to bound them
/// together. A read timeout (`WouldBlock` or `TimedOut`) and `Interrupted` are retried.
pub fn read_exact_deadline(
    s: &mut impl Read,
    n: usize,
    started: Instant,
    deadline: Duration,
) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut got = 0usize;
    while got < n {
        if started.elapsed() > deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read exceeded its deadline"));
        }
        match s.read(&mut buf[got..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed")),
            Ok(k) => got += k,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

/// Read one DATUM frame: the four masked header bytes, unmasked by `unmask`, then the body
/// the header's `cmd_len` names, refused with `InvalidData` over the protocol's
/// `MAX_CMD_DATA_SIZE`. `started` and `deadline` bound both reads together.
pub fn read_frame(
    s: &mut impl Read,
    unmask: impl FnOnce([u8; 4]) -> Header,
    started: Instant,
    deadline: Duration,
) -> io::Result<(Header, Vec<u8>)> {
    let head = read_exact_deadline(s, 4, started, deadline)?;
    let header = unmask(head.try_into().expect("four bytes"));
    if header.cmd_len > framing::MAX_CMD_DATA_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds the protocol limit"));
    }
    let body = read_exact_deadline(s, header.cmd_len as usize, started, deadline)?;
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that returns one byte per call and a timeout in between.
    struct Trickle(Vec<u8>, bool);
    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.1 = !self.1;
            if self.1 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if self.0.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0.remove(0);
            Ok(1)
        }
    }

    #[test]
    fn accumulates_across_timeouts_and_reports_eof() {
        let mut t = Trickle(vec![1, 2, 3], false);
        let got = read_exact_deadline(&mut t, 3, Instant::now(), Duration::from_secs(1)).unwrap();
        assert_eq!(got, [1, 2, 3]);
        let e = read_exact_deadline(&mut t, 1, Instant::now(), Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_passed_deadline_times_out() {
        let mut t = Trickle(vec![1, 2, 3], false);
        let started = Instant::now() - Duration::from_secs(2);
        let e = read_exact_deadline(&mut t, 3, started, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_frame_over_the_limit_is_refused() {
        let header =
            Header { cmd_len: framing::MAX_CMD_DATA_SIZE + 1, ..Header::from_bytes([0; 4]) };
        let mut t = Trickle(vec![0, 0, 0, 0], false);
        let e = read_frame(&mut t, |_| header, Instant::now(), Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
