use std::io::{self, Read};
use std::time::{Duration, Instant};

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
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
