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
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}
