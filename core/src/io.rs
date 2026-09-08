use crate::datum::framing::{self, Header};
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

pub fn read_frame(
    s: &mut impl Read,
    unmask: impl FnOnce([u8; framing::HEADER_LEN]) -> Header,
    started: Instant,
    deadline: Duration,
) -> io::Result<(Header, Vec<u8>)> {
    let head = read_exact_deadline(s, framing::HEADER_LEN, started, deadline)?;
    let header = unmask(head.try_into().expect("four bytes"));
    if header.cmd_len > framing::MAX_CMD_DATA_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds the protocol limit"));
    }
    let body = read_exact_deadline(s, header.cmd_len as usize, started, deadline)?;
    Ok((header, body))
}
