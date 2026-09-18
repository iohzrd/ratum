//! A non-blocking socket registered with a poller: reads and writes that respect an idle limit and
//! a deadline rather than blocking, and a waker another thread raises to interrupt the wait.

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const SOCKET: Token = Token(0);
const WAKE: Token = Token(1);

const EVENT_CAPACITY: usize = 8;

pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct PolledSocket {
    stream: TcpStream,
    poll: Poll,
    events: Events,
    readable: bool,
}

impl PolledSocket {
    pub fn new(stream: std::net::TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let mut stream = TcpStream::from_std(stream);
        let poll = Poll::new()?;
        poll.registry().register(&mut stream, SOCKET, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self { stream, poll, events: Events::with_capacity(EVENT_CAPACITY), readable: false })
    }

    pub fn waker(&self) -> io::Result<Waker> {
        Waker::new(self.poll.registry(), WAKE)
    }

    pub fn readable(&self) -> bool {
        self.readable
    }

    pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self.poll.poll(&mut self.events, timeout) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
            Err(e) => return Err(e),
        }
        for ev in &self.events {
            if ev.token() == SOCKET && (ev.is_readable() || ev.is_read_closed() || ev.is_error()) {
                self.readable = true;
            }
        }
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.stream.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.readable = false;
                Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn read_exact(
        &mut self,
        buf: &mut [u8],
        idle: Duration,
        total: Duration,
    ) -> io::Result<()> {
        let started = Instant::now();
        let mut idle_since = started;
        let mut got = 0usize;
        while got < buf.len() {
            if started.elapsed() >= total {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read exceeded its deadline"));
            }
            if !self.readable {
                let left = idle.checked_sub(idle_since.elapsed()).filter(|d| !d.is_zero());
                let Some(left) = left else {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "read stalled"));
                };
                self.wait(Some(left.min(total.saturating_sub(started.elapsed()))))?;
                continue;
            }
            match self.read(&mut buf[got..])? {
                Some(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed mid-read",
                    ));
                }
                Some(n) => {
                    got += n;
                    idle_since = Instant::now();
                }
                None => {}
            }
        }
        Ok(())
    }

    pub(crate) fn read_vec(
        &mut self,
        n: usize,
        idle: Duration,
        total: Duration,
    ) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.read_exact(&mut buf, idle, total)?;
        Ok(buf)
    }

    pub fn write_all(&mut self, data: &[u8], timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut rest = data;
        while !rest.is_empty() {
            match self.stream.write(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    self.wait(Some(left))?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn pair() -> (TcpStream, PolledSocket) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (served, _) = listener.accept().unwrap();
        (client, PolledSocket::new(served).unwrap())
    }

    #[test]
    fn read_exact_times_out_on_a_slow_peer() {
        let (mut client, mut socket) = pair();
        let sender = std::thread::spawn(move || {
            client.write_all(&[0x01]).unwrap();
            std::thread::sleep(Duration::from_millis(600));
            drop(client);
        });
        let started = Instant::now();
        let mut buf = [0u8; 4];
        let limit = Duration::from_millis(200);
        let e = socket.read_exact(&mut buf, limit, limit).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2), "it returns near the deadline");
        sender.join().unwrap();
    }

    #[test]
    fn read_exact_reads_all_bytes_when_they_arrive() {
        let (mut client, mut socket) = pair();
        let sender = std::thread::spawn(move || {
            client.write_all(&[1, 2]).unwrap();
            std::thread::sleep(Duration::from_millis(60));
            client.write_all(&[3, 4, 5, 6]).unwrap();
        });
        let mut buf = [0u8; 4];
        let limit = Duration::from_secs(5);
        socket.read_exact(&mut buf, limit, limit).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
        sender.join().unwrap();
    }

    #[test]
    fn read_exact_stalls_on_the_idle_limit_before_the_total() {
        let (mut client, mut socket) = pair();
        let sender = std::thread::spawn(move || {
            client.write_all(&[0x01]).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            drop(client);
        });
        let started = Instant::now();
        let mut buf = [0u8; 4];
        let e = socket
            .read_exact(&mut buf, Duration::from_millis(100), Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1), "the idle limit ended the read");
        sender.join().unwrap();
    }

    #[test]
    fn a_peer_that_closes_mid_read_is_unexpected_eof() {
        let (client, mut socket) = pair();
        drop(client);
        let mut buf = [0u8; 4];
        let limit = Duration::from_secs(1);
        let e = socket.read_exact(&mut buf, limit, limit).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }
}
