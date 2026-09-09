use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const SOCKET: Token = Token(0);
const WAKE: Token = Token(1);

const EVENT_CAPACITY: usize = 8;

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

    pub fn read_exact(
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
