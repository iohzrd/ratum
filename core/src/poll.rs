//! A non-blocking TCP socket with its own `mio::Poll`, which the pool's gateway
//! connections, the gateway's pool session and the gateway's stratum connections all serve
//! one per thread.
//!
//! Each of those threads blocks in [`PolledSocket::wait`] between frames, on the socket and
//! on a [`Waker`] another thread calls when there is something to send (a published job, a
//! queued share, a new tip). The registration is edge triggered, so read readiness is
//! recorded when the poll reports it and cleared when a read returns `WouldBlock`; a caller
//! reads only while [`PolledSocket::readable`] holds and waits otherwise.

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// The socket's token in its own `Poll`.
pub const SOCKET: Token = Token(0);
/// The token of the `Waker` [`PolledSocket::waker`] builds.
pub const WAKE: Token = Token(1);

/// The events one poll call collects: the socket and the waker are the only two sources.
const EVENT_CAPACITY: usize = 8;

pub struct PolledSocket {
    stream: TcpStream,
    poll: Poll,
    events: Events,
    /// Set when the poll reports the socket readable, cleared when a read returns
    /// `WouldBlock`: the registration is edge triggered, so readiness holds until then.
    readable: bool,
}

impl PolledSocket {
    /// Take over a connected socket: make it non-blocking and register it for read and write
    /// readiness. Both directions return `WouldBlock` from here on rather than blocking.
    pub fn new(stream: std::net::TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let mut stream = TcpStream::from_std(stream);
        let poll = Poll::new()?;
        poll.registry().register(&mut stream, SOCKET, Interest::READABLE | Interest::WRITABLE)?;
        Ok(PolledSocket {
            stream,
            poll,
            events: Events::with_capacity(EVENT_CAPACITY),
            readable: false,
        })
    }

    /// A waker that returns this socket's thread from [`wait`](Self::wait). A waker event
    /// records nothing: the caller re-reads the state it was woken for each time around its
    /// loop.
    pub fn waker(&self) -> io::Result<Waker> {
        Waker::new(self.poll.registry(), WAKE)
    }

    /// Whether a read may find bytes. False after a read returned `WouldBlock`, until the
    /// poll reports readiness again.
    pub fn readable(&self) -> bool {
        self.readable
    }

    /// Block until an event or `timeout`, recording read readiness. `Interrupted` returns
    /// with no event, as a timeout does.
    pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self.poll.poll(&mut self.events, timeout) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
            Err(e) => return Err(e),
        }
        for ev in self.events.iter() {
            // A closed or errored socket is read so that `read` reports it.
            if ev.token() == SOCKET && (ev.is_readable() || ev.is_read_closed() || ev.is_error()) {
                self.readable = true;
            }
        }
        Ok(())
    }

    /// Read what has arrived: `Some(n)` bytes, `Some(0)` at end of file, or `None` when
    /// nothing can be read without waiting, which clears [`readable`](Self::readable).
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

    /// Write every byte, waiting for write readiness while the socket buffer is full. Fails
    /// with `TimedOut` once `timeout` has passed. Read readiness seen while waiting is kept
    /// for the next read.
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
    use std::net::{TcpListener, TcpStream as StdStream};

    /// A connected pair on the loopback interface: the polled end and the plain other end.
    fn pair() -> (PolledSocket, StdStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = StdStream::connect(addr).expect("connect");
        let (served, _) = listener.accept().expect("accept");
        (PolledSocket::new(served).expect("polled"), client)
    }

    #[test]
    fn a_read_before_anything_arrives_reports_nothing_and_clears_readiness() {
        let (mut socket, mut peer) = pair();
        let mut buf = [0u8; 8];
        assert_eq!(socket.read(&mut buf).unwrap(), None);
        assert!(!socket.readable());

        peer.write_all(b"abc").unwrap();
        socket.wait(Some(Duration::from_secs(5))).unwrap();
        assert!(socket.readable(), "the poll reported the arriving bytes");
        assert_eq!(socket.read(&mut buf).unwrap(), Some(3));
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn a_closed_peer_reads_as_end_of_file() {
        let (mut socket, peer) = pair();
        drop(peer);
        socket.wait(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(socket.read(&mut [0u8; 4]).unwrap(), Some(0));
    }

    #[test]
    fn a_waker_returns_the_thread_from_a_wait_with_no_bytes_to_read() {
        let (mut socket, _peer) = pair();
        let waker = socket.waker().unwrap();
        std::thread::spawn(move || waker.wake());
        socket.wait(None).expect("the waker ends the wait");
        assert!(!socket.readable(), "a waker event is not read readiness");
    }

    #[test]
    fn write_all_delivers_the_whole_buffer() {
        let (mut socket, mut peer) = pair();
        let sent = vec![0x5au8; 4096];
        socket.write_all(&sent, Duration::from_secs(5)).unwrap();
        let mut got = vec![0u8; sent.len()];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, sent);
    }

    #[test]
    fn a_full_socket_buffer_times_out_rather_than_blocking() {
        let (mut socket, peer) = pair();
        // The peer never reads, so the buffers fill and the write cannot finish.
        let e = socket
            .write_all(&vec![0u8; 64 << 20], Duration::from_millis(50))
            .expect_err("a peer that never reads cannot take 64 MiB");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        drop(peer);
    }
}
