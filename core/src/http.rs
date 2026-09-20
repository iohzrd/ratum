//! The HTTP/1.1 server both status interfaces run on, with their replies and the query and form
//! parsing. One listener thread accepts connections and starts one thread per connection; each
//! connection carries one request and is closed after its reply. Every quantity a client
//! controls is bounded: the connections served at once, the bytes and count of the request line
//! and headers, the body, and the time the request and the reply may take.

use log::{debug, warn};
use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The connections one server serves at once. A connection accepted while this many are open
/// is closed without reading from it.
pub const MAX_CONNECTIONS: usize = 32;
/// The connections one server serves at once from one address (`net::limit_key`), so one
/// client cannot hold every slot. Loopback clients, a reverse proxy on the same host among
/// them, are counted only against `MAX_CONNECTIONS`.
pub const MAX_CONNECTIONS_PER_ADDRESS: usize = 8;
/// The read and write timeout of every socket operation.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// The time from accepting a connection to having read its whole request.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// The time writing a reply may take.
const REPLY_DEADLINE: Duration = Duration::from_secs(60);
/// The most bytes of the request line and headers, the blank line ending them included.
const MAX_HEAD_LEN: usize = 16 * 1024;
const MAX_HEADERS: usize = 100;
/// After the reply, the connection's input is read and discarded for up to this long, or up
/// to `MAX_DISCARDED_LEN` bytes, before the socket is closed. Closing a socket with unread
/// input sends a TCP reset, which can make the client discard the reply it has not yet read.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
const MAX_DISCARDED_LEN: usize = 64 * 1024;
const READ_CHUNK_LEN: usize = 4096;
/// The pause after an accept error other than a connection the peer aborted. Without it a
/// descriptor limit (EMFILE, ENFILE) would make the listener call accept() without pause.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const ACCEPT_WARNING_INTERVAL: Duration = Duration::from_secs(1);
const HEAD_END: &[u8] = b"\r\n\r\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Other(String),
}

impl Method {
    fn parse(s: &str) -> Self {
        match s {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            other => Self::Other(other.to_string()),
        }
    }
}

/// One request as read off a connection, its body read in full.
#[derive(Debug)]
pub struct Request {
    pub method: Method,
    /// The request target exactly as sent: the path and any query.
    pub url: String,
    /// Every header in the order sent, the value with surrounding whitespace removed.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct Header {
    name: String,
    value: String,
}

/// A reply: the status, headers and body, and what runs once it has been written and the
/// connection closed.
pub struct Reply {
    status: u16,
    headers: Vec<Header>,
    body: Vec<u8>,
    after_sent: Option<Box<dyn FnOnce() + Send>>,
}

impl Reply {
    fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, headers: Vec::new(), body, after_sent: None }
    }

    pub fn with_header(mut self, header: Header) -> Self {
        self.headers.push(header);
        self
    }

    pub fn with_status_code(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Runs `f` on the connection's thread after the reply has been written (or writing it
    /// failed) and the connection closed.
    pub fn after_sent(mut self, f: impl FnOnce() + Send + 'static) -> Self {
        self.after_sent = Some(Box::new(f));
        self
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The status line, headers and body as written to the socket; the body is left out of
    /// the reply to a HEAD request, whose Content-Length still gives its length.
    pub(crate) fn encode(&self, head_request: bool) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for h in &self.headers {
            out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", self.body.len()));
        let mut out = out.into_bytes();
        if !head_request {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// A header with any CR or LF removed from both parts, so no value can end the header early.
pub fn header(name: &str, value: &str) -> Header {
    let strip = |s: &str| -> String { s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect() };
    Header { name: strip(name), value: strip(value) }
}

pub fn body(text: String, content_type: &str) -> Reply {
    Reply::new(200, text.into_bytes())
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-cache, no-store, must-revalidate"))
}

pub fn html(text: String) -> Reply {
    body(text, "text/html; charset=utf-8")
}

pub fn json(v: serde_json::Value) -> Reply {
    body(v.to_string(), "application/json")
}

pub fn noindex(reply: Reply) -> Reply {
    reply.with_header(header("X-Robots-Tag", "noindex"))
}

pub fn text(code: u16, text: &str) -> Reply {
    Reply::new(code, text.as_bytes().to_vec())
        .with_header(header("Content-Type", "text/plain; charset=utf-8"))
}

pub fn not_found() -> Reply {
    text(404, "not found")
}

pub fn method_not_allowed() -> Reply {
    text(405, "method not allowed")
}

/// `status` with the body `{"error": message}`, for a listener whose every reply is JSON.
pub fn json_error(status: u16, message: &str) -> Reply {
    json(serde_json::json!({ "error": message })).with_status_code(status)
}

pub fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

pub fn path_and_query(req: &Request) -> (String, String) {
    match req.url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (req.url.clone(), String::new()),
    }
}

fn split_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
}

pub fn param(query: &str, key: &str) -> Option<String> {
    split_pairs(query).find(|(k, _)| *k == key).map(|(_, v)| url_decode(v))
}

pub fn pairs(query: &str) -> Vec<(String, String)> {
    split_pairs(query).map(|(k, v)| (url_decode(k), url_decode(v))).collect()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|pair| Some(hex_digit(pair[0])? << 4 | hex_digit(pair[1])?));
        match (escape, bytes[i]) {
            (Some(v), _) => {
                out.push(v);
                i += 2;
            }
            (None, b'+') => out.push(b' '),
            (None, b) => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A bound listener, not yet accepting; `serve` starts it.
pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn http(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self { listener: crate::net::listen(addr)? })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

pub fn bind(addr: &str, port: u16) -> Result<Server, String> {
    crate::net::bind_first(addr, port, |candidate: &str| Server::http(candidate))
}

/// Accepts connections on a thread named `name` and answers each request with `handle`, on
/// the connection's own thread. A request whose Content-Length exceeds `max_body` is answered
/// 413 without its body being read.
pub fn serve(
    name: &str,
    server: Server,
    max_body: usize,
    handle: impl Fn(Request) -> Reply + Send + Sync + 'static,
) {
    let handle: Arc<dyn Fn(Request) -> Reply + Send + Sync> = Arc::new(handle);
    let owned = name.to_string();
    crate::thread::spawn(name, move || accept_forever(&owned, &server.listener, max_body, &handle));
}

/// The connections a server has open, in all and per address.
#[derive(Default)]
struct OpenConnections {
    total: usize,
    per_address: HashMap<IpAddr, usize>,
}

/// Why a connection was not given a slot.
enum Full {
    Server,
    Address,
}

/// One of the `MAX_CONNECTIONS` a server serves at once, and of the
/// `MAX_CONNECTIONS_PER_ADDRESS` its address may hold, given back when dropped.
struct ConnectionSlot {
    open: Arc<Mutex<OpenConnections>>,
    address: Option<IpAddr>,
}

impl ConnectionSlot {
    fn take(open: &Arc<Mutex<OpenConnections>>, peer: IpAddr) -> Result<Self, Full> {
        let address = (!peer.to_canonical().is_loopback()).then(|| crate::net::limit_key(peer));
        let mut counts = crate::lock(open);
        if counts.total >= MAX_CONNECTIONS {
            return Err(Full::Server);
        }
        if let Some(address) = address {
            let from_address = counts.per_address.entry(address).or_default();
            if *from_address >= MAX_CONNECTIONS_PER_ADDRESS {
                return Err(Full::Address);
            }
            *from_address += 1;
        }
        counts.total += 1;
        Ok(Self { open: Arc::clone(open), address })
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut counts = crate::lock(&self.open);
        counts.total -= 1;
        if let Some(address) = self.address
            && let Some(from_address) = counts.per_address.get_mut(&address)
        {
            *from_address -= 1;
            if *from_address == 0 {
                counts.per_address.remove(&address);
            }
        }
    }
}

/// Logs at warn level at most once per `ACCEPT_WARNING_INTERVAL`, with the count of the
/// messages it did not log since the last one it did.
#[derive(Default)]
struct IntervalWarning {
    last_at: Option<Instant>,
    unlogged: u64,
}

impl IntervalWarning {
    fn warn(&mut self, message: std::fmt::Arguments<'_>) {
        let now = Instant::now();
        if self.last_at.is_some_and(|t| now.duration_since(t) < ACCEPT_WARNING_INTERVAL) {
            self.unlogged += 1;
            return;
        }
        match std::mem::take(&mut self.unlogged) {
            0 => warn!("{message}"),
            n => warn!("{message} ({n} more since the last report)"),
        }
        self.last_at = Some(now);
    }
}

fn accept_forever(
    name: &str,
    listener: &TcpListener,
    max_body: usize,
    handle: &Arc<dyn Fn(Request) -> Reply + Send + Sync>,
) {
    let open = Arc::new(Mutex::new(OpenConnections::default()));
    let mut accept_warning = IntervalWarning::default();
    let mut full_warning = IntervalWarning::default();
    let connection_thread = format!("{name}-conn");
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(e) => {
                let aborted = matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                );
                if !aborted {
                    accept_warning.warn(format_args!("{name}: accept failed: {e}"));
                    std::thread::sleep(ACCEPT_RETRY_DELAY);
                }
                continue;
            }
        };
        let slot = match ConnectionSlot::take(&open, peer.ip()) {
            Ok(slot) => slot,
            Err(full) => {
                match full {
                    Full::Server => full_warning.warn(format_args!(
                        "{name}: {MAX_CONNECTIONS} connections open; closed the connection from \
                         {peer}"
                    )),
                    Full::Address => full_warning.warn(format_args!(
                        "{name}: {MAX_CONNECTIONS_PER_ADDRESS} connections open from the address \
                         of {peer}; closed its connection"
                    )),
                }
                drop(stream);
                continue;
            }
        };
        let handle = Arc::clone(handle);
        let thread_name = name.to_string();
        let started = crate::thread::try_spawn(&connection_thread, move || {
            let _slot = slot;
            serve_connection(&thread_name, stream, peer, max_body, &*handle);
        });
        if let Err(e) = started {
            accept_warning.warn(format_args!(
                "{name}: could not start a thread for the connection from {peer}: {e}"
            ));
        }
    }
}

fn serve_connection(
    name: &str,
    mut stream: TcpStream,
    peer: SocketAddr,
    max_body: usize,
    handle: &(dyn Fn(Request) -> Reply + Send + Sync),
) {
    let (reply, head_request) = match read_request(&mut stream, peer, max_body) {
        Ok(req) => {
            let head_request = req.method == Method::Head;
            (handle(req), head_request)
        }
        Err(Refusal::Closed) => return,
        Err(Refusal::Status(code, why)) => {
            debug!("{name}: refused a request from {peer}: {code} {why}");
            (text(code, why), false)
        }
    };
    let deadline = Instant::now() + REPLY_DEADLINE;
    if let Err(e) = write_all_by(&mut stream, &reply.encode(head_request), deadline) {
        debug!("{name}: could not send the reply to {peer}: {e}");
    }
    close(stream);
    if let Some(after_sent) = reply.after_sent {
        after_sent();
    }
}

/// Why no request was read: the connection closed or failed, which is answered with nothing,
/// or the request broke a rule, which is answered with the status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Closed,
    Status(u16, &'static str),
}

/// Reads onto the end of `buf` until it holds at most `limit` bytes, reading at most
/// `READ_CHUNK_LEN` and waiting no later than `deadline`.
fn read_some(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limit: usize,
    deadline: Instant,
) -> Result<(), Refusal> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Refusal::Status(408, "the request was not received in time"));
    }
    stream.set_read_timeout(Some(left.min(IO_TIMEOUT))).map_err(|_| Refusal::Closed)?;
    let mut chunk = [0u8; READ_CHUNK_LEN];
    let want = limit.saturating_sub(buf.len()).min(READ_CHUNK_LEN);
    match stream.read(&mut chunk[..want]) {
        Ok(0) => Err(Refusal::Closed),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            Err(Refusal::Status(408, "the request was not received in time"))
        }
        Err(_) => Err(Refusal::Closed),
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|at| from + at)
}

pub(crate) fn read_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    max_body: usize,
) -> Result<Request, Refusal> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::with_capacity(READ_CHUNK_LEN);
    let head_len = loop {
        let searched_to = buf.len().saturating_sub(HEAD_END.len() - 1);
        if buf.len() >= MAX_HEAD_LEN {
            return Err(Refusal::Status(431, "the request line and headers are too long"));
        }
        read_some(stream, &mut buf, MAX_HEAD_LEN, deadline)?;
        if let Some(at) = find(&buf, HEAD_END, searched_to) {
            break at + HEAD_END.len();
        }
    };
    let head = parse_head(&buf[..head_len - HEAD_END.len()])?;
    let length = content_length(&head.headers, max_body)?;
    let mut body = buf.split_off(head_len);
    body.truncate(length);
    if body.len() < length {
        let expects_continue = head.headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("Expect") && v.eq_ignore_ascii_case("100-continue")
        });
        if expects_continue {
            write_all_by(stream, b"HTTP/1.1 100 Continue\r\n\r\n", deadline)
                .map_err(|_| Refusal::Closed)?;
        }
        body.reserve_exact(length - body.len());
        while body.len() < length {
            read_some(stream, &mut body, length, deadline)?;
        }
    }
    Ok(Request { method: head.method, url: head.url, headers: head.headers, body, peer })
}

struct Head {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
}

fn parse_head(head: &[u8]) -> Result<Head, Refusal> {
    const MALFORMED: Refusal = Refusal::Status(400, "malformed request");
    let head = std::str::from_utf8(head).map_err(|_| MALFORMED)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(MALFORMED)?;
    let parts: Vec<&str> = request_line.split(' ').collect();
    let [method, url, version] = parts[..] else { return Err(MALFORMED) };
    if method.is_empty() || url.is_empty() {
        return Err(MALFORMED);
    }
    if !version.starts_with("HTTP/") {
        return Err(MALFORMED);
    }
    if !version.starts_with("HTTP/1.") {
        return Err(Refusal::Status(505, "only HTTP/1.0 and HTTP/1.1 are served"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() == MAX_HEADERS {
            return Err(Refusal::Status(431, "too many headers"));
        }
        let (name, value) = line.split_once(':').ok_or(MALFORMED)?;
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(MALFORMED);
        }
        headers.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    Ok(Head { method: Method::parse(method), url: url.to_string(), headers })
}

/// The body length the headers give: 0 without a Content-Length. A Transfer-Encoding is
/// refused, since no caller takes a body it does not know the length of in advance.
fn content_length(headers: &[(String, String)], max_body: usize) -> Result<usize, Refusal> {
    if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("Transfer-Encoding")) {
        return Err(Refusal::Status(
            501,
            "Transfer-Encoding is not supported; send Content-Length",
        ));
    }
    let mut length = None;
    for (_, value) in headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("Content-Length")) {
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Refusal::Status(400, "malformed Content-Length"));
        }
        // A value too long for u64 is over any limit as well.
        let parsed = value.parse::<u64>().unwrap_or(u64::MAX);
        if length.is_some_and(|l| l != parsed) {
            return Err(Refusal::Status(400, "conflicting Content-Length headers"));
        }
        length = Some(parsed);
    }
    let length = length.unwrap_or(0);
    if length > max_body as u64 {
        return Err(Refusal::Status(413, "the request body is too large"));
    }
    Ok(length as usize)
}

fn write_all_by(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    while !data.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(left.min(IO_TIMEOUT)))?;
        match stream.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Ends the connection: shuts down the sending half, so the client reads the reply to its
/// end, then reads and discards what the client still sends for up to `CLOSE_WAIT` or
/// `MAX_DISCARDED_LEN` bytes before the socket is dropped.
fn close(mut stream: TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let deadline = Instant::now() + CLOSE_WAIT;
    let mut chunk = [0u8; READ_CHUNK_LEN];
    let mut discarded = 0;
    while discarded < MAX_DISCARDED_LEN {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => discarded += n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_address_holds_at_most_its_share_of_the_slots_and_loopback_only_the_total() {
        let open = Arc::new(Mutex::new(OpenConnections::default()));
        let remote: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let held: Vec<ConnectionSlot> = (0..MAX_CONNECTIONS_PER_ADDRESS)
            .map(|_| ConnectionSlot::take(&open, remote).ok().unwrap())
            .collect();
        assert!(matches!(ConnectionSlot::take(&open, remote), Err(Full::Address)));
        let from_other = ConnectionSlot::take(&open, other).ok().unwrap();
        let local: Vec<ConnectionSlot> = (MAX_CONNECTIONS_PER_ADDRESS + 1..MAX_CONNECTIONS)
            .map(|_| ConnectionSlot::take(&open, loopback).ok().unwrap())
            .collect();
        assert!(matches!(ConnectionSlot::take(&open, loopback), Err(Full::Server)));
        drop(local);
        drop(from_other);
        drop(held);
        let counts = crate::lock(&open);
        assert_eq!(counts.total, 0);
        assert!(counts.per_address.is_empty(), "every slot is given back");
    }

    #[test]
    fn params_decode() {
        assert_eq!(param("a=1&b=x%20y+z", "b").as_deref(), Some("x y z"));
        assert_eq!(param("a=1&flag", "flag").as_deref(), Some(""));
        assert_eq!(param("a=1", "c"), None);
        assert_eq!(url_decode("%zz%4"), "%zz%4");
        assert_eq!(
            pairs("a=1&&b=x+y"),
            [("a".to_string(), "1".to_string()), ("b".to_string(), "x y".to_string())]
        );
    }

    const MAX_BODY: usize = 1024;
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

    /// A server on a free loopback port whose handler answers with the method, target and
    /// body length it was given.
    fn start() -> SocketAddr {
        let server = Server::http("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        serve("http-test", server, MAX_BODY, |req: Request| {
            let summary = format!("{:?} {} {}", req.method, req.url, req.body.len());
            text(200, &summary).with_header(header("X-Peer-Loopback", "1"))
        });
        addr
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
        s.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
        s
    }

    /// Sends `request` and reads until the server closes the connection; an error reading is
    /// returned as what was read before it.
    fn exchange(addr: SocketAddr, request: &[u8]) -> String {
        let mut s = connect(addr);
        s.write_all(request).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn get(addr: SocketAddr) -> String {
        exchange(addr, b"GET /stats.json?x=1 HTTP/1.1\r\nHost: test\r\n\r\n")
    }

    fn assert_status(reply: &str, status: &str) {
        assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply:?}");
    }

    #[test]
    fn a_get_is_answered_and_the_connection_closed() {
        let addr = start();
        let reply = get(addr);
        assert_status(&reply, "200 OK");
        assert!(reply.contains("\r\nConnection: close\r\n"), "{reply}");
        assert!(reply.contains("\r\nX-Peer-Loopback: 1\r\n"), "{reply}");
        assert!(reply.ends_with("\r\n\r\nGet /stats.json?x=1 0"), "{reply}");
    }

    #[test]
    fn a_body_within_the_limit_is_read_whole() {
        let addr = start();
        let body = "a=1&b=2";
        let request = format!("POST /cmd HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let reply = exchange(addr, request.as_bytes());
        assert_status(&reply, "200 OK");
        assert!(reply.ends_with("Post /cmd 7"), "{reply}");
    }

    #[test]
    fn a_body_over_the_limit_is_refused_unread_and_the_server_keeps_answering() {
        let addr = start();
        let huge = exchange(addr, b"POST / HTTP/1.1\r\nContent-Length: 70368744177664\r\n\r\n");
        assert_status(&huge, "413");
        let over_u64 =
            exchange(addr, b"POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n");
        assert_status(&over_u64, "413");
        let one_over = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_status(&exchange(addr, one_over.as_bytes()), "413");
        assert_status(&get(addr), "200 OK");
    }

    #[test]
    fn a_chunked_body_and_malformed_requests_are_refused() {
        let addr = start();
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_status(&exchange(addr, chunked), "501");
        assert_status(&exchange(addr, b"GET /\r\n\r\n"), "400");
        assert_status(&exchange(addr, b"GET / HTTP/2.0\r\n\r\n"), "505");
        assert_status(&exchange(addr, b"GET / HTTP/1.1\r\nno colon\r\n\r\n"), "400");
        let conflicting = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
        assert_status(&exchange(addr, conflicting), "400");
    }

    #[test]
    fn a_stalled_client_does_not_hold_up_another() {
        let addr = start();
        let mut stalled = connect(addr);
        stalled.write_all(b"GET / HTTP/1.1\r\nHost: test\r\n").unwrap();
        let mut stalled_body = connect(addr);
        stalled_body.write_all(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nab").unwrap();
        let started = Instant::now();
        assert_status(&get(addr), "200 OK");
        assert!(started.elapsed() < REQUEST_DEADLINE, "answered before the stalled deadline");
        drop((stalled, stalled_body));
    }

    #[test]
    fn an_over_long_head_is_refused() {
        let addr = start();
        let long = format!("GET / HTTP/1.1\r\nX-Long: {}\r\n\r\n", "a".repeat(20_000));
        assert_status(&exchange(addr, long.as_bytes()), "431");
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: v\r\n")).collect();
        let many = format!("GET / HTTP/1.1\r\n{many}\r\n");
        assert_status(&exchange(addr, many.as_bytes()), "431");
        assert_status(&get(addr), "200 OK");
    }

    #[test]
    fn connections_over_the_limit_are_closed_and_served_again_once_others_close() {
        let addr = start();
        let held: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let mut s = connect(addr);
                s.write_all(b"GET / HTTP/1.1\r\n").unwrap();
                s
            })
            .collect();
        // The listener accepts in order, so this one is accepted after every held connection
        // has taken a slot, and none of those ends before its request deadline.
        let refused = exchange(addr, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!refused.starts_with("HTTP/"), "a connection over the limit is closed: {refused}");
        drop(held);
        let started = Instant::now();
        loop {
            let reply = get(addr);
            if reply.starts_with("HTTP/1.1 200") {
                break;
            }
            assert!(started.elapsed() < CLIENT_TIMEOUT, "never answered again: {reply:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_head_reply_carries_the_length_but_not_the_body() {
        let reply = text(200, "abc");
        let encoded = String::from_utf8(reply.encode(true)).unwrap();
        assert!(encoded.ends_with("Content-Length: 3\r\nConnection: close\r\n\r\n"), "{encoded}");
        assert!(String::from_utf8(reply.encode(false)).unwrap().ends_with("\r\n\r\nabc"));
    }

    #[test]
    fn a_header_cannot_carry_a_line_break() {
        let h = header("Location", "/\r\nSet-Cookie: x=1");
        assert_eq!(h.value, "/Set-Cookie: x=1");
    }
}
