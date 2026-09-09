use std::io::Cursor;
use tiny_http::{Header, Request, Response, Server};

pub type Reply = Response<Cursor<Vec<u8>>>;

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header is valid")
}

pub fn body(text: String, content_type: &str) -> Reply {
    Response::from_string(text)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-cache, no-store, must-revalidate"))
}

pub fn html(text: String) -> Reply {
    body(text, "text/html; charset=utf-8")
}

pub fn json(v: serde_json::Value) -> Reply {
    body(v.to_string(), "application/json")
}

pub fn plain(text: String) -> Reply {
    body(text, "text/plain; charset=utf-8")
}

pub fn noindex(reply: Reply) -> Reply {
    reply.with_header(header("X-Robots-Tag", "noindex"))
}

pub fn text(code: u16, text: &str) -> Reply {
    Response::from_string(text).with_status_code(code)
}

pub fn not_found() -> Reply {
    text(404, "not found")
}

pub fn method_not_allowed() -> Reply {
    text(405, "method not allowed")
}

pub fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

pub fn path_and_query(req: &Request) -> (String, String) {
    let url = req.url();
    match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.to_string(), String::new()),
    }
}

/// The `key=value` pairs of a query string or form body, still percent-encoded.
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

/// Decodes percent-escapes and `+`. A `%` not followed by two hex digits stands for
/// itself, and bytes that do not form UTF-8 become the replacement character.
pub fn url_decode(s: &str) -> String {
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

/// The addresses to try for a listener. An empty address means every interface, which is
/// two candidates: the dual-stack `[::]` first, then IPv4 alone for a host without IPv6.
fn bind_candidates(addr: &str, port: u16) -> Vec<String> {
    if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    }
}

/// Opens a listener on the first candidate address `open` accepts, reporting the last
/// candidate and its error when none is.
pub fn bind_first<T, E: std::fmt::Display>(
    addr: &str,
    port: u16,
    open: impl Fn(&str) -> Result<T, E>,
) -> Result<T, String> {
    let mut last = String::new();
    for candidate in bind_candidates(addr, port) {
        match open(&candidate) {
            Ok(listener) => return Ok(listener),
            Err(e) => last = format!("{candidate}: {e}"),
        }
    }
    Err(last)
}

pub fn bind(addr: &str, port: u16) -> Result<Server, String> {
    bind_first(addr, port, |candidate: &str| Server::http(candidate))
}

pub fn serve(name: &str, server: Server, handle: impl Fn(Request) + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            for req in server.incoming_requests() {
                handle(req);
            }
        })
        .expect("http thread");
}
