//! The `tiny_http` calls the pool's stats page and the gateway's API share: responses
//! with a content type and no caching, the request path and query, and a named thread that
//! serves a bound listener.

use std::io::Cursor;
use tiny_http::{Header, Request, Response, Server};

pub type Reply = Response<Cursor<Vec<u8>>>;

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header is valid")
}

/// A response of `content_type` that a browser does not cache.
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

/// A plain-text response with a status code.
pub fn text(code: u16, text: &str) -> Reply {
    Response::from_string(text).with_status_code(code)
}

pub fn not_found() -> Reply {
    text(404, "not found")
}

pub fn method_not_allowed() -> Reply {
    text(405, "method not allowed")
}

/// The request's path and query string, split at the first `?`.
pub fn path_and_query(req: &Request) -> (String, String) {
    let url = req.url();
    match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.to_string(), String::new()),
    }
}

/// `key`'s value in a `k=v&k=v` query or form body, percent-decoded, with `+` as a space.
pub fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| url_decode(v))
    })
}

pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The addresses to try for a listener: `addr:port`, or every address when `addr` is empty
/// (IPv6 and IPv4 together, then IPv4 alone if the dual-stack bind fails).
pub fn bind_candidates(addr: &str, port: u16) -> Vec<String> {
    if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    }
}

/// Bind the first of `bind_candidates` that binds; the last error otherwise.
pub fn bind(addr: &str, port: u16) -> Result<Server, String> {
    let mut last = String::new();
    for candidate in bind_candidates(addr, port) {
        match Server::http(&candidate) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{candidate}: {e}"),
        }
    }
    Err(last)
}

/// Serve `server`'s requests on a thread named `name` until the process ends.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_decode() {
        assert_eq!(param("a=1&b=x%20y+z", "b").as_deref(), Some("x y z"));
        assert_eq!(param("a=1&flag", "flag").as_deref(), Some(""));
        assert_eq!(param("a=1", "c"), None);
        assert_eq!(url_decode("%zz%4"), "%zz%4");
    }

    #[test]
    fn candidates() {
        assert_eq!(bind_candidates("", 80), ["[::]:80", "0.0.0.0:80"]);
        assert_eq!(bind_candidates("127.0.0.1", 80), ["127.0.0.1:80"]);
    }
}
