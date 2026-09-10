use std::io::Cursor;
use tiny_http::{Header, Request, Response, Server};

pub type Reply = Response<Cursor<Vec<u8>>>;

pub fn header(name: &str, value: &str) -> Header {
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

fn bind_candidates(addr: &str, port: u16) -> Vec<String> {
    if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    }
}

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
    crate::thread::spawn(name, move || {
        for req in server.incoming_requests() {
            handle(req);
        }
    });
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
        assert_eq!(
            pairs("a=1&&b=x+y"),
            [("a".to_string(), "1".to_string()), ("b".to_string(), "x y".to_string())]
        );
    }

    #[test]
    fn candidates() {
        assert_eq!(bind_candidates("", 80), ["[::]:80", "0.0.0.0:80"]);
        assert_eq!(bind_candidates("127.0.0.1", 80), ["127.0.0.1:80"]);
    }
}
