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

pub fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| url_decode(v))
    })
}

pub fn pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
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

pub fn bind_candidates(addr: &str, port: u16) -> Vec<String> {
    if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    }
}

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
