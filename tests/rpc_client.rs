//! `ratum::rpc::Client` against a server that returns exactly what a test specifies,
//! including the responses a real node gives on an error.

mod support;

use ratum::rpc::{Chain, Client, Error};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::lock;

/// One request as the server received it.
#[derive(Clone, Debug)]
struct Received {
    head: String,
    body: String,
}

struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Received>>>,
}

impl Stub {
    /// Serve `replies` in order, repeating the last one, as raw HTTP responses.
    fn serving(replies: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);

        std::thread::spawn(move || {
            for (n, conn) in listener.incoming().enumerate() {
                let Ok(mut conn) = conn else { return };
                let reply = replies.get(n).or_else(|| replies.last()).cloned();
                let Some(reply) = reply else { return };
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || {
                    if let Ok(received) = read_request(&mut conn) {
                        lock(&sink).push(received);
                    }
                    let _ = conn.write_all(reply.as_bytes());
                    let _ = conn.flush();
                });
            }
        });
        Stub { addr, seen }
    }

    fn client(&self) -> Client {
        Client::new(&format!("http://{}", self.addr), "rpcuser", "rpcpass").expect("client")
    }

    fn requests(&self) -> Vec<Received> {
        lock(&self.seen).clone()
    }
}

fn read_request(conn: &mut TcpStream) -> std::io::Result<Received> {
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut head = String::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    Ok(Received { head, body: String::from_utf8_lossy(&body).into_owned() })
}

fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn ok(result: &str) -> String {
    http("200 OK", &format!(r#"{{"result":{result},"error":null,"id":"ratum"}}"#))
}

#[test]
fn a_call_carries_basic_auth_and_the_json_rpc_envelope() {
    let stub = Stub::serving(vec![ok("42")]);
    let value = stub.client().call("getblockcount", serde_json::json!([])).expect("call");
    assert_eq!(value, serde_json::json!(42));

    let request = &stub.requests()[0];
    assert!(request.head.starts_with("POST / HTTP/1.1"), "{:?}", request.head);
    // "rpcuser:rpcpass" in base64
    assert!(
        request.head.contains("Authorization: Basic cnBjdXNlcjpycGNwYXNz"),
        "{:?}",
        request.head
    );
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body["method"], "getblockcount");
    assert_eq!(body["jsonrpc"], "1.0");
    assert_eq!(body["params"], serde_json::json!([]));
}

#[test]
fn the_tip_is_read_in_internal_byte_order() {
    let display = "0000000000000000000123456789abcdef0123456789abcdef0123456789abcd";
    let stub = Stub::serving(vec![ok(&format!(
        r#"{{"chain":"main","bestblockhash":"{display}","blocks":961632,"difficulty":1.5e14}}"#
    ))]);
    let tip = stub.client().tip().expect("tip");
    assert_eq!(tip.height, 961_632);
    assert_eq!(tip.chain, Chain::Main);
    assert!((tip.difficulty - 1.5e14).abs() < 1.0);

    let mut expected: [u8; 32] = hex::decode(display).unwrap().try_into().unwrap();
    expected.reverse();
    assert_eq!(tip.hash, expected, "the hash is stored the way a header holds it");
}

#[test]
fn a_tip_missing_a_field_is_an_error_not_a_default() {
    for body in [
        r#"{"chain":"main","blocks":1,"difficulty":1.0}"#,
        r#"{"chain":"main","bestblockhash":"00","difficulty":1.0}"#,
        r#"{"chain":"main","bestblockhash":"00","blocks":1}"#,
        r#"{"chain":"main","bestblockhash":"not hex","blocks":1,"difficulty":1.0}"#,
        r#"{"chain":"main","bestblockhash":"aabb","blocks":1,"difficulty":1.0}"#,
        r#"{"bestblockhash":"00","blocks":1,"difficulty":1.0}"#,
    ] {
        let stub = Stub::serving(vec![ok(body)]);
        assert!(
            matches!(stub.client().tip(), Err(Error::BadResponse(_))),
            "{body} should not parse as a tip"
        );
    }
}

#[test]
fn an_rpc_error_is_reported_even_with_a_200() {
    let stub = Stub::serving(vec![http(
        "200 OK",
        r#"{"result":null,"error":{"code":-8,"message":"Block height out of range"},"id":"ratum"}"#,
    )]);
    let err = stub.client().call("getblockhash", serde_json::json!([99])).unwrap_err();
    assert!(matches!(err, Error::Rpc(_)), "{err}");
    assert!(err.to_string().contains("out of range"), "{err}");
    assert!(!err.is_method_not_found());
}

#[test]
fn a_method_the_node_does_not_serve_is_recognized() {
    let stub = Stub::serving(vec![http(
        "404 Not Found",
        r#"{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":"ratum"}"#,
    )]);
    let err = stub.client().wait_for_block_height(5, Duration::from_millis(50)).unwrap_err();
    assert!(err.is_method_not_found(), "{err}");
}

#[test]
fn an_http_error_without_json_keeps_its_status_and_body() {
    let stub = Stub::serving(vec![http("401 Unauthorized", "<html>no</html>")]);
    let err = stub.client().call("getblockchaininfo", serde_json::json!([])).unwrap_err();
    match err {
        Error::Http(code, body) => {
            assert_eq!(code, 401);
            assert!(body.contains("<html>"), "{body}");
        }
        other => panic!("expected an http error, got {other}"),
    }
}

#[test]
fn a_response_that_is_not_http_is_refused() {
    let stub = Stub::serving(vec!["this is not a response".to_string()]);
    let err = stub.client().call("getblockchaininfo", serde_json::json!([])).unwrap_err();
    // A reply the HTTP client cannot frame is refused, not parsed as a result; the transport
    // may report it as a transport error, a bad response, or a synthetic HTTP status.
    assert!(matches!(err, Error::Transport(_) | Error::BadResponse(_) | Error::Http(..)), "{err}");
}

#[test]
fn a_200_with_a_broken_body_is_a_bad_response() {
    let stub = Stub::serving(vec![http("200 OK", "{not json")]);
    let err = stub.client().call("getblockchaininfo", serde_json::json!([])).unwrap_err();
    assert!(matches!(err, Error::BadResponse(_)), "{err}");
}

#[test]
fn a_node_that_never_responds_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let held: Vec<TcpStream> = listener.incoming().filter_map(Result::ok).collect();
        drop(held);
    });

    let mut client = Client::new(&format!("http://{addr}"), "u", "p").expect("client");
    // The transport bounds timeouts to whole seconds, so this becomes a one-second wait.
    client.timeout = Duration::from_millis(200);
    let started = std::time::Instant::now();
    let err = client.call("getblockchaininfo", serde_json::json!([])).unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "{err}");
    assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
}

#[test]
fn submitblock_returns_the_node_result() {
    let stub = Stub::serving(vec![ok("null")]);
    assert_eq!(stub.client().submit_block(&[0xab; 80]).expect("submit"), None);
    let body: serde_json::Value = serde_json::from_str(&stub.requests()[0].body).unwrap();
    assert_eq!(body["method"], "submitblock");
    assert_eq!(body["params"][0], hex::encode([0xab; 80]));

    let stub = Stub::serving(vec![ok(r#""duplicate-invalid""#)]);
    assert_eq!(
        stub.client().submit_block(&[0; 80]).expect("submit"),
        Some("duplicate-invalid".to_string())
    );

    let stub = Stub::serving(vec![ok("17")]);
    assert_eq!(stub.client().submit_block(&[0; 80]).expect("submit"), Some("17".to_string()));

    // A malformed 200 carrying neither result nor error must not parse as a null result, which
    // for submitblock would report a block the node never accepted.
    let stub = Stub::serving(vec![http("200 OK", r#"{"id":"ratum"}"#)]);
    assert!(matches!(stub.client().submit_block(&[0; 80]), Err(Error::BadResponse(_))));
}

#[test]
fn the_template_call_declares_the_fork_rules_and_reads_the_value() {
    let stub =
        Stub::serving(vec![ok(r#"{"coinbasevalue":312500000,"bits":"1a2b3c4d","height":961632}"#)]);
    let next = stub.client().next_block().expect("next block");
    assert_eq!(next.coinbase_value, 312_500_000);
    assert_eq!(next.bits, 0x1a2b_3c4d);
    let body: serde_json::Value = serde_json::from_str(&stub.requests()[0].body).unwrap();
    assert_eq!(body["method"], "getblocktemplate");
    assert_eq!(body["params"][0]["rules"], serde_json::json!(["segwit", "blake2b"]));

    // Either field missing is a bad response.
    let stub = Stub::serving(vec![ok(r#"{"bits":"1a2b3c4d","height":961632}"#)]);
    assert!(matches!(stub.client().next_block(), Err(Error::BadResponse(_))));
    let stub = Stub::serving(vec![ok(r#"{"coinbasevalue":312500000}"#)]);
    assert!(matches!(stub.client().next_block(), Err(Error::BadResponse(_))));
}

#[test]
fn waiting_for_a_height_returns_the_height_the_node_reached() {
    let stub = Stub::serving(vec![ok(r#"{"height":961633,"hash":"00"}"#)]);
    let height =
        stub.client().wait_for_block_height(961_633, Duration::from_millis(10)).expect("wait");
    assert_eq!(height, 961_633);
    let body: serde_json::Value = serde_json::from_str(&stub.requests()[0].body).unwrap();
    assert_eq!(body["method"], "waitforblockheight");
    assert_eq!(body["params"][0], 961_633);
    assert_eq!(body["params"][1], 10, "the timeout is sent in milliseconds");

    let stub = Stub::serving(vec![ok(r#"{"hash":"00"}"#)]);
    assert!(matches!(
        stub.client().wait_for_block_height(1, Duration::from_millis(10)),
        Err(Error::BadResponse(_))
    ));
}

/// The responses a restarted node gives a pool still holding its old cookie.
#[test]
fn a_refused_credential_is_distinguished_from_a_server_error() {
    let stub = Stub::serving(vec![http("401 Unauthorized", "<html>no</html>")]);
    let err = stub.client().tip().expect_err("the node refused the credential");
    assert!(err.is_unauthorized(), "{err}");

    let stub = Stub::serving(vec![http("500 Internal Server Error", "broken")]);
    let err = stub.client().tip().expect_err("the node returned a server error");
    assert!(!err.is_unauthorized(), "a server fault is not a credential problem: {err}");
}
