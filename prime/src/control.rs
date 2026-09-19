//! The control socket: a Unix domain socket in the data directory over which the running pool
//! executes the ledger commands, so an operator settles a block without stopping it. Newline-
//! delimited JSON, version 1: the client sends one request line and reads reply lines, `out`
//! lines carrying text for its stdout and one final `exit` line carrying the exit code and the
//! text for its stderr. No ledger or records lock is held while the socket is read or written.

use std::io;

pub const SOCKET_NAME: &str = "control.sock";

/// Why the client could not reach a pool.
#[derive(Debug)]
pub enum ConnectError {
    /// No pool answers at the socket: there is no socket file, or no pool listens on the one
    /// there (left by a pool that did not exit cleanly).
    NoPool(io::Error),
    Failed(io::Error),
}

#[cfg(unix)]
pub use unix::{ControlSocket, connect, send};

#[cfg(unix)]
mod unix {
    use super::{ConnectError, SOCKET_NAME};
    use crate::admin::{self, Command, LedgerAccess};
    use crate::ledger::blocks::BlockRecords;
    use crate::server::Server;
    use log::{error, info, warn};
    use ratum::lock;
    use redb::Database;
    use serde::{Deserialize, Serialize};
    use std::io::{self, Write};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    pub const PROTOCOL_VERSION: u32 = 1;
    /// The most bytes a request line may hold.
    pub const MAX_REQUEST_LEN: usize = 1 << 20;
    /// How long the pool waits for the request line, and the client for its request to be
    /// taken.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    /// How long the pool waits for the client to take each write.
    const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
    /// How long the client waits for each reply line: a snapshot answers once it is written.
    const REPLY_TIMEOUT: Duration = Duration::from_secs(15 * ratum::SECS_PER_MINUTE);
    /// The control connections served at once.
    const MAX_CONNECTIONS: usize = 4;
    /// The text one `out` line carries, at most; a dump is sent in such pieces.
    const OUT_CHUNK_LEN: usize = 64 << 10;
    const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Request {
        pub version: u32,
        #[serde(flatten)]
        pub command: Command,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum Reply {
        /// Text for the client's stdout, any part of a line.
        Out { out: String },
        /// The end: the code the client exits with, after `err` went to its stderr.
        Exit {
            exit: i32,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            err: String,
        },
    }

    /// One line: the value's JSON and a newline. A snapshot path that is not UTF-8 has no
    /// JSON and is refused.
    pub fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
        let mut line = serde_json::to_vec(value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        line.push(b'\n');
        Ok(line)
    }

    /// The request in `line`, or why it is refused.
    pub fn decode_request(line: &[u8]) -> Result<Request, String> {
        serde_json::from_slice(line).map_err(|e| format!("malformed request: {e}"))
    }

    /// Reads one request line of at most `MAX_REQUEST_LEN` bytes; the end of the stream ends
    /// it.
    fn read_request_line(stream: &mut impl io::Read) -> Result<Vec<u8>, String> {
        use std::io::{BufRead as _, Read as _};
        let limit = MAX_REQUEST_LEN as u64 + 1;
        let mut line = Vec::new();
        let mut reader = io::BufReader::new(stream).take(limit);
        reader.read_until(b'\n', &mut line).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                format!("no request within {} seconds", REQUEST_TIMEOUT.as_secs())
            }
            _ => format!("reading the request: {e}"),
        })?;
        if line.last() == Some(&b'\n') {
            line.pop();
        } else if line.len() as u64 >= limit {
            return Err(format!("the request is over {MAX_REQUEST_LEN} bytes"));
        }
        Ok(line)
    }

    /// The listener at `<data-dir>/control.sock`, mode 0600. Binding it claims the data
    /// directory: a second pool on it refuses to start while this one answers. Dropped, it
    /// removes the socket file.
    pub struct ControlSocket {
        path: PathBuf,
        pub(super) listener: Option<UnixListener>,
    }

    impl ControlSocket {
        /// Binds the socket, replacing a socket file no pool answers on; refuses to bind one
        /// a pool answers on (`AddrInUse`). A path past the platform's Unix socket path limit
        /// (107 bytes on Linux) is refused as `InvalidInput`, which no socket can be bound or
        /// connected at.
        pub fn bind(data_dir: &Path) -> io::Result<Self> {
            let path = data_dir.join(SOCKET_NAME);
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "another pool owns {}: its control socket {} answers",
                            data_dir.display(),
                            path.display()
                        ),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&path).map_err(|e| {
                        named(&path, "cannot remove the control socket no pool answers on", e)
                    })?;
                    info!("removed {}, left by a pool that did not exit cleanly", path.display());
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "the path {} is past the platform's Unix socket path limit ({e})",
                            path.display()
                        ),
                    ));
                }
                Err(e) => return Err(named(&path, "cannot connect to the control socket", e)),
            }
            let listener = bind_private(&path)?;
            Ok(Self { path, listener: Some(listener) })
        }

        /// Serves control connections on a thread, each on its own, until the process ends.
        pub fn serve(&mut self, server: Arc<Server>) {
            let Some(listener) = self.listener.take() else { return };
            ratum::thread::spawn("control", move || accept_loop(&listener, &server));
            info!(
                "control socket at {}: the ledger commands run here while the pool serves",
                self.path.display()
            );
        }
    }

    impl Drop for ControlSocket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn named(path: &Path, what: &str, e: io::Error) -> io::Error {
        io::Error::new(e.kind(), format!("{what} {}: {e}", path.display()))
    }

    /// Binds `path`, then sets its mode to 0600; a socket whose mode cannot be set is removed.
    fn bind_private(path: &Path) -> io::Result<UnixListener> {
        let listener = UnixListener::bind(path)
            .map_err(|e| named(path, "cannot bind the control socket", e))?;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            drop(listener);
            let _ = std::fs::remove_file(path);
            return Err(named(path, "cannot set the mode of the control socket", e));
        }
        Ok(listener)
    }

    fn accept_loop(listener: &UnixListener, server: &Arc<Server>) {
        let open = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    error!("could not accept a control connection: {e}");
                    std::thread::sleep(ACCEPT_RETRY_DELAY);
                    continue;
                }
            };
            let slot = Slot::take(&open);
            let server = Arc::clone(server);
            let spawned = ratum::thread::try_spawn("control-connection", move || {
                let refusal = (!slot.taken).then(|| {
                    format!("the pool serves at most {MAX_CONNECTIONS} control connections at once")
                });
                if let Err(e) = serve_connection(&server, stream, refusal) {
                    warn!("control: {e}");
                }
                drop(slot);
            });
            if let Err(e) = spawned {
                error!("could not start a thread for a control connection: {e}");
            }
        }
    }

    /// One of the `MAX_CONNECTIONS`, counted back down when dropped; `taken` is false past
    /// the bound, and the connection is then refused with a reply.
    struct Slot {
        open: Arc<AtomicUsize>,
        taken: bool,
    }

    impl Slot {
        fn take(open: &Arc<AtomicUsize>) -> Self {
            let held = open.fetch_add(1, Ordering::Relaxed);
            Self { open: Arc::clone(open), taken: held < MAX_CONNECTIONS }
        }
    }

    impl Drop for Slot {
        fn drop(&mut self) {
            self.open.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// The pool's ledger for a command: the records under their lock for as long as the
    /// command reads and writes them, released before any reply is written.
    struct PoolLedger<'a>(&'a Server);

    impl LedgerAccess for PoolLedger<'_> {
        fn with_records<T>(&mut self, f: impl FnOnce(&mut BlockRecords) -> T) -> io::Result<T> {
            let mut records = lock(&self.0.records);
            Ok(f(&mut records))
        }

        fn database(&mut self) -> io::Result<(Arc<Database>, PathBuf)> {
            lock(&self.0.ledger)
                .file()
                .ok_or_else(|| io::Error::other("the pool holds its ledger in memory only"))
        }
    }

    /// Reads the request, runs it and writes the replies. `refusal` set answers that alone.
    pub(super) fn serve_connection(
        server: &Server,
        mut stream: UnixStream,
        refusal: Option<String>,
    ) -> io::Result<()> {
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        if let Some(why) = refusal {
            warn!("control: refused a connection: {why}");
            return send_exit(&mut stream, 1, &why);
        }
        let request = read_request_line(&mut stream).and_then(|line| decode_request(&line));
        let command = match request {
            Ok(r) if r.version == PROTOCOL_VERSION => r.command,
            Ok(r) => {
                let why = format!(
                    "control protocol version {} is not served; this pool (ratum-prime {}) \
                     serves version {PROTOCOL_VERSION}",
                    r.version,
                    crate::VERSION
                );
                warn!("control: {why}");
                return send_exit(&mut stream, 1, &why);
            }
            Err(why) => {
                warn!("control: refused a request: {why}");
                return send_exit(&mut stream, 1, &why);
            }
        };
        info!("control: {command}");
        let mut out = ChunkedOut { stream: &mut stream, text: Vec::new(), first_line: None };
        let result = admin::execute(&command, &mut PoolLedger(server), ratum::unix_now(), &mut out);
        out.flush()?;
        let first_line = out.first_line.take().unwrap_or_default();
        match result {
            Ok(()) => {
                info!("control: {command}: done; {first_line}");
                send_exit(&mut stream, 0, "")
            }
            Err(failure) => {
                let message = failure.message();
                let how = match failure {
                    admin::Failure::Usage(_) => "refused",
                    admin::Failure::Io(_) => "failed",
                };
                warn!("control: {command}: {how} (exit {}): {message}", failure.exit_code());
                send_exit(&mut stream, failure.exit_code(), &message)
            }
        }
    }

    fn send_exit(stream: &mut UnixStream, exit: i32, err: &str) -> io::Result<()> {
        stream.write_all(&encode(&Reply::Exit { exit, err: err.to_string() })?)
    }

    /// The text a command prints, sent as `out` lines of at most `OUT_CHUNK_LEN` each. A
    /// `write` carries whole UTF-8 pieces, and a line is sent between two writes, so no
    /// character is split. The first line printed is kept for the log.
    struct ChunkedOut<'a> {
        stream: &'a mut UnixStream,
        text: Vec<u8>,
        first_line: Option<String>,
    }

    impl ChunkedOut<'_> {
        fn send(&mut self) -> io::Result<()> {
            if self.text.is_empty() {
                return Ok(());
            }
            let text = match String::from_utf8(std::mem::take(&mut self.text)) {
                Ok(text) => text,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
            };
            if self.first_line.is_none() {
                self.first_line = Some(text.lines().next().unwrap_or_default().to_string());
            }
            self.stream.write_all(&encode(&Reply::Out { out: text })?)
        }
    }

    impl Write for ChunkedOut<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.text.extend_from_slice(bytes);
            if self.text.len() >= OUT_CHUNK_LEN {
                self.send()?;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.send()
        }
    }

    /// Connects to the pool at `socket`. A path past the Unix socket path limit
    /// (`InvalidInput`) is one no pool can listen at.
    pub fn connect(socket: &Path) -> Result<UnixStream, ConnectError> {
        match UnixStream::connect(socket) {
            Ok(stream) => Ok(stream),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::InvalidInput
                ) =>
            {
                Err(ConnectError::NoPool(e))
            }
            Err(e) => Err(ConnectError::Failed(named(socket, "cannot connect to", e))),
        }
    }

    /// Sends `command` to the pool on `stream`, copies the reply's text to `out` and `err`
    /// as it arrives, and returns the exit code the pool answered.
    pub fn send(
        mut stream: UnixStream,
        command: &Command,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> io::Result<i32> {
        use std::io::BufRead as _;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
        let request = Request { version: PROTOCOL_VERSION, command: command.clone() };
        stream.write_all(&encode(&request)?)?;
        let mut reader = io::BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err(io::Error::other(
                    "the pool closed the control connection before answering",
                ));
            }
            match serde_json::from_str::<Reply>(&line) {
                Ok(Reply::Out { out: text }) => out.write_all(text.as_bytes())?,
                Ok(Reply::Exit { exit, err: message }) => {
                    if !message.is_empty() {
                        writeln!(err, "{message}")?;
                    }
                    return Ok(exit);
                }
                Err(e) => {
                    return Err(io::Error::other(format!(
                        "the pool answered a line this build cannot read ({e})"
                    )));
                }
            }
        }
    }
}

#[cfg(not(unix))]
pub use other::{ControlSocket, connect, send};

/// Without Unix domain sockets there is no control socket: the ledger commands run on the
/// file, as they do when no pool answers.
#[cfg(not(unix))]
mod other {
    use super::ConnectError;
    use crate::admin::Command;
    use crate::server::Server;
    use std::io::{self, Write};
    use std::path::Path;
    use std::sync::Arc;

    pub struct ControlSocket;

    impl ControlSocket {
        pub fn bind(_data_dir: &Path) -> io::Result<Self> {
            Ok(Self)
        }

        pub fn serve(&mut self, _server: Arc<Server>) {
            log::warn!(
                "no control socket on this platform: the ledger commands run on the ledger file \
                 with the pool stopped"
            );
        }
    }

    pub struct NoStream;

    pub fn connect(_socket: &Path) -> Result<NoStream, ConnectError> {
        Err(ConnectError::NoPool(io::Error::from(io::ErrorKind::Unsupported)))
    }

    pub fn send(
        _stream: NoStream,
        _command: &Command,
        _out: &mut dyn Write,
        _err: &mut dyn Write,
    ) -> io::Result<i32> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::{
        MAX_REQUEST_LEN, PROTOCOL_VERSION, Reply, Request, decode_request, encode, serve_connection,
    };
    use super::*;
    use crate::admin::{self, Command, run_to};
    use crate::cli::USAGE_EXIT;
    use crate::fixtures::{ALICE, Scratch, found, hash, owed, server_on, server_with, share};
    use crate::ledger::blocks::ConfirmationReading;
    use crate::ledger::split::SplitPolicy;
    use crate::ledger::{Ledger, LedgerLocation, WindowRule, open_share_ledger};
    use crate::server::Server;
    use ratum::lock;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const RECORDING_BOUND: Duration = Duration::from_secs(5);

    fn hash_arg(hash: [u8; 32]) -> String {
        hex::encode(hash)
    }

    /// A file-backed regtest ledger in `scratch` holding `shares` shares from `identity`, one
    /// found block with an unsettled owed record and a reading placing it on the best chain.
    fn ledger_in(scratch: &Scratch, shares: u64, identity: &str) -> Arc<Server> {
        let ledger = Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default());
        let path = scratch.join("regtest.redb");
        let (mut ledger, mut records) =
            open_share_ledger(Some(&path), None, Some("regtest"), ledger).unwrap();
        for i in 0..shares {
            ledger.record(share(1_000 + i, identity, 16, hash(i), "garage")).unwrap();
        }
        records.record_block(owed_block()).unwrap();
        records.record_owed(owed_record()).unwrap();
        let reading = ConfirmationReading { checked_at: 5, confirmations: 3 };
        records.record_confirmations(owed_block().block_hash, reading).unwrap();
        Arc::new(server_on(ledger, records))
    }

    fn owed_block() -> crate::ledger::blocks::FoundBlock {
        crate::ledger::blocks::FoundBlock { block_hash: owed_record().block_hash, ..found(1, 16) }
    }

    fn owed_record() -> crate::ledger::blocks::OwedBlock {
        owed(1, None)
    }

    /// The pool serving `server` at the scratch directory's control socket.
    fn serving(scratch: &Scratch, server: &Arc<Server>) -> ControlSocket {
        let mut socket = ControlSocket::bind(scratch.dir()).unwrap();
        socket.serve(Arc::clone(server));
        socket
    }

    /// Records shares to `server` until `stop` is set; the thread returns how many.
    fn record_until(
        server: &Arc<Server>,
        stop: &Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<usize> {
        let (server, stop) = (Arc::clone(server), Arc::clone(stop));
        std::thread::spawn(move || {
            let mut recorded = 0;
            while !stop.load(Ordering::Relaxed) {
                let mut block_hash = hash(0xacce_0000 + recorded as u64);
                block_hash[31] = 0xee;
                let s = share(5_000 + recorded as u64, ALICE, 16, block_hash, "");
                lock(&server.ledger).record(s).unwrap();
                recorded += 1;
            }
            recorded
        })
    }

    /// Closes the listener and leaves the socket file, as a pool killed by a signal does.
    fn abandon(mut socket: ControlSocket) {
        drop(socket.listener.take());
        std::mem::forget(socket);
    }

    /// `run_to` through the socket in `scratch`, with what it wrote to stdout and stderr.
    fn run(scratch: &Scratch, command: &Command, offline: bool) -> (i32, String, String) {
        let location = LedgerLocation::InDir(scratch.dir().to_path_buf());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_to(command, offline, &location, &mut out, &mut err).unwrap();
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    #[test]
    fn a_request_and_its_replies_round_trip_through_one_json_line_each() {
        let commands = [
            Command::SettleBlock { arg: "list".into() },
            Command::VoidBlock { arg: "ab".into() },
            Command::RecordOwed { arg: "ab".into(), owed: vec!["alice=1".into()] },
            Command::DumpLedger,
            Command::Snapshot { path: "/backups/main".into() },
        ];
        for command in commands {
            let request = Request { version: PROTOCOL_VERSION, command };
            let line = encode(&request).unwrap();
            assert_eq!(line.last(), Some(&b'\n'));
            assert!(!line[..line.len() - 1].contains(&b'\n'), "one line");
            assert_eq!(decode_request(&line[..line.len() - 1]).unwrap(), request);
        }
        let list = Request { version: 1, command: Command::SettleBlock { arg: "list".into() } };
        assert_eq!(
            String::from_utf8(encode(&list).unwrap()).unwrap(),
            "{\"version\":1,\"command\":\"settle-block\",\"arg\":\"list\"}\n"
        );
        for reply in [
            Reply::Out { out: "height 1\n  alice 5\n".into() },
            Reply::Exit { exit: 0, err: String::new() },
            Reply::Exit { exit: USAGE_EXIT, err: "no owed block".into() },
        ] {
            let line = encode(&reply).unwrap();
            assert_eq!(serde_json::from_slice::<Reply>(&line).unwrap(), reply);
        }
        let exit = encode(&Reply::Exit { exit: 0, err: String::new() }).unwrap();
        assert_eq!(String::from_utf8(exit).unwrap(), "{\"exit\":0}\n");
        use std::os::unix::ffi::OsStrExt as _;
        let not_utf8 = std::ffi::OsStr::from_bytes(b"/backups/\xff").into();
        let request = Request { version: 1, command: Command::Snapshot { path: not_utf8 } };
        assert_eq!(encode(&request).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let e = decode_request(b"{\"version\":1,\"command\":\"settle-block\"}").unwrap_err();
        assert!(e.starts_with("malformed request:"), "a settle without its arg: {e}");
        assert!(decode_request(b"{\"version\":1}").is_err(), "no command");
        assert!(decode_request(b"not json").is_err());
    }

    /// The pool's side answered over one end of a socket pair, as `serve_connection` would.
    fn answered(server: &Arc<Server>, request: &[u8]) -> Vec<Reply> {
        let (theirs, mut ours) = UnixStream::pair().unwrap();
        let server = Arc::clone(server);
        let served = std::thread::spawn(move || serve_connection(&server, theirs, None));
        ours.write_all(request).unwrap();
        ours.shutdown(std::net::Shutdown::Write).unwrap();
        let mut text = String::new();
        ours.read_to_string(&mut text).unwrap();
        served.join().unwrap().unwrap();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn an_oversize_a_malformed_and_a_wrong_version_request_are_answered_with_an_error() {
        let server = Arc::new(server_with(&[]));
        let refused = |request: &[u8]| match answered(&server, request).as_slice() {
            [Reply::Exit { exit: 1, err }] => err.clone(),
            other => panic!("{other:?}"),
        };
        let oversize = vec![b'{'; MAX_REQUEST_LEN + 1];
        let err = refused(&oversize);
        assert!(err.contains("over 1048576 bytes"), "{err}");
        let err = refused(b"{\"version\":1}\n");
        assert!(err.starts_with("malformed request:"), "{err}");
        let err = refused(b"{\"version\":2,\"command\":\"dump-ledger\"}\n");
        assert!(err.contains("version 2 is not served"), "{err}");
        let no_newline = b"{\"version\":1,\"command\":\"settle-block\",\"arg\":\"list\"}";
        let replies = answered(&server, no_newline);
        assert_eq!(
            replies,
            [
                Reply::Out { out: "no owed blocks\n".into() },
                Reply::Exit { exit: 0, err: "".into() }
            ],
            "the end of the stream ends the request line"
        );
    }

    #[test]
    fn a_block_is_settled_through_the_running_pool_while_it_records_shares() {
        let scratch = Scratch::new("control-settle");
        let server = ledger_in(&scratch, 3, ALICE);
        let _socket = serving(&scratch, &server);
        let stop = Arc::new(AtomicBool::new(false));
        let recorder = record_until(&server, &stop);
        while lock(&server.ledger).len() < 8 {
            std::thread::sleep(Duration::from_millis(5));
        }

        let settle = Command::SettleBlock { arg: hash_arg(owed_record().block_hash) };
        let (code, out, err) = run(&scratch, &settle, false);
        let recorded_before = lock(&server.ledger).len();
        assert_eq!(code, 0, "{err}");
        assert!(err.starts_with("executed by the pool at "), "{err}");
        assert!(err.trim_end().ends_with(SOCKET_NAME), "{err}");
        let settled_at = lock(&server.records).owed()[0].settled_at.expect("settled in memory");
        assert_eq!(
            out,
            format!(
                "height {} block {} found {} total 301 sats settled at {settled_at} 3 \
                 confirmations\n  alice 201\n  bob 100\n",
                owed_record().height,
                hash_arg(owed_record().block_hash),
                owed_record().found_at
            )
        );
        let stats = crate::stats::snapshot(&server, &Default::default());
        let block = &stats["owed"]["blocks"][0];
        assert_eq!(block["block_hash"], serde_json::json!(hash_arg(owed_record().block_hash)));
        assert_eq!(block["settled_at"], serde_json::json!(settled_at), "shown without a restart");
        assert_eq!(stats["owed"]["unsettled_sats"], serde_json::json!(0));

        let (code, out, err) = run(&scratch, &Command::SettleBlock { arg: "list".into() }, false);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains(&format!("settled at {settled_at}")), "{out}");
        while lock(&server.ledger).len() < recorded_before + 8 {
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        let recorded = recorder.join().unwrap();
        // At least 5 to reach 8 shares before the first command, and 8 waited for after it.
        assert!(recorded >= 13, "recording went on through the commands: {recorded}");

        // The same command on an equal ledger of a stopped pool prints the same and exits the
        // same, the settlement time given.
        let stopped = Scratch::new("control-settle-offline");
        drop(ledger_in(&stopped, 3, ALICE));
        let location = LedgerLocation::InDir(stopped.dir().to_path_buf());
        let (mut offline_out, mut offline_err) = (Vec::new(), Vec::new());
        let offline_code =
            admin::run_offline(&settle, &location, settled_at, &mut offline_out, &mut offline_err)
                .unwrap();
        assert_eq!(offline_code, code);
        assert_eq!(String::from_utf8(offline_out).unwrap(), out);
        assert!(offline_err.is_empty());
    }

    #[test]
    fn a_refusal_through_the_pool_prints_and_exits_as_the_offline_command_does() {
        let scratch = Scratch::new("control-refusal");
        let server = ledger_in(&scratch, 1, ALICE);
        let orphaned = ConfirmationReading { checked_at: 9, confirmations: -1 };
        lock(&server.records).record_confirmations(owed_record().block_hash, orphaned).unwrap();
        let _socket = serving(&scratch, &server);
        let settle = Command::SettleBlock { arg: hash_arg(owed_record().block_hash) };
        let (code, out, err) = run(&scratch, &settle, false);
        assert_eq!(code, USAGE_EXIT);
        assert!(out.contains("NOT ON THE BEST CHAIN as of 9"), "the record is printed: {out}");
        assert!(err.contains("--void-block"), "{err}");
        assert_eq!(lock(&server.records).owed()[0].settled_at, None);

        let bad = Command::SettleBlock { arg: "xyz".into() };
        let (code, out, err) = run(&scratch, &bad, false);
        assert_eq!((code, out.as_str()), (USAGE_EXIT, ""));
        assert!(err.contains("--settle-block takes the block hash"), "{err}");

        let stopped = Scratch::new("control-refusal-offline");
        let server = ledger_in(&stopped, 1, ALICE);
        lock(&server.records).record_confirmations(owed_record().block_hash, orphaned).unwrap();
        drop(server);
        let (mut offline_out, mut offline_err) = (Vec::new(), Vec::new());
        let location = LedgerLocation::InDir(stopped.dir().to_path_buf());
        let offline_code =
            admin::run_offline(&settle, &location, 1, &mut offline_out, &mut offline_err).unwrap();
        assert_eq!(offline_code, USAGE_EXIT);
        let (_, out, err) = run(&scratch, &settle, false);
        assert_eq!(String::from_utf8(offline_out).unwrap(), out);
        assert_eq!(
            String::from_utf8(offline_err).unwrap(),
            err.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n"
        );
    }

    #[test]
    fn with_no_pool_the_command_runs_on_the_ledger_file_and_says_so() {
        let scratch = Scratch::new("control-offline");
        drop(ledger_in(&scratch, 2, ALICE));
        let list = Command::SettleBlock { arg: "list".into() };
        let (code, out, err) = run(&scratch, &list, false);
        assert_eq!(code, 0);
        assert!(err.starts_with("no pool at "), "{err}");
        assert!(err.contains("opening the ledger in "), "{err}");
        assert!(out.contains(" total 301 sats unsettled 3 confirmations\n"), "{out}");

        let (code, _, err) = run(&scratch, &list, true);
        assert_eq!(code, 0);
        assert!(err.starts_with("--offline: opening the ledger in "), "{err}");

        // A socket file no pool listens on: the same, naming the refusal.
        abandon(ControlSocket::bind(scratch.dir()).unwrap());
        assert!(scratch.join(SOCKET_NAME).exists());
        let (code, _, err) = run(&scratch, &list, false);
        assert_eq!(code, 0);
        assert!(err.starts_with("no pool at ") && err.contains("refused"), "{err}");
    }

    #[test]
    fn a_data_directory_past_the_socket_path_limit_has_no_socket_and_runs_on_the_file() {
        let scratch = Scratch::new(&"long".repeat(30));
        assert!(scratch.dir().as_os_str().len() > 108);
        drop(ledger_in(&scratch, 1, ALICE));
        let Err(e) = ControlSocket::bind(scratch.dir()) else { panic!("no socket at that path") };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("socket path limit"), "{e}");
        assert!(matches!(
            connect(&scratch.join(SOCKET_NAME)),
            Err(ConnectError::NoPool(e)) if e.kind() == io::ErrorKind::InvalidInput
        ));
        let (code, out, err) = run(&scratch, &Command::SettleBlock { arg: "list".into() }, false);
        assert_eq!(code, 0, "{err}");
        assert!(err.starts_with("no pool at "), "{err}");
        assert!(out.contains(" total 301 sats unsettled 3 confirmations\n"), "{out}");
    }

    #[test]
    fn a_stale_socket_file_is_replaced_and_a_live_one_makes_a_second_pool_refuse() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("control-bind");
        let path = scratch.join(SOCKET_NAME);
        let stale = ControlSocket::bind(scratch.dir()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        abandon(stale);
        assert!(path.exists(), "the file stays after a pool that did not exit cleanly");
        assert!(matches!(
            connect(&path),
            Err(ConnectError::NoPool(e)) if e.kind() == io::ErrorKind::ConnectionRefused
        ));

        let live = ControlSocket::bind(scratch.dir()).expect("the stale file is replaced");
        assert!(connect(&path).is_ok(), "the new listener answers");
        let Err(e) = ControlSocket::bind(scratch.dir()) else { panic!("a live socket") };
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        assert!(e.to_string().contains("another pool owns"), "{e}");
        assert!(path.exists(), "the refused pool removed nothing");
        drop(live);
        assert!(!path.exists(), "removed on exit");
        assert!(matches!(connect(&path), Err(ConnectError::NoPool(_))));
    }

    #[test]
    fn a_snapshot_through_the_pool_opens_and_holds_what_the_live_ledger_held() {
        let scratch = Scratch::new("control-snapshot");
        let server = ledger_in(&scratch, 40, ALICE);
        let _socket = serving(&scratch, &server);
        let backups = Scratch::new("control-snapshot-copy");
        let target = backups.join("regtest.redb");
        let (code, out, err) = run(&scratch, &Command::Snapshot { path: target.clone() }, false);
        assert_eq!(code, 0, "{err}");
        assert!(
            out.contains("40 shares, 1 blocks, 1 owed records, 1 confirmation readings"),
            "{out}"
        );
        assert!(out.contains(&target.display().to_string()), "{out}");
        assert!(!backups.join("regtest.redb.tmp").exists());

        let (code, listed, err) =
            run(&backups, &Command::SettleBlock { arg: "list".into() }, false);
        assert_eq!(code, 0, "{err}");
        assert!(err.starts_with("no pool at "), "{err}");
        let (_, live, _) = run(&scratch, &Command::SettleBlock { arg: "list".into() }, false);
        assert_eq!(listed, live, "the same owed records");
        let (_, dumped, _) = run(&backups, &Command::DumpLedger, false);
        let (_, live_dump, _) = run(&scratch, &Command::DumpLedger, false);
        assert_eq!(dumped.lines().count(), 40);
        assert_eq!(dumped, live_dump, "the same shares");

        let (code, _, err) =
            run(&scratch, &Command::Snapshot { path: scratch.join("regtest.redb") }, false);
        assert_eq!(code, USAGE_EXIT);
        assert!(err.contains("is the live ledger"), "{err}");
        let (code, _, err) =
            run(&scratch, &Command::Snapshot { path: scratch.join("backup.redb") }, false);
        assert_eq!(code, USAGE_EXIT);
        assert!(err.contains("holds the pool's own files"), "{err}");
        assert!(!scratch.join("backup.redb").exists());
    }

    #[test]
    fn a_client_that_sends_nothing_does_not_hold_up_share_recording() {
        let scratch = Scratch::new("control-slow-request");
        let server = ledger_in(&scratch, 1, ALICE);
        let _socket = serving(&scratch, &server);
        let _silent = connect(&scratch.join(SOCKET_NAME)).unwrap();
        let _silent_too = connect(&scratch.join(SOCKET_NAME)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let recorder = record_until(&server, &stop);
        let started = Instant::now();
        while lock(&server.ledger).len() < 1 + 50 {
            assert!(
                started.elapsed() < RECORDING_BOUND,
                "recording stalled behind a connection that sent no request"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        recorder.join().unwrap();
    }

    /// A dump the client does not read: the pool blocks writing it, holding its read
    /// transaction and no lock, and the dump it then reads is the ledger as it was.
    #[test]
    fn a_dump_the_client_does_not_read_does_not_hold_up_share_recording() {
        let scratch = Scratch::new("control-slow-dump");
        let long_identity = ALICE.repeat(4);
        let server = ledger_in(&scratch, 4_000, &long_identity);
        let _socket = serving(&scratch, &server);
        let mut stream = connect(&scratch.join(SOCKET_NAME)).unwrap();
        let request = Request { version: PROTOCOL_VERSION, command: Command::DumpLedger };
        stream.write_all(&encode(&request).unwrap()).unwrap();
        // The first piece: the dump's read transaction has begun. The rest stays unread.
        let mut reader = io::BufReader::new(stream);
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let Reply::Out { out: mut text } = serde_json::from_str(&first).unwrap() else { panic!() };
        let lines = text.lines().count();
        assert!(lines > 0 && lines < 4_000, "one piece of the dump: {lines} lines");

        let stop = Arc::new(AtomicBool::new(false));
        let recorder = record_until(&server, &stop);
        let started = Instant::now();
        while lock(&server.ledger).len() < 4_000 + 50 {
            assert!(
                started.elapsed() < RECORDING_BOUND,
                "recording stalled behind a dump the client is not reading"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        let recorded = recorder.join().unwrap();

        // The pieces are not line-aligned, so the lines are counted over the whole text.
        let mut exit = None;
        for line in reader.lines() {
            match serde_json::from_str::<Reply>(&line.unwrap()).unwrap() {
                Reply::Out { out } => text.push_str(&out),
                Reply::Exit { exit: code, .. } => exit = Some(code),
            }
        }
        assert_eq!(exit, Some(0));
        let lines = text.lines().count();
        assert_eq!(lines, 4_000, "the dump is the ledger as it was, not the {recorded} since");
        assert!(text.lines().all(|l| l.split(' ').nth(2) == Some(&long_identity)), "whole lines");
    }
}
