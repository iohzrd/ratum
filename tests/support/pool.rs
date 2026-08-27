//! The `ratum-prime` binary under test: started as the release binary, its output captured.

use super::*;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The `ratum-prime` binary under test, with its output captured.
pub struct Pool {
    child: Child,
    pub addr: SocketAddr,
    pub pubkey: String,
    pub dir: TempDir,
    lines: Arc<Mutex<Vec<String>>>,
    /// The pool refuses to start without a node, so a test that does not supply one gets
    /// this. It is held here only to outlive the pool that is connected to it.
    _node: Option<FakeNode>,
}

/// Arguments for a pool under test. Defaults are the ones the tests need most.
pub struct PoolArgs {
    pub payout_script: Option<String>,
    pub payout_address: Option<String>,
    pub rpc_url: Option<String>,
    /// Set when the test supplies `--rpc` some other way (through `extra` or a configuration
    /// file), so the harness does not add one that would conflict with it.
    pub rpc_supplied_elsewhere: bool,
    pub min_difficulty: u64,
    pub min_payout: u64,
    pub window_multiple: f64,
    pub window_floor: u128,
    pub coinbase_tag: String,
    pub prime_id: u32,
    pub motd: String,
    pub activation: Option<(u32, String)>,
    pub max_connections: Option<usize>,
    pub data_dir: Option<PathBuf>,
    pub extra: Vec<String>,
}

impl Default for PoolArgs {
    fn default() -> Self {
        PoolArgs {
            payout_script: Some(hex::encode(script_for_address("pool"))),
            payout_address: None,
            rpc_url: None,
            rpc_supplied_elsewhere: false,
            min_difficulty: 1,
            min_payout: 1,
            window_multiple: 8.0,
            window_floor: 1,
            coinbase_tag: "RATUM".to_string(),
            prime_id: 1,
            motd: "RATUM Prime".to_string(),
            activation: None,
            max_connections: None,
            data_dir: None,
            extra: Vec::new(),
        }
    }
}

impl Pool {
    pub fn start(dir: TempDir, args: PoolArgs) -> Self {
        let data_dir = args.data_dir.clone().unwrap_or_else(|| dir.path().to_path_buf());
        let mut argv: Vec<String> = vec![
            "--listen".into(),
            "127.0.0.1:0".into(),
            "--data-dir".into(),
            data_dir.display().to_string(),
            "--min-diff".into(),
            args.min_difficulty.to_string(),
            "--min-payout".into(),
            args.min_payout.to_string(),
            "--window".into(),
            args.window_multiple.to_string(),
            "--window-floor".into(),
            args.window_floor.to_string(),
            "--coinbase-tag".into(),
            args.coinbase_tag.clone(),
            "--prime-id".into(),
            args.prime_id.to_string(),
            "--motd".into(),
            args.motd.clone(),
            "--poll".into(),
            "0.2".into(),
        ];
        if let Some(script) = &args.payout_script {
            argv.push("--payout-script".into());
            argv.push(script.clone());
        }
        if let Some(address) = &args.payout_address {
            argv.push("--payout-address".into());
            argv.push(address.clone());
        }
        let owned_node = match (&args.rpc_url, args.rpc_supplied_elsewhere) {
            (Some(_), _) | (None, true) => None,
            (None, false) => {
                let node = FakeNode::start();
                // Match the jobs `work::Work` builds, so its shares are not stale.
                node.set_tip(&hex::encode(work::PREV_HASH), 100);
                Some(node)
            }
        };
        let rpc_url = args.rpc_url.clone().or_else(|| owned_node.as_ref().map(|n| n.url()));
        if let Some(url) = &rpc_url {
            argv.push("--rpc".into());
            argv.push(url.clone());
            argv.push("--rpc-user".into());
            argv.push("test".into());
            // No password: the fake node does not check credentials, and a password on the
            // command line would make the pool log a warning some tests assert is absent.
        }
        if let Some((height, headline)) = &args.activation {
            argv.push("--activation-height".into());
            argv.push(height.to_string());
            argv.push("--headline".into());
            argv.push(headline.clone());
        }
        if let Some(n) = args.max_connections {
            argv.push("--max-connections".into());
            argv.push(n.to_string());
        }
        argv.extend(args.extra.iter().cloned());

        // The protocol tests assert on the per-frame and per-share lines, which the pool
        // logs at debug: a connect, a share accept and a share reject are below its default
        // level of info, the same level the DATUM Gateway and Monero p2pool log them at.
        let mut child = Command::new(env!("CARGO_BIN_EXE_ratum-prime"))
            .args(&argv)
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ratum-prime");

        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            Box::new(child.stdout.take().expect("stdout")) as Box<dyn Read + Send>,
            Box::new(child.stderr.take().expect("stderr")) as Box<dyn Read + Send>,
        ] {
            let sink = Arc::clone(&lines);
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    lock(&sink).push(line);
                }
            });
        }

        let mut pool = Pool {
            child,
            addr: "127.0.0.1:0".parse().unwrap(),
            pubkey: String::new(),
            dir,
            lines,
            _node: owned_node,
        };
        // `ratum_prime] listening on <addr> (at most N connections)`. The module suffix is part
        // of the needle because tiny_http logs `Server listening on <addr>` for the stats
        // interface at debug, which would otherwise match first and give the stats port.
        let listening = pool
            .wait_for_line("ratum_prime] listening on ", TIMEOUT)
            .expect("the pool never logged that it was listening");
        pool.addr = after(&listening, "listening on ")
            .split_whitespace()
            .next()
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| panic!("cannot read the address out of {listening:?}"));
        pool.pubkey = after(
            &pool.wait_for_line("pool_pubkey: ", TIMEOUT).expect("no pool_pubkey line"),
            "pool_pubkey: ",
        )
        .to_string();
        pool
    }

    /// Start a pool with the defaults; the harness starts a stand-in node for it.
    pub fn simple(tag: &str) -> Self {
        Pool::start(TempDir::new(tag), PoolArgs::default())
    }

    pub fn sign_pk(&self) -> [u8; 32] {
        hex::decode(&self.pubkey[..64]).unwrap().try_into().unwrap()
    }

    pub fn box_pk(&self) -> [u8; 32] {
        hex::decode(&self.pubkey[64..128]).unwrap().try_into().unwrap()
    }

    pub fn lines(&self) -> Vec<String> {
        lock(&self.lines).clone()
    }

    /// Whether the line is in what has been read from the pool so far, without waiting for
    /// more. Use this for a line that must be absent, or one the pool logged before
    /// something already waited on. For a line the pool will write, use `expect_line`: the
    /// pool logs on one pipe and responds on the socket, so a line logged immediately before
    /// a response the test already has need not have been read yet.
    pub fn logged(&self, needle: &str) -> bool {
        lock(&self.lines).iter().any(|l| l.contains(needle))
    }

    pub fn wait_for_line(&self, needle: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(found) = lock(&self.lines).iter().find(|l| l.contains(needle)) {
                return Some(found.clone());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL);
        }
    }

    pub fn expect_line(&self, needle: &str) -> String {
        self.wait_for_line(needle, TIMEOUT).unwrap_or_else(|| {
            panic!("never found {needle:?} in the pool's output:\n{}", self.lines().join("\n"))
        })
    }

    /// The credited shares, one per line in the `--dump-ledger` format
    /// `<unix-seconds> <difficulty> <identity> <share-hash>`, oldest first.
    ///
    /// The pool's ledger is a redb database it holds an exclusive lock on for its whole run,
    /// so it cannot be opened from here while the pool is running. The pool logs each credited
    /// share at debug (`record_and_credit`) immediately before it responds to the share, in the
    /// order it records them; this reconstructs the dump lines from those log lines. The `at`
    /// field is not logged, so it is a placeholder; the tests read difficulty, identity and
    /// hash.
    ///
    /// A short sleep lets the log-reader thread read the lines already written to the pipe: the
    /// accept line reaches the pipe
    /// immediately before the share response reaches the socket the caller has already read.
    pub fn ledger_lines(&self) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(500));
        lock(&self.lines)
            .iter()
            .filter_map(|l| {
                let rest = l.split_once("accepted diff=")?.1;
                let diff = rest.split_whitespace().next()?;
                let hash = after(rest, "hash=").split_whitespace().next()?;
                // The tail is `; {username} credited {total}`.
                let username = l.rsplit_once("; ")?.1.split_whitespace().next()?;
                let identity = username.split('.').next().unwrap_or(username);
                Some(format!("0 {diff} {identity} {hash}"))
            })
            .collect()
    }

    pub fn connect(&self) -> Gateway {
        Gateway::connect(self.addr, self.sign_pk(), self.box_pk())
    }

    pub fn stop(mut self) -> Vec<String> {
        let lines = self.lines();
        let _ = self.child.kill();
        let _ = self.child.wait();
        lines
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The part of a log line after `needle`. The pool writes through env_logger, so every
/// line begins with `[<timestamp> <LEVEL> ratum_prime]` and the message is not at the
/// start of it.
fn after<'a>(line: &'a str, needle: &str) -> &'a str {
    match line.split_once(needle) {
        Some((_, rest)) => rest,
        None => panic!("{needle:?} is not in {line:?}"),
    }
}

/// Run the pool with exactly these arguments and wait for it to exit, for the cases that
/// refuse to start. It gets its own directory because the pool writes its key file
/// before checking the arguments that determine where money goes, so even a failed run leaves
/// a key behind and that key must not be written into the source tree.
pub fn run_pool(args: &[&str]) -> std::process::Output {
    let cwd = TempDir::new("run");
    Command::new(env!("CARGO_BIN_EXE_ratum-prime"))
        .args(args)
        .current_dir(cwd.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ratum-prime")
}

/// What the pool printed on both streams, for asserting on a refusal.
pub fn printed(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
