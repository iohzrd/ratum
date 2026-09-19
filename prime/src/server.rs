//! The state every pool thread shares: the settings, the keys, the ledger and its block records,
//! the node and what it last reported, and the sessions saved for resume.

use crate::accounting::{ACCEPTED_HASH_RETENTION_SECS, AcceptedShareHashes, MAX_ACCEPTED_HASHES};
use crate::bounded::BoundedSet;
use crate::ledger::Ledger;
use crate::ledger::blocks::BlockRecords;
use crate::node::NodeState;
use crate::sessions::SessionStore;
use crate::settings::Settings;
use crate::txns::TxnCache;
use crate::verify::SharePolicy;
use log::info;
use ratum::datum::handshake::ResumeToken;
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::config::{ClientConfig, V3Config};
use ratum::lock;
use ratum::rpc;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The block hashes `Server::relayed_blocks` holds.
const MAX_RELAYED_BLOCKS: usize = 1024;

pub struct Server {
    pub settings: Settings,
    pub pool_keys: KeyPairs,
    pub sessions: Mutex<SessionStore>,
    pub node: rpc::Client,
    pub node_state: NodeState,
    pub accepted_hashes: Mutex<AcceptedShareHashes>,
    pub ledger: Mutex<Ledger>,
    pub records: Mutex<BlockRecords>,
    pub share_policy: SharePolicy,
    pub config_payload: Vec<u8>,
    pub open_connections: AtomicUsize,
    /// The open connections from each address (`net::limit_key`: an IPv4 address, or an IPv6
    /// /64 prefix), which `--max-connections-per-ip` bounds.
    pub open_per_ip: Mutex<HashMap<IpAddr, usize>>,
    pub txn_cache: Mutex<TxnCache>,
    /// The hashes of the blocks most recently submitted to the node, so a share sent again,
    /// on any connection, is not submitted again.
    pub relayed_blocks: Mutex<BoundedSet<[u8; 32]>>,
}

impl Server {
    pub fn new(
        settings: Settings,
        share_policy: SharePolicy,
        pool_keys: KeyPairs,
        node: rpc::Client,
        (ledger, records): (Ledger, BlockRecords),
    ) -> io::Result<Self> {
        let config_payload = share_policy.config.encode().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot build the client config: {e}"),
            )
        })?;
        let sessions =
            Mutex::new(SessionStore::new(share_policy.config.prime_id, settings.abw_reveal_after));
        Ok(Self {
            settings,
            pool_keys,
            sessions,
            accepted_hashes: accepted_hashes_from(&ledger)?,
            node,
            node_state: NodeState::default(),
            ledger: Mutex::new(ledger),
            records: Mutex::new(records),
            share_policy,
            config_payload,
            open_connections: AtomicUsize::new(0),
            open_per_ip: Mutex::new(HashMap::new()),
            txn_cache: Mutex::new(TxnCache::default()),
            relayed_blocks: Mutex::new(BoundedSet::new(MAX_RELAYED_BLOCKS)),
        })
    }

    /// Counts one more open connection from `ip` (the peer's `net::limit_key`) and returns the
    /// guard that counts it back down when it is dropped, or why it is refused:
    /// `--max-connections` are already open, or `--max-connections-per-ip` from that address.
    /// Every change to the counts is here and in that guard's `Drop`.
    pub fn open_connection(
        server: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<OpenConnectionGuard, &'static str> {
        let held = server.open_connections.fetch_add(1, Ordering::Relaxed);
        let from_ip = {
            let mut per_ip = lock(&server.open_per_ip);
            let count = per_ip.entry(ip).or_insert(0);
            *count += 1;
            *count
        };
        let guard = OpenConnectionGuard { server: Arc::clone(server), ip };
        if held >= server.settings.max_connections {
            Err("--max-connections")
        } else if from_ip > server.settings.max_connections_per_ip {
            Err("--max-connections-per-ip")
        } else {
            Ok(guard)
        }
    }

    pub fn config_payload_v3(&self, token: &ResumeToken) -> Vec<u8> {
        ClientConfig {
            v3: Some(V3Config { resume_token: *token, bulk_framing: true, abw_disabled: false }),
            ..self.share_policy.config.clone()
        }
        .encode()
        .expect("the v1 config from the same policy encoded at startup")
    }
}

/// The hashes of the shares the ledger recorded within `ACCEPTED_HASH_RETENTION_SECS`, so a
/// share accepted before a restart is still refused as a duplicate after it.
fn accepted_hashes_from(ledger: &Ledger) -> io::Result<Mutex<AcceptedShareHashes>> {
    let now = ratum::unix_now();
    let cutoff = now.saturating_sub(ACCEPTED_HASH_RETENTION_SECS);
    let mut hashes = AcceptedShareHashes::new(MAX_ACCEPTED_HASHES);
    let seeded = ledger
        .accepted_since(cutoff, MAX_ACCEPTED_HASHES)?
        .into_iter()
        .fold(0usize, |n, (at, hash)| n + usize::from(hashes.restore(hash, at, now)));
    if seeded != 0 {
        info!("{seeded} accepted share hash(es) seeded from the ledger");
    }
    Ok(Mutex::new(hashes))
}

pub struct OpenConnectionGuard {
    server: Arc<Server>,
    ip: IpAddr,
}

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.server.open_connections.fetch_sub(1, Ordering::Relaxed);
        let mut per_ip = lock(&self.server.open_per_ip);
        if let Some(count) = per_ip.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}
