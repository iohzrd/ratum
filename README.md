# RATUM

## Gateway

`ratum-gateway` builds block templates from a local Knots node, serves version 2 (164-byte) headers to
BLAKE2b hardware over the Siacoin dialect of Stratum v1, takes the coinbase payout split from
the pool over DATUM, and submits blocks to the node.

It reimplements the C gateway at https://github.com/CONVOYMining/datum_gateway
and reads its configuration file unchanged; the wire formats are the C gateway's byte for
byte.

### Build and run

```
cargo run --bin ratum-gateway -- -c gateway.json

or

cargo build --workspace --release
target/release/ratum-gateway -c gateway.json

or, if you're using the release

ratum-gateway -c gateway.json
```

The file is the C gateway's JSON schema with the same defaults, except `datum.pool_host` and
`datum.pool_pubkey` (`datum-beta1.mine.ocean.xyz` and its key, where the C gateway names
`datum-beta1.mine.convoy.xyz`) and the two coinbase tags (empty, where the C gateway writes
"DATUM Gateway" and "DATUM User"; an empty secondary tag is what the pool reads as a gateway
of the miner's own, see "Public gateway fee"). Required: `bitcoind.rpcurl` (an http:// or
https:// URL; any other scheme is refused at startup) with `rpcuser`/`rpcpassword` or
`rpccookiefile`, and `mining.pool_address`. The node's
template decides when BLAKE2b (version 2) headers apply: until it lists the `!blake2b` rule
no work is served. `mining.blake2b_activation_height` and `mining.blake2b_headline` are
ignored. `RUST_LOG` overrides `logger.log_level_console`.

### Differences from the C gateway

- SIGUSR1 is a block notification, as in C (`blocknotify=kill -USR1 <pid>`); `/NOTIFY` on
  the API port does the same over HTTP. Unix only. A notification is followed by
  `getbestblockhash` reads, every 250 ms for up to 4 s, and one template request once the
  best block moves; a notification the node does not bear out requests no template, and one
  naming no block within 2.5 s of a block change is ignored.

- `api.miner_listen_port` defaults to `8000` and serves one endpoint, the miner lookup
  `GET /?addr=<address>` (the C gateway leaves the lookup off). It answers JSON and is
  unauthenticated: it reports only what the given address is already mining under. The page
  that used to render it now lives in a separate frontend project.
- `datum.pool_url` (not a C key; empty by default) names the pool's web page, and the status
  page links the pool host to it when it is set. It must begin with http:// or https://; any
  other scheme is refused at startup.
- `/clients` and `/coinbaser` are not served: the status page renders both tables from
  `/stats.json`, which carries the coinbaser outputs to anyone (the C gateway serves
  `/coinbaser` without authentication too) and the clients table only after `/login` has
  prompted for `api.admin_password`. Authentication is HTTP Basic, not Digest: keep the API
  behind TLS or on a private interface. `/cmd` takes form fields with the page's token and is
  refused without an admin password. After 10 failed Basic authentication attempts within 60
  seconds from one address (an IPv4 address, or an IPv6 /64 prefix), a request from that
  address carrying credentials is answered 429
  until the 60 seconds end, without the password being compared. Every admin reply carries
  `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.
- The API and miner lookup ports each serve at most 32 connections at once, 8 of them from one
  address (an IPv4 address, or an IPv6 /64 prefix; loopback clients, a reverse proxy on the same
  host among them, count only against the 32), and one request per connection. A request must arrive within 10 seconds, with at most 16 KiB and 100 headers in
  its request line and headers, and a body of at most 1 MiB on the API port and none on the
  miner lookup port (413 otherwise, before any body is read); chunked bodies are refused
  (501).
- `/config` is the settings page. It requires `api.admin_password`; saving requires
  `api.modify_conf` too. A save validates the edited file as at startup (the configuration
  checks, building the node client, which reads `bitcoind.rpccookiefile` when `rpcuser` is
  empty, and binding a changed stratum port), writes the edited keys into the configuration
  file (the other keys and the key order are kept) with the original file's permission bits (a
  symlinked file stays a symlink and its target is written), and restarts the gateway on the
  same command line to apply it (the running executable, or argv[0] when the executable was
  replaced in place): every change restarts, where the C gateway applies some without one. A
  password in `bitcoind.rpcurl` is shown as `***`; saving the URL as shown keeps the file's
  value. The field names and the `pool_host(old)` convention are the C gateway's;
  `datum.pool_url`, the stratum port, `stratum.vardiff_min`,
  `stratum.max_network_share_bps` and `stratum.require_address_username` are editable in
  addition to the C page's fields.
- A share whose hash meets the block target is sent to the pool before the block is submitted
  to the node, and is sent even when a share check (stale job, duplicate, username) refuses
  it, as in C. Under an anti-block-withholding assignment the gateway holds only the hash of
  the XOR key, cannot compute the block hash and recognizes no block, so a share a check
  refuses is not sent, whatever its hash (the C gateway does the same).
- A gateway the pool operator runs for miners without a node of their own sets
  `mining.coinbase_tag_secondary` to the pool's `--public-gateway-tag`, and the pool charges
  its shares `--public-gateway-fee-bps` (see "Public gateway fee" under Prime).
- One thread per stratum connection, so `stratum.max_clients` alone limits the total and
  sizes the duplicate-share table and the share queue: each holds the shares
  `stratum.vardiff_target_shares_min` gives every client over the stale window, with
  headroom. `stratum.max_clients_per_thread` and `stratum.max_threads` bound nothing here
  and are read only for the C gateway's check that their product covers `max_clients`.
  `empty_thread` disconnects every client; `/threads` is not served.
- New stratum connections are refused while the gateway's own miners measure above
  `stratum.max_network_share_bps` of the network hashrate (not a C key; 1000 basis points,
  10%, by default; 0 refuses none). The limit keeps a gateway open to the public from
  growing past that fraction of the chain, and the miner lookup reports it as
  `max_network_share_bps` beside the current `network_share`. The gateway's hashrate is the
  sum of its clients' measured windows; the network's is `getnetworkhashps` from the
  configured node, read once a minute. Connections already established keep mining and no
  client is disconnected; the status page and `/stats.json` report the share
  (`stratum.network_share`) whether or not it is over. The limit applies on chain `main`
  alone, and is not enforced while the node has answered no estimate: a node that does not
  serve `getnetworkhashps`, or a regtest chain, leaves every connection accepted. The C
  gateway has no such limit.
- The extranonce1 session id is the 32-bit connection counter, so it never repeats for a live
  connection.
- A new tip builds two immutable jobs (priority and coinbaser) where C rewrites one, so
  `datum.protocol_job_slots` must leave one extra slot. The priority job is served twice: as
  subsidy-only empty work, then, after a 50 ms hold, as the pooled work its coinbase pays.
  Both notifies name the same job, because under the version 2 header the mining machine never
  receives the coinbase, so only the notify's prefix and coinbase id separate them. A
  `mining.notify` sets clean_jobs when its job builds on a previous block other than the one
  that connection was last notified of, and on the first notify after `mining.subscribe`, so a
  connection that did not send the empty work within the hold gets the pooled work with
  clean_jobs set. An anti-block-withholding assignment notice requests a job on the current tip
  at once, which marks no earlier job stale (the C gateway's `notifynew(NULL, 0)` does the same
  after up to 4 s of retries). A coinbaser answer for a template on a replaced tip is
  discarded.
- `mining.set_difficulty` carries the difficulty as the C gateway formats it,
  n * 65535 / 65536 (16384 is announced as 16383.75); the share target is the one n names.
- At startup the gateway raises its soft open file limit (RLIMIT_NOFILE) to the hard limit and
  logs the limit in force. Each stratum connection holds three descriptors (its socket and its
  poller's epoll instance and eventfd), and a warning names the number of clients that fit when
  3 * `stratum.max_clients` + 64 exceeds the soft limit. The C gateway warns when `max_clients`
  exceeds either limit and raises neither.
- `datum.protocol_global_timeout` is at most 86400 seconds and
  `stratum.vardiff_target_shares_min` at most 20000.
- The type 2 coinbase puts every output after the OP_RETURN extranonce output and keeps that
  output with an empty split; it pays the same, the txid differs from C's.
- `mining.pool_address`, `datum.pool_pubkey` and every address in
  `stratum.username_modifiers` are checked at startup.
- `stratum.require_address_username` (not a C key; off by default) refuses the authorization,
  and every share, of a username the pool would not credit to an address: the username up
  to its first `.`, after removing a `~name` suffix that names a configured
  `stratum.username_modifiers` entry. A suffix that names none is sent to the pool as part of
  the username, so it is not removed. The address is decoded as `ratum-prime` decodes it, with
  the prefixes of every chain accepted: the gateway does not read the node's chain for this
  check, so an address of another chain passes it and `ratum-prime` refuses its shares.
- The node's `getmininginfo` is read once a minute, for the network hashrate the connection
  limit above applies to and for the node's `warnings`, which the status page shows one line
  each (a node before Bitcoin Core 29 answers a single string in place of the array; both
  read back). The C gateway shows neither.
- A block the node accepts is checked once, two minutes later, with `getblockheader`: the log
  says whether it is still on the best chain and at what depth, or that another block won the
  height. `submitblock` answering null means the node accepted the block, not that it stayed
  in the chain. The C gateway does not check.
- Log level 5 keeps errors; higher silences the sink. Timestamps are UTC.
- Every message to the pool is padded, the block-transactions response included.
- After the handshake a frame from the pool that is neither channel-encrypted nor sealed ends
  the session, which then reconnects; the C gateway processes it, which lets anyone able to
  write to the connection send an unauthenticated coinbaser split. The pool's coinbase tag is
  cut at its first NUL byte, as the C gateway's use of it is, and a tag that is not UTF-8, like
  any configuration that does not decode, ends the session.
- A transaction request (0x50 0x11) that names one index twice is answered bad-request, and a
  transaction reply that would not fit in one frame is answered too-many-transactions; the C
  gateway copies a repeated index once per listing and sends large replies bulk-framed. While
  the share queue is full, or while shares arrive for an anti-block-withholding commitment the
  session does not hold, the first dropped share is logged and then one line per 10 seconds
  with the count dropped since.
- A refused template is logged once per reason.
- Version 3 protocol (`datum.protocol_v3`, the
  [CONVOYMining gateway](https://github.com/CONVOYMining/datum_gateway)): the gateway commits
  its work to the pool's anti-block-withholding assignment and sends the slot with every
  share, but retains no proofs and audits no reveal (the pool relays every block), sends no
  bulk-framed replies (a parent fetch, 0x50 0x14, is served from its node in one frame),
  and logs a migration request (0xA4) without following it. While the pool has announced no
  active assignment it serves no work (the C gateway builds solo work then). On a disconnect
  it discards its queued and unanswered shares and replays none, keeping only the resume
  token; the shares its miners submit before the next session holds an assignment wait for
  it, and are sent when the pool resumed the session (their assignment is announced again)
  and discarded when it did not.

- The stratum dialect differs from the C gateway's in four details a miner sees:
  `mining.notify` carries an empty version field (C sends the template's version); its
  `coinb1` is 35 bytes and the extranonce1 of `mining.subscribe` 8 bytes (C sends 39 and 4:
  the concatenation the work root hashes is the same bytes); `mining.configure` answers
  `version-rolling` false when it is listed, as well as `minimum-difficulty` (C answers only
  the latter); and a request id that is a JSON object or array is accepted (C refuses it).
- A template with more than 16383 transactions (the DATUM short-id list limit) is refused
  and no job is built on it; the C gateway serves its first 16383 transactions. Only a block
  of 4,000,000 weight units, after RDTS ends, can hold that many.
- A share whose hash is a block and that a miner submits again is refused as a duplicate and
  is not submitted to the node, or sent to the pool, a second time (the newest 64 blocks
  found are held).
- A username (`mining.authorize` and `mining.submit`) is cut at its first NUL character, as the
  C gateway's copy of it stops there.

Not served: the PROXY protocol (`stratum.trust_proxy`), daily rotation
and SIGHUP (`logger.log_rotate_daily`; the file is held open, so rotate it with logrotate's
`copytruncate`), `datum.always_pay_self`, the per-client pacing of job updates, the
testnet fast-forward, hasher time rolling (`mining.allow_hasher_time_rolling`), the
retention and audit of anti-block-withholding proofs
(`mining.abw_verify_all_shares_on_disclosure`), migration (`datum.migration_max_seconds`),
`--example-conf`, `--test` and `/assets` (`--help` lists this gateway's own options). Set
values among these are reported at startup.

### Coinbase size

The coinbase a pooled job commits to carries every output the pool dictated that the
block has room for. Under the version 2 header the mining machine never receives the
coinbase: the bytes it is sent (`CBlockHeader::GetHash`) are a fixed 35-byte `coinb1`
(three zero bytes and H2, the commitment to the header's first stage, which carries the
merkle root) and the 16-byte extranonce the header carries, so a coinbase of two
outputs and one of two thousand give a miner the same job. The size classes the C gateway
builds per miner (its Antminer-safe default holds about 17 outputs) exist because SHA256d
miners reconstruct and hash the coinbase; this gateway builds one pooled coinbase and one
subsidy-only coinbase per job, and serves the pooled one to every miner.

What bounds it is the block: the weight limit (4,000,000; 800,000 while RDTS is active,
every block from the fork height until the parent's median-time-past reaches
2027-09-01), the sigop limit (80,000; a legacy P2PKH output costs four, a segwit output
none), and, while RDTS is active, output scripts of at most 34 bytes. The gateway sizes the
coinbase to the template's `sizelimit`, `weightlimit` and `sigoplimit` less its
transactions, and at 33,791 bytes in all, the largest coinbase section the pool accepts
(sized to the 512-output, 32,767-byte split a coinbaser response carries). The room a template leaves is the node's
`-blockreservedweight` (8,000 by default, about 40 taproot outputs or 55 P2WPKH) once transactions fill it, so a
node serving a pool with many identities is run with more: about 172 weight units per
output (a taproot output; 124 for P2WPKH) plus about 1,400 for the rest of the coinbase. The pool dictates at most 512
outputs (the DATUM coinbaser cap), and records what a coinbase leaves out as owed (see
"Owed blocks" under Prime).

## Prime

RATUM Prime is a DATUM pool for the [Bitcoin Knots BLAKE2b hardfork chain](https://github.com/bitcoinknots/bitcoin/pull/359),
written in Rust. Gateways beside the miners' nodes build the templates and serve stratum; the
pool dictates where the coinbase pays, verifies the shares and relays the blocks.

The workspace holds the `core` library (the protocol, the version 2 header, the RPC client and
the code the binaries share), `ratum-prime` (the pool), `ratum-gateway` (a reimplementation of
the [CONVOY DATUM Gateway](https://github.com/CONVOYMining/datum_gateway), see [Gateway](#gateway))
and `sia-test-miner` (a CPU miner that mines against a gateway). The header hash and share
format are byte-coupled between the pool and the gateway, so they are one release.

### Build and test

```
cargo build --workspace --release        # target/release/ratum-prime, ratum-gateway, sia-test-miner
cargo test --workspace
cargo test --workspace --release -- --ignored  # searches ~2^32 hashes for the test nonces
e2e/e2e.py full-stack                    # the activation block
e2e/e2e.py full-stack --mempool-txns 5   # a pooled block carrying transactions the pool requested
e2e/e2e.py multi-miner                   # three miners, two gateways: credit and payout split
e2e/e2e.py public-gateway-fee            # a tagged gateway's shares charged, the fee paid to the other's miner
```

`core/tests/header_vectors.rs` reproduces the five version 2 header vectors in
`core/tests/data/block_header_v2.json`, taken from the C implementation: the serialization,
the tagged SHA-256 chain, the BLAKE2b work root, the ASIC input of each of the four profiles
and the XOR mask. `core/tests/decoders.rs` feeds every decoder random and damaged input and
requires that none panics and that whatever decodes re-encodes to a fixed point.

The pool and the gateway read the node over JSON-RPC. Knots 29.4.2 (`v29.4.2.knots20260508rc2`
and later) prints a header-v2 block's difficulty as `difficulty_blake2b` (the expected hash
count) and omits `difficulty` in `getblockchaininfo`, `getblock` and `getblockheader`; 29.4.1
prints `difficulty`. The pool reads either: `difficulty` when present, else the difficulty
of the answer's `bits` in the same unit, else `difficulty_blake2b` divided by `2^32`.

The e2e runs need a Knots build with the BLAKE2b change (`BITCOIND`, `BITCOIN_CLI`);
`DATUM_GATEWAY` or `--gateway` runs another gateway build instead of this workspace's, and
`e2e/e2e.py <run> --help` lists each run's own options (share counts, timeouts, `--keep`).

The `ci` GitHub Actions workflow runs `cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test --workspace --all-targets` on every push and pull request. The `gateway`
workflow builds `ratum-gateway` for x86_64 and aarch64 Linux (static musl), x86_64
Windows, and x86_64 and aarch64 macOS on the same events (each an artifact of the run) and attaches the archives and their
SHA-256 sums to a release on a `v*` tag.

`git config core.hooksPath .githooks` enables the pre-commit hook that bumps the workspace
version's patch component (and `Cargo.lock`) on every commit; a reword-only amend, a commit
that already changes the version line, and `NO_BUMP=1` are left alone.

### Configuration

Every setting is a flag; `--config`, or `ratum.toml` in `--data-dir`, may hold them under the
flags' names without the dashes, and a flag given as well overrides the file. The file keeps
the node's password out of the process command line; the pool warns when it holds one and is
readable by more than its owner.

```toml
rpc = "http://ratum:...@127.0.0.1:8332"   # the node, on this host or a private link
min-diff = 16384                          # smallest share difficulty credited, a power of two
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--rpc <url>` | required | the node; a `user:password@` in the URL is the credential |
| `--rpc-cookie <file>` | none | the node's cookie file, used instead of the URL's credential and re-read when a request is refused |
| `--payout-address <address>` | required | the pool's script: the coinbase output every job reserves, and every fallback payment |
| `--data-dir <dir>` | none | holds `<chain>.redb`, `ratum-prime.key`, `hashrate.json` and `ratum.toml`; without it the window is in memory only |
| `--config <file>` | `ratum.toml` in `--data-dir` | the settings file |
| `--listen <address>` | `0.0.0.0:28915` | the DATUM listener |
| `--stats-listen <address>` | none | the `/stats.json` and `/block.json` listener (see "Stats interface") |
| `--coinbase-tag <text>` | empty | pushed into every pooled coinbase ahead of the gateway's secondary tag |
| `--motd <text>` | `RATUM Prime` | sent to every gateway at hello |
| `--min-diff <n>` | 16384 | the smallest share difficulty credited, a power of two |
| `--window <multiple>` | 8 | the window's work as a multiple of the network difficulty |
| `--ledger-keep-shares <n>` | keep all | the shares retained on disk (see "Ledger and window") |
| `--fee-bps <n>` | 0 | the operator fee, at most 100 |
| `--public-gateway-tag <text>` | none | the public gateway's secondary coinbase tag |
| `--public-gateway-fee-bps <n>` | 0 | the fee on public-gateway work, at most 10000 |
| `--public-gateway-fee-subsidy-bps <n>` | 0 | the portion of that fee reassigned to own-gateway miners |
| `--require-v3` | off | refuse version 1 gateways at hello |
| `--max-connections <n>` | 1024 | the gateway connections served at once |
| `--max-connections-per-ip <n>` | 32 | those from one address |
| `--poll <seconds>` | 0.5 | the bound on each wait for the next block before the tip is re-read |

The ledger commands (`--settle-block`, `--void-block`, `--record-owed` with `--owed`,
`--dump-ledger`, `--snapshot`) run instead of the pool, with `--data-dir`, and are executed
by the pool running on that directory when there is one; see "Ledger commands".

`RUST_LOG` selects the level (`info` default; `debug` adds every frame and share).

`--max-connections` (default 1024) bounds the gateway connections served at once and
`--max-connections-per-ip` (default 32) those from one address (an IPv4 address, or an IPv6
/64 prefix, as the stats interface counts them). A connection is closed when it sends no hello
within 5 seconds of its acceptance, and after 10 minutes without a frame from its gateway, which
sends a coinbaser request for every job it builds. The pool raises its soft open file limit to
the hard limit at startup and warns when
the limit does not cover three descriptors per connection.

A share the ledger cannot record (a write error) is answered as refused (`Other`) and its
hash released, so the gateway's count of accepted shares matches the credit.

`--require-v3` refuses at hello any gateway that does not use the version 3 protocol (its
hello carries no DRS extension). Off, the default, serves version 1 and version 3 gateways;
a version 1 client computes true block hashes and so can withhold blocks selectively. On,
every connection is under an anti-block-withholding assignment and a gateway cannot tell
which of its shares are blocks; with job validation (below) it cannot keep a block from the
pool and still be credited for its shares. Every gateway not yet on version 3 is refused. `ratum-gateway` sends a version 3
hello by default (`datum.protocol_v3`) and, when the pool responds with a version 1
configuration, runs that session under version 1.

A version 3 session's anti-block-withholding slots rotate on a new tip (once the active
slot is 75 seconds old), after 16384 accepted shares, and after 10
minutes; a rotation onto a slot whose previous key is not yet revealed waits for that reveal
rather than revealing it early. A slot on which the pool relays a block is treated as revealed
(the block's header carries its key), and rotated off at once if active. A retired slot's key is revealed 300 seconds
after its retirement, not at the next rotation: the gateway audits every proof it retained on the slot
the moment it processes the reveal, so the reveal must come after the last share the gateway
can still submit on the slot's jobs (its stale-share rule allows `share_stale_seconds +
work_update_seconds`, 160 s by default and 270 s at most; the default covers the most), and
it is sent only once every share received before it has been answered. The gateway holds one
proof per share until the reveal, in a cache of 65536, so the delay bounds the share rate one
gateway can sustain: about 160 shares per second at the default, 270 at a delay of 180 (which
covers the C default window only). A share on a revealed slot is
refused (its key is public) but still rebuilt with that key for its exact reference and its
receipt. When the connection closes the pool keeps the session for an hour under the
gateway's signing key, so a gateway that reconnects with its resume token continues the same
slots and the shares it replays verify. A resume does not postpone a reveal: its delay runs
from the retirement, or from the close of the connection the slot was retired on, since a
gateway that did not receive the rotation notice can build work on that slot until that
connection ends. The reveals it may not have received are sent again on the next connection.
Every reveal, and every rotation, waits for the first 10 seconds of a connection to pass, for
its socket to hold no unread data and for no share to be waiting on its job's transactions,
so every share the gateway sent before it, the ones it replays when it is configured
included, is answered first. The hello carries no challenge from the pool, so a copy of an
earlier hello can be sent again by anyone who observed it. A hello that presents no resume
token, or another one, leaves the saved session in place; one that presents its token
receives a copy of the session under a new token, and the saved session is removed only once
the connection sends a frame the session key decrypts, which a copy of a hello cannot. A
connection that never does saves nothing when it closes. A pool restart declines every
resume. Every share that is a
block by the node's target or by its job's own `nbits` (the measure of the gateway's reveal
audit) gets a receipt, relayed or not; a refused share answered with a receipt or reference keeps
its hash claimed, so a resend of it is not credited.

### Job validation

No share is credited on a job whose block the node has not validated. The first share on a
job that carries transactions makes the pool request them from the gateway (0x50 0x12), before
any share on the job can be known to be a block, and every share on the job waits for them, at
most 20 seconds. The transactions must be the job's: their count and their merkle branch on
the coinbase's side are the ones the job section carries. The node then checks the job's
block with each coinbase its shares use (a subsidy-only share's block, which holds the coinbase
alone, is checked apart from the pooled block with the same coinbase) (`getblocktemplate` in proposal mode: every consensus
rule but the proof of work, among them the bits, the height, the time against the parent's
median time past, the coinbase value, the witness commitment, the weight and the sigops), and
each share's header version may differ from the validated one only in the bits BIP 320 lets a
miner roll. A job whose transactions do not arrive, are not the job's, or whose block the
node refuses has none of its shares credited, and a block found on a validated job is relayed
from the transactions the pool already holds. A job with no transactions, and subsidy-only
work, is checked by the node at its first share without a request. A share on a block the
pool's node has not reported (the gateway's node received it first) is held up to 10 seconds
for the node to report it, then verified on that tip; one whose block the node does not
report in time is refused as stale. A share held for its job's transactions when the tip
moves is refused: the node validates a block on its tip alone.

Before that, a share on a job built on the node's template's parent is refused when the job's
`nbits` differ from the template's (except on testnet and testnet4, whose blocks may carry the
minimum difficulty depending on their own time, which the node's validation checks), when
its height is not the template's, or when its time is before the template's `mintime`.

The cost is one transfer of each job's transactions from its gateway (a job's block, up to
800,000 weight units while RDTS is active, about every 40 seconds per gateway), one proposal
per job and coinbase on the pool's node, and the share responses of a job's first shares
delayed by that round trip. A transaction is held once however many jobs and connections
name it. A connection holds at most 8 transaction requests and 4096 waiting shares (for
their transactions or their parent); a share past either is refused. A frame from a gateway
is at most 64 KiB, or the protocol's 4 MiB while the pool has asked it for a job's
transactions. It holds the transactions of its 4 newest jobs that have sent them; a
share on an older job requests them again, and the node validates the job's block again. A block the node refuses is not recorded as found;
one `submitblock` answers "duplicate" (the node already held it, as when the gateway's own
submission reached it first) or "inconclusive" (stored without being connected) is recorded,
and the confirmation pass reads whether it stays on the best chain. A block is submitted once
however many times its share is sent, on any connection, unless the node did not answer, in which case a resend submits it again. A
refused share that is a block by its job's own bits is submitted only when those bits are the
template's for a job on the template's parent, or name a target at most four times the
template's for a job on another parent (any bits on testnet and testnet4).

### Ledger and window

Every accepted share is written to a [redb](https://github.com/cberner/redb) database before
it is credited: `--data-dir` holds it as `<chain>.redb`; without one the window is in
memory only. `--ledger-keep-shares <n>` keeps the newest `n` shares
on disk and removes the rest as each share is recorded, at most 4096 rows per share, so a
surplus left by setting or lowering it on a large ledger is removed over the shares that
follow; unset keeps every one, which is what
TIDES specifies, since a rising network difficulty widens the window over shares that had
left it. Retention never removes a share the window holds, since the window reads itself back
from these rows, nor one of the newest `2^20` accepted in the last 4 hours 10 minutes, whose
hashes the duplicate check reads back at startup, however small `n` is: the file cannot be
bounded below what these need, and `n` is a request that both floors override.
A ledger is stamped with the node's chain and refused on another chain.

A payout is measured over the most recent shares whose difficulties sum to `--window` times the
difficulty of the block being mined, read from the node's template (the tip's while no template
has been read), as OCEAN's TIDES rule specifies (8 by default), and at least 1. At the BLAKE2b
activation height Knots resets the target to the previous target shifted left by
`Blake2bTargetShift` bits (22 on mainnet, 20 elsewhere), so the window narrows by that factor
at the fork and the shares before it leave it.

The window holds at most `2^22` shares whatever their difficulties sum to. The window is a work
target and how many shares that is depends on their difficulty, so a count bound is the only
memory guarantee that does not depend on an assigned difficulty being reasonable. It is not a
limit to run against: what keeps the count below it is `--min-diff`, since the window requires
at most `--window × network difficulty ÷ --min-diff` shares. At a window of 8 and the default
`--min-diff` of 16384 the count stays under `2^22` while the network difficulty is under `2^33`,
and higher as vardiff assigns more than the floor. In memory a share costs 16 bytes in the
window, whose buffer is kept within an eighth of the shares it has held, and each identity with
a share in it about 260 more (both measured), so the bound corresponds to 64 MiB for a pool of a
few dozen miners and about 1.1 GiB if every share in the window came from a different address,
and twice either while a reload holds the previous window. On disk a share is 119 bytes, 0.47
GiB at the bound, and redb keeps the pages it has read in a cache of 64 MiB. `--min-diff`
determines how much of the bound is used: at `2^33` on a window of 8 the window is at its bound,
while the same `--min-diff` at the present mainnet difficulty holds it under 30 MiB. The window
is read back from the store at startup, and again each time a difficulty increase widens it,
oldest first and without holding the shares it reads: 2.2 million shares take about 0.4 seconds
with the file in the operating system's page cache. The previous window is kept until the read
succeeds, so a failed read leaves it in place, and a reload briefly holds two windows.

A share is credited once however many times it is sent, across every connection and across a
restart: its block hash is held for 4 hours 10 minutes after it is accepted, and read back
from the ledger at startup. No resend can be accepted after that, since a share is refused
when its header time, which is hashed into it, is more than 2 hours from the pool's clock; the
10 minutes cover the clock stepping back. At most `2^20` hashes are held, about 123 MiB, which
covers 69 shares a second; past that the oldest are forgotten early and the pool warns.

Reaching the count bound ends the window at the newest `2^22` shares, spanning less work than
`--window` specifies, which raises payout variance; the pool warns each time the window reaches
the bound with less work than the target, and `/stats.json` reports `window.count_capped` beside
`window.max_shares` for as long as it holds. The correction is to raise `--min-diff` and the
gateways' `stratum.vardiff_min` (both 16384 by default) so the window requires fewer shares to
span the same work: each doubling of the floor halves the count required. The smallest miner
served sets the other end of that range: at a floor of 8192 a 1 TH/s miner submits a share every
35 seconds, and at 16384 every 70.

### The split

One ledger serves every gateway; a block found by any pays the miners of all, in proportion
to their work in the window. A miner's identity is its stratum username up to the first `.`,
with a bech32 address written all in uppercase lowercased, since both forms pay one script (a
base58 address is kept as written, and identities a ledger already holds stay as stored),
and it must be a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address with the prefixes of the chain the
node reported at startup (`bc`, `tb` or `bcrt` for a segwit address); other shares are rejected
with `BadUsername`. The pool decodes the address itself, with the decoder `ratum-gateway` uses
for `stratum.require_address_username`, so a witness version above 1, the pay-to-anchor
address and an address of another chain are refused. A pool that started without an answer
from the node, which only a memory-only ledger does, accepts the prefixes of every chain, for
identities and for `--payout-address`. An identity past the 512 outputs a gateway accepts, or
one whose amount would fall under 546 sats (the P2PKH dust threshold), is dropped before the split's denominator is
summed, so the miners that remain divide the whole value between them. An identity in the
window that is not such an address when the split is built (a share an earlier version of the
pool credited) is dropped after the amounts are computed, so its amount stays in the coinbase
value that reaches the pool's payout script as the remainder.

`--fee-bps` (0 to 100, default 0) is deducted from the coinbase before the split and paid to
the pool's payout script as the remainder.

A split pays each identity its part of the value it was dictated for, so a share whose job
names a split dictated for another previous block, or for a value other than the job's
coinbase value, is refused (`BadCoinbaserId`): for more, its outputs would pay the identities
the coinbase keeps more than their part; for less, the difference would reach the pool's
script with no owed record. A gateway uses a split only on the value it requested it for. A connection may request 16 splits at once and one a second after that;
a request past that is not answered. A session keeps its 64 newest splits, and saves with it
for resume at most the 8 newest of those on the tip or a tip replaced within the last second.

### Public gateway fee

A public gateway is one the pool operator runs for miners without a node of their own.
`--public-gateway-tag` names its `mining.coinbase_tag_secondary`, which the pool reads from
every share's coinbase and which a miner cannot alter (under the version 2 header the mining
machine never receives the coinbase); it must not be empty, since an empty secondary tag is
the gateway's default. A share carrying that tag is public-gateway work; a share carrying any
other tag, or none, is own-gateway work.

`--public-gateway-fee-bps` (0 to 10000, default 0) is charged on public-gateway work at each
split: an identity's weight is its work less that fraction of its public-gateway work, and
`--public-gateway-fee-subsidy-bps` (0 to 10000, default 0) is the portion of the work so
charged that is added to the own-gateway miners' weights in proportion to their own-gateway
work. The rest stays in the coinbase value that reaches the pool's payout script as the
remainder, so with no own-gateway work in the window the whole fee stays with the pool. The
fee requires the tag, and the subsidy requires the fee. The fee is charged on the work the
pool credits, so a share it rejects is not charged and a block share is charged like any
other. The reassignment is applied before the 512-output limit and the 546 sat minimum, and the
owed-block records and `/stats.json` payouts follow it, since all of them are one split. No
sats are held or paid by hand: the fee and the subsidy are share work, settled in the
coinbase of the next block found and ageing out of the window with the shares that produced
them.

Own-gateway miners' extra pay over their own work is `subsidy * fee * p / (1 - p)`, where
`p` is the public gateway's share of the window's work: at a 2% fee, a full subsidy and 80%
of the work on the public gateway, 8%. It is not capped; it can never exceed the fee charged
and falls as miners move to their own gateways. What the tag does not establish: a gateway's
node is not verified to be the miner's own, and a gateway run by someone else without the
tag counts as an own gateway.

### Owed blocks

Whatever a block's coinbase pays to the pool's payout script beyond the operator fee is owed
to the window, and the pool records it in the ledger's `owed` table at acceptance. Two cases
produce it. A coinbase that leaves dictated outputs out, paying their value to the pool's
script as its remainder: a gateway with less room than the split (a C gateway's size class,
this gateway before 0.1.23 with its 17-output default class, or any gateway on a block its
transactions fill; see "Coinbase size" under Gateway). The record names exactly those
outputs, from the split the pool dictated for the job. The other case is a coinbase that
pays the window nothing on a job with no recorded split (a subsidy-only job, served in the
interval between a tip change and the next coinbaser split); the record is the split a
coinbaser at that moment would have dictated, minus the operator fee. The amounts are logged, shown in the stats page's block table ("in
coinbase; X owed to N", or "owed by pool") and summed in its banner, and included in
`/stats.json` under `owed`. Settlement is an ordinary transaction from the operator's
wallet; afterwards `ratum-prime --settle-block <block-hash>` (with `--data-dir`; the
running pool executes it, see "Ledger commands") marks the record settled, and
`--settle-block list` prints every record. A recorded block that was rejected or orphaned (the pool's payout script never
received its value) is removed with `--void-block <block-hash>`, which deletes its block
record, its owed record if it has one, and its confirmation reading, so it is no longer
counted in luck or read from the node; `--record-owed <block-hash> --owed <identity>=<sats>
...` adds a record from command-line values for a block in the history that has none. Each
ledger command opens an existing ledger file and exits with an error naming the path when
there is none; none creates one.

The pool finds an orphaned block itself: every five minutes it asks the node
(`getblockheader`) for the confirmation count of each recorded block under 100 confirmations,
at most 32 per pass: blocks never read first, oldest first, then the least recently read, so
a block that stays under 100 (one off the best chain, or one the node does not store) is read
in turn after the others and never keeps a newer block from being read. It stores the
answer, including an answer that the node stores no block under the hash. A block the node
answers with a negative count is on a branch the best chain does not include, and a block the
node stores nothing for is not on it either; either is logged as an error naming the amounts
owed against it. `/stats.json` shows `confirmations` on both the block and
its owed record: the block's depth below the node's tip (tip height less block height plus
one) while its last reading, if any, is on the best chain, so the figure keeps growing after
the pool stops asking at 100; a negative last reading is shown as read, and a reading that the
node stores no such block as -1; null while the pool has no reading and either no tip or a
tip below the block's height (the tip was read before the block was found). `--settle-block`
refuses a block whose last reading was off the best chain or found no such block on the node,
and names `--void-block` instead, so a payout is not recorded against a coinbase that pays
nobody; it also refuses a block the pool has not yet read from the node, which it reads every
five minutes while running, so run the pool until the block's confirmations are read. `submitblock` answering null means the node
accepted the block, not that it stayed in the chain, and nothing else in the pool re-read
that.

### Ledger commands

The ledger commands run instead of the pool and take the same `--data-dir` (or `--config`
naming a file that sets it):

| Command | Effect |
| --- | --- |
| `--settle-block <block-hash>` | marks the block's owed record settled (see "Owed blocks") |
| `--settle-block list` | prints every owed record with its confirmations |
| `--void-block <block-hash>` | removes the block's record, its owed record and its confirmation reading |
| `--record-owed <block-hash> --owed <identity>=<sats> ...` | adds an owed record for a block in the history that has none |
| `--dump-ledger` | prints every stored share, one per line: time, difficulty, identity, hash, secondary tag |
| `--snapshot <path>` | writes a copy of the ledger file to `<path>` |
| `--offline` | with any of the above: opens the ledger file directly instead of asking the pool |

A pool started with `--data-dir` listens on a Unix domain socket at `<data-dir>/control.sock`
(mode 0600; never a TCP port, and not the stats interface). A command first connects to that
socket: when a pool answers, the pool executes the command against its open ledger and its
in-memory records, so a settlement or a voided block shows in `/stats.json` at once and no
restart is needed; the pool logs each command at `info` and its result at `info` (done) or
`warn` (refused or failed). When there is no socket file, or nobody listens on the one there
(a pool stopped by a signal leaves it, and the next start replaces it), the command opens the
ledger file itself, as it did before the socket existed; the file's lock still refuses that
while a pool holds the file open. `--offline` skips the socket. Either way the command says
on stderr which of the two ran, prints the same text on stdout and exits with the same code
(2 for a refused argument, 1 for an error reading or writing the ledger). In Docker, with
the pool as container `ratum-pool` on `--data-dir=/data`:

```
docker exec ratum-pool ratum-prime --data-dir=/data --settle-block list
docker exec ratum-pool ratum-prime --data-dir=/data --settle-block <block-hash>
docker exec ratum-pool ratum-prime --data-dir=/data --snapshot /data/backups/main-$(date +%F)
docker exec ratum-pool ratum-prime --data-dir=/data --dump-ledger > shares.txt
```

`--snapshot <path>` is how the ledger is backed up while the pool runs: a copy of the file
taken while the pool writes does not open, and the pool holds the file's lock, so a plain
copy needed the pool stopped. The snapshot is written from one read transaction of the
ledger's database (the pool's writes proceed meanwhile and are not in it), first to
`<path>.tmp`, which is opened again and its row counts checked before it is renamed to
`<path>`, so `<path>` is either the previous file or a copy that opens. It is refused for
any path directly in the data directory, which holds the pool's own files (a second `.redb`
there would be read as a second ledger); a subdirectory such as `/data/backups` is allowed.
The path is written by the pool, so in Docker it is a path inside the container; a relative
path is resolved by the command before it is sent. A snapshot holds every share, block, owed
record and confirmation reading as of the transaction. The ledger commands read it as they
read a ledger, named `<anything>.redb` and the only `.redb` in the directory `--data-dir`
names, so a dated snapshot as in the example is renamed into a directory of its own to be
read. A snapshot of 2 million shares takes about 1.2 seconds with the file in the
operating system's page cache, and `--dump-ledger` of the same about 0.7 seconds (both
measured, release build).

The socket takes one request and answers with newline-delimited JSON (protocol version 1; a
request of another version is answered with a refusal naming the version the pool serves).
A request is at most 1 MiB and must arrive within 10 seconds, each write to the client must
be taken within 30 seconds, and at most 4 control connections are served at once, so a stuck
client holds a thread and never the pool: no ledger or records lock is held while the socket
is read or written, and `--dump-ledger` and `--snapshot` read the file through their own
transaction. A second pool started on the same data directory finds the socket answering and
refuses to start, naming the first; a pool that returns from an error at startup removes the
socket. When the socket cannot be bound for any other reason (a path of more than 107 bytes
on Linux, or a filesystem that holds no sockets), the pool warns at startup and runs without
it, and its commands run on the file with the pool stopped, as before the socket existed.

### Stats interface

`--stats-listen <address>` serves two read-only endpoints, the snapshot at `/stats.json` and
one block at a time at `/block.json` (below); every other path is a 404 and every method but
GET a 405, each with the JSON body `{"error": "<reason>"}`. The snapshot is computed at most once a second (`generated_at` is
when), and requests within that second receive the same one, so a client polling at full
rate costs the pool one computation a second. A request carrying a body is refused (413), and the interface
serves at most 32 connections at once, 8 of them from one address (an IPv4 address, or an IPv6
/64 prefix; loopback clients count only against the 32), one request each. It carries the tip, the coinbase value, the fee, the connected gateways, the build (`--version` prints the
same string), an approximate hashrate (accepted-share difficulty over the last 10 minutes,
at 2^32 hashes per difficulty unit, for the pool and per miner) and each miner's share of the
window with `payable`, `unpayable_reason`, `tag` (the secondary coinbase tag of the
miner's newest share in the window, the gateway's `mining.coinbase_tag_secondary`),
and `own_gateway_work`; the window carries `work` against `target_work`, the `shares` it
holds against the `max_shares` it may hold, and `count_capped`, true while the count bound
rather than `target_work` is what ends it, so a reader can tell a window still filling from
one that has stopped short; `public_gateway_fee` (null unless `--public-gateway-fee-bps` is set)
carries the rates, the tag, the public-gateway work, the fee work, the work reassigned, the
own-gateway work it is divided over, and what the fee work and the reassigned work are worth
in sats at the current split. Every block the pool relays and the node does not refuse is
recorded in the ledger's `blocks` table and listed with its coinbase amounts, finder, the secondary coinbase tag its coinbase carried, and the confirmation count
the node last answered for it (see "Owed blocks"); from the record and
a cumulative work counter it derives a luck figure (blocks found over blocks
expected, each block's expected count being the work since the previous block over that
block's own difficulty, the one the window was sized to), and from the observed block spacing an expected time to the pool's next block and
the next difficulty adjustment (height, countdown, estimated factor). It also carries the
DATUM port, the public key and the values a `datum_gateway` config block needs to point a
gateway at the pool. It is unauthenticated: bind it to `127.0.0.1` unless it is behind a
reverse proxy.

The node is read for `getmininginfo` once a minute alongside the tip: `hashrate.network_hs`
is its estimate of the network's hashes per second and `hashrate.pool_share` is
`pool_hs / network_hs`, the fraction of the chain this pool directs (null while the node has
given no estimate). `node_warnings` carries the node's `warnings`, one entry each and empty
when it reports none; a change is logged as it happens, since on a chain that has just
hardforked this is where a node that does not know the new rules says so, which decides
whether the blocks the pool relays are accepted.

`hashrate.history` is the pool's hashrate over the last 24 hours as `[unix time, hashes per
second]` pairs, oldest first, one taken every `hashrate.interval_seconds` (60). A sample
taken while the node has answered `getnetworkhashps` carries that estimate as a third
element, `[unix time, pool hashes per second, network hashes per second]`, so the two can be
charted over the same span; a sample taken before the node answered is a pair, as is every
sample a gateway takes, and a reader that takes the first two elements reads either shape.
With
`--data-dir` the samples are written to `hashrate.json` in it whenever one is taken and read
back at startup, so a restart keeps the history rather than starting from an empty chart; a
sample more than 24 hours old is discarded as the file is read, and a file that cannot be
read or parsed is reported and replaced at the next sample. Without a data directory the
history is in memory only.

The response carries `X-Robots-Tag: noindex`, so the snapshot is not a search result of its
own. Rendering it is the job of a separate frontend project, which serves the snapshot from
its own origin so the browser makes no cross-origin request.

#### `/block.json`

`GET /block.json?hash=<64 hex digits>` or `GET /block.json?height=<decimal>` answers one
block the node holds, its header fields and its coinbase decoded, with the pool's own record
of it when the block is one the pool found. The node runs without `txindex`; the coinbase is
read with its block hash, which needs none. The parameters are checked before the node is
read: `hash` must be exactly 64 hex digits (either case; the reply prints it lowercase) and
`height` a decimal integer below 2^32. The statuses, each with a JSON body:

| Status | Condition | Body |
| ------ | --------- | ---- |
| 200 | the node holds the block | the object below |
| 400 | neither or both parameters, or one that does not parse | `{"error": "<reason>"}` |
| 404 | the node stores no block under the hash (`no block under the hash`), or the height is above its tip (`no block at the height`) | `{"error": "<reason>", "pool": <the pool's record of the hash, as in the object below, or null>}` |
| 405 | a method other than GET | `{"error": "method not allowed"}` |
| 502 | a node error other than those, or an answer missing a field | `{"error": "<the node error, or the field missing>"}` |

The node's answer for a hash (the block and its coinbase) is held for 60 seconds per hash,
and a height's hash for 60 seconds per height, each at most 128 entries (the least recently
requested is dropped for a new one, so a run of 128 new hashes, held by the node or not,
evicts every held answer; a run of height lookups evicts none), since `confirmations` and
`next_hash` change as blocks arrive and a height's hash on a reorg; requests for one hash or
one height arriving together wait for one node read. The `pool` object is read from the
pool's records on every request, so it reflects a `--void-block` at once, and a 404 by hash
carries it too: a block the pool found that the node does not hold is off the node's chain,
which `/stats.json` reports as `confirmations` -1, and the record is what identifies it. A 404 is held for the same 60 seconds, so a height above the tip answers 404 for up to
60 seconds after the block arrives, as `next_hash` on the block before it stays null for up
to 60 seconds. A 400 costs no node read and a 502 is not held (its key's entry stays, empty,
until evicted), so the node is read again on the next request. An uncached request makes two node calls, `getblock <hash> 1` and
`getrawtransaction <coinbase txid> true <hash>`; an uncached `height` makes one more,
`getblockhash`, before them. A key not held always costs a node read, and the connection
limit above (32 at once, 8 per address) bounds the reads in progress. The interface is
unauthenticated and read-only, and this endpoint lets a client make the pool read the node,
so the same advice applies: bind it to `127.0.0.1` unless it is behind a reverse proxy.

The fields, in order:

- `hash`, `height`, `time`, `mediantime`: the node's.
- `confirmations`: the node's count, negative when the block is off its best chain, as
  `/stats.json` reports it.
- `version` (the header's version integer), `bits` (hex, as the node prints it),
  `difficulty`, `nonce`, `merkle_root`.
- `previous_hash`: null on the genesis block. `next_hash`: null at the tip.
- `size`, `weight`, `tx_count`.
- `coinbase`: `txid`; `script_sig`, the coinbase input's script hex (the height push and the
  tags are in it); `value`, the sum of the outputs in sats; `outputs`, each with `value` in
  sats, `address` (the node's `scriptPubKey.address`, null for an OP_RETURN or a
  non-standard script) and `script`, the scriptPubKey hex.
- `pool`: null unless the block is in the pool's `blocks` table; else the row `/stats.json`
  lists the block as under `blocks.recent`, without `confirmations`: `height`, `block_hash`,
  `found_at`, `paid_to_split`, `paid_to_pool`, `finder` and `tag` (the secondary coinbase
  tag, empty when the coinbase carried none).

Nothing else the node answers is passed through: not `versionHex`, `target`, `chainwork`
or `strippedsize`, and not the transactions past the coinbase (the node lists their txids
at verbosity 1; verbosity 2, which decodes every transaction, is not used). The 164-byte
version 2 header carries fields past the first nonce (`nonce2`, `nonce3`, the time offset
and the merge-mining commitment) that the node's `getblock` does not print, so this endpoint
cannot carry them; `nonce` is the first nonce field, `version` is the header's version
integer without the version 2 flag, and `time` is the block time with the header's time
offset applied, as the node reports it. Transactions, addresses and the mempool have no
endpoint: the node keeps no index for them.

## References

https://github.com/OCEAN-xyz/datum_gateway
https://github.com/SiaMining/Stratum/blob/master/Stratum.md
https://github.com/bitcoinknots/bitcoin/pull/359
https://ocean.xyz/docs/datum
https://ocean.xyz/docs/tides
