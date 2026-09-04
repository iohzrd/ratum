# RATUM

## Gateway

`ratum-gateway` builds block templates from a local Knots node, serves version 2 (164-byte) headers to
BLAKE2b hardware over the Siacoin dialect of Stratum v1, takes the coinbase payout split from
the pool over DATUM, and submits blocks to the node.

It reimplements the C gateway at https://github.com/iohzrd/datum_gateway (branch `blake2b`)
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

The file is the C gateway's JSON schema with the same defaults. Required: `bitcoind.rpcurl`
with `rpcuser`/`rpcpassword` or `rpccookiefile`, and `mining.pool_address`. The node's
template decides when BLAKE2b (version 2) headers apply: until it lists the `!blake2b` rule
no work is served. `mining.blake2b_activation_height` and `mining.blake2b_headline` are
ignored. `RUST_LOG` overrides `logger.log_level_console`.

### Differences from the C gateway

- SIGUSR1 is a block notification, as in C (`blocknotify=kill -USR1 <pid>`); `/NOTIFY` on
  the API port does the same over HTTP. Unix only.

- `api.miner_listen_port` defaults to `8000` (the C gateway leaves the lookup page off).
- `datum.pool_url` (not a C key; empty by default) names the pool's web page, and the status
  and miner pages link the pool host to it when it is set.
- `/clients` and `/coinbaser` are not served: `/login` prompts for `api.admin_password`,
  after which the status page renders both tables from `/stats.json`. Authentication is
  HTTP Basic, not Digest: keep the API behind TLS or on a private interface. `/cmd` takes
  form fields with the page's token and is refused without an admin password.
- A block share is charged the gateway fee like any other share when it passes the share
  checks (the C gateway exempts it); a block a check refuses is still sent under the miner's
  name.
- One thread per stratum connection; `stratum.max_clients` limits the total and the
  per-thread settings size the duplicate-share table and share queue. `empty_thread`
  disconnects every client; `/threads` is not served.
- The extranonce1 session id is the 32-bit connection counter, so it never repeats for a live
  connection.
- A new tip builds three immutable jobs (empty, priority, coinbaser) where C rewrites one, so
  `datum.protocol_job_slots` must leave two extra slots.
- The type 2 coinbase puts every output after the OP_RETURN extranonce output and keeps that
  output with an empty split; it pays the same, the txid differs from C's.
- `mining.pool_address` and `datum.pool_pubkey` are checked at startup.
- Log level 5 keeps errors; higher silences the sink. Timestamps are UTC.
- Every message to the pool is padded, the block-transactions response included.
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

Not served: `api.modify_conf`, the PROXY protocol (`stratum.trust_proxy`), daily rotation
and SIGHUP (`logger.log_rotate_daily`; the file is held open, so rotate it with logrotate's
`copytruncate`), the
open-file limit warning, `datum.always_pay_self`, the per-client pacing of job updates, the
testnet fast-forward, `--help`, `--example-conf`, `--test` and `/assets`. Set values among
these are reported at startup.

## Prime

RATUM Prime is a DATUM pool for the [Bitcoin Knots BLAKE2b hardfork chain](https://github.com/bitcoinknots/bitcoin/pull/359),
written in Rust. Gateways beside the miners' nodes build the templates and serve stratum; the
pool dictates where the coinbase pays, verifies the shares and relays the blocks.

The workspace holds the `core` library (the protocol, the version 2 header, the RPC client and
the code the binaries share), `ratum-prime` (the pool), `ratum-gateway` (a reimplementation of
the [DATUM Gateway fork](https://github.com/iohzrd/datum_gateway), see [Gateway](#gateway))
and `sia-test-miner` (the CPU miner the end-to-end tests drive). The header hash and share
format are byte-coupled between the pool and the gateway, so they are one release.

### Build and test

```
cargo build --workspace --release        # target/release/ratum-prime, ratum-gateway, sia-test-miner
cargo test --workspace
cargo test --workspace --release -- --ignored  # shares and blocks, ~2^32 hashes each
tests/e2e/full_stack.sh                  # the activation block
tests/e2e/multi_miner.sh                 # three miners, two gateways: credit and payout split
tests/e2e/gateway_fee.sh                 # a gateway charging a fee beside one charging none
```

The scripts need a Knots build with the BLAKE2b change (`BITCOIND`, `BITCOIN_CLI`);
`DATUM_GATEWAY` runs another gateway build instead of this workspace's.

The `gateway` GitHub Actions workflow builds `ratum-gateway` for x86_64 and aarch64 Linux
(static musl) and x86_64 Windows on every push and pull request (each an artifact of the
run) and attaches the archives and their SHA-256 sums to a release on a `v*` tag.

`git config core.hooksPath .githooks` enables the pre-commit hook that bumps the workspace
version's patch component (and `Cargo.lock`) on every commit; a reword-only amend, a commit
that already changes the version line, and `NO_BUMP=1` are left alone.

### Configuration

Every setting is a flag; `--config`, or `ratum.toml` in `--data-dir`, may hold them under the
flags' names without the dashes, and a flag given as well overrides the file.

```toml
rpc = "http://127.0.0.1:8332"   # the node, on this host or a private link
rpc-user = "ratum"
rpc-pass = "..."                # or --rpc-cookie <file>
min-diff = 16384                # smallest share difficulty credited, a power of two
min-payout = 546                # smallest output written; a miner under it leaves the split
```

`RUST_LOG` selects the level (`info` default; `debug` adds every frame and share).

`--allow-agent` (comma-separated prefixes, e.g. `ratum-gateway/`) refuses at hello any
gateway whose user agent matches none of them; empty (the default) accepts every agent.
The agent is self-reported: this fences out builds known to mishandle the coinbaser (their
blocks pay no split), it does not authenticate anyone.

`--require-v3` refuses at hello any gateway that does not use the version 3 protocol (its
hello carries no DRS extension). Off, the default, serves version 1 and version 3 gateways;
a version 1 client computes true block hashes and so can withhold blocks selectively. On,
every connection is under an anti-block-withholding assignment and that is no longer
possible; every gateway not yet on version 3 is refused. `ratum-gateway` sends a version 3
hello by default (`datum.protocol_v3`) and, when the pool responds with a version 1
configuration, runs that session under version 1.

A version 3 session's anti-block-withholding slots rotate on a new tip (once the active
slot is a quarter of `--abw-reveal-after` old), after 16384 shares, and after 10 minutes. A
retired slot's key is revealed `--abw-reveal-after` seconds (1 to 600, default 300) after its
retirement, not at the next rotation: the gateway audits every proof it retained on the slot
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
slots and the shares it replays verify; the reveals it may not have received are sent again
once the delay has passed from the resume, after its replayed shares are answered. A pool
restart declines every resume. Every share that is a block by the node's target or by its
job's own `nbits` (the measure of the gateway's reveal audit) gets a receipt, relayed or not.

### Ledger and window

Every accepted share is written to a [redb](https://github.com/cberner/redb) database before
it is credited: `--ledger` names the file, `--data-dir` puts `<chain>.redb` inside, with
neither the window is in memory only. `--ledger-keep <n>` keeps the newest `n × 2^20` shares.
A ledger is stamped with the node's chain and refused on another chain.

A payout is measured over the most recent shares whose difficulties sum to `--window` times
the network difficulty (8, OCEAN's TIDES rule), never below `--window-floor`. At the BLAKE2b
activation height Knots resets the target to the previous target shifted left by
`Blake2bTargetShift` bits (22 on mainnet, 20 elsewhere), so set `--window-floor` to hold
the intended span of work and keep the whole ledger across the fork.

### The split

One ledger serves every gateway; a block found by any pays the miners of all, in proportion
to their work in the window. A miner's identity is its stratum username up to the first `.`,
and it must be an address the node's `validateaddress` accepts whose script fits a coinbase
output (34 bytes, or 83 beginning OP_RETURN); other shares are rejected with `BadUsername`.
An identity past the 512 outputs a gateway accepts, under `--min-payout`, or unpayable when
the split is built is left out and its amount goes to the pool's payout script.

`--fee-bps` (0 to 100, default 0) is deducted from the coinbase before the split and paid to
the pool's payout script as the remainder.

### Owed blocks

A gateway serves a subsidy-only job in the interval between a tip change and the next
coinbaser split; a block found on one pays its whole value to the pool's payout script and
the window's miners receive nothing from it. The pool records such a block in the ledger's
`owed` table at acceptance: the split a coinbaser at that moment would have dictated, minus
the operator fee. The amounts are logged, shown on the stats page (an "Owed by pool" card
and table), and included in `/stats.json` under `owed`. Settlement is an ordinary
transaction from the operator's wallet; afterwards `ratum-prime --settle-block <block-hash>`
(with `--ledger` or `--data-dir`, pool stopped) marks the record settled, and
`--settle-block list` prints every record. A recorded block that was rejected or orphaned
(the pool's payout script never received its value) is removed with
`--void-block <block-hash>`.

### Stats interface

`--stats-listen <address>` serves a read-only page at `/` and its snapshot at `/stats.json`:
the tip, the coinbase value, the fee, the connected gateways, the build (`--version` prints the
same string), an approximate hashrate (accepted-share difficulty over the last 10 minutes,
at 2^32 hashes per difficulty unit, for the pool and per miner) and each miner's share of the
window with `payable` and `unpayable_reason`. Every accepted block is recorded in the
ledger's `blocks` table and listed with its coinbase amounts and finder; from the record and
a cumulative work counter the page derives a luck figure (blocks found over blocks
expected), and from the observed block spacing an expected time to the pool's next block and
the next difficulty adjustment (height, countdown, estimated factor). The
page shows the DATUM address, the public key and a `datum_gateway` config block to point a
gateway at the pool; `--advertise-address host[:port]` sets the address when the public one
differs. It is unauthenticated: bind it to `127.0.0.1` unless it is behind a reverse proxy.

## References

https://github.com/OCEAN-xyz/datum_gateway
https://github.com/SiaMining/Stratum/blob/master/Stratum.md
https://github.com/bitcoinknots/bitcoin/pull/359
https://ocean.xyz/docs/datum
https://ocean.xyz/docs/tides
