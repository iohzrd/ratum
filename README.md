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

The file is the C gateway's JSON schema with the same defaults. Required: `bitcoind.rpcurl`
with `rpcuser`/`rpcpassword` or `rpccookiefile`, and `mining.pool_address`. The node's
template decides when BLAKE2b (version 2) headers apply: until it lists the `!blake2b` rule
no work is served. `mining.blake2b_activation_height` and `mining.blake2b_headline` are
ignored. `RUST_LOG` overrides `logger.log_level_console`.

### Differences from the C gateway

- SIGUSR1 is a block notification, as in C (`blocknotify=kill -USR1 <pid>`); `/NOTIFY` on
  the API port does the same over HTTP. Unix only.

- `api.miner_listen_port` defaults to `8000` and serves one endpoint, the miner lookup
  `GET /?addr=<address>` (the C gateway leaves the lookup off). It answers JSON and is
  unauthenticated: it reports only what the given address is already mining under. The page
  that used to render it now lives in a separate frontend project.
- `datum.pool_url` (not a C key; empty by default) names the pool's web page, and the status
  page links the pool host to it when it is set.
- `/clients` and `/coinbaser` are not served: `/login` prompts for `api.admin_password`,
  after which the status page renders both tables from `/stats.json`. Authentication is
  HTTP Basic, not Digest: keep the API behind TLS or on a private interface. `/cmd` takes
  form fields with the page's token and is refused without an admin password.
- `/config` is the settings page. It requires `api.admin_password`; saving requires
  `api.modify_conf` too. A save writes the edited keys into the configuration file (the other
  keys and the key order are kept), validates it as at startup, and restarts the gateway on
  the same command line to apply it: every change restarts, where the C gateway applies some
  without one. The field names and the `pool_host(old)` convention are the C gateway's;
  `datum.pool_url`, the stratum port, `stratum.vardiff_min`,
  `stratum.max_network_share_bps` and `stratum.require_address_username` are editable in
  addition to the C page's fields.
- A block a share check refuses is still sent to the pool. A gateway the pool operator runs
  for miners without a node of their own sets `mining.coinbase_tag_secondary` to the pool's
  `--public-gateway-tag`, and the pool charges its shares `--public-gateway-fee-bps` (see
  "Public gateway fee" under Prime).
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
  receives the coinbase, so only the notify's prefix and coinbase id separate them.
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

Not served: the PROXY protocol (`stratum.trust_proxy`), daily rotation
and SIGHUP (`logger.log_rotate_daily`; the file is held open, so rotate it with logrotate's
`copytruncate`), the
open-file limit warning, `datum.always_pay_self`, the per-client pacing of job updates, the
testnet fast-forward, `--help`, `--example-conf`, `--test` and `/assets`. Set values among
these are reported at startup.

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
e2e/e2e.py multi-miner                   # three miners, two gateways: credit and payout split
e2e/e2e.py public-gateway-fee            # a tagged gateway's shares charged, the fee paid to the other's miner
```

`core/tests/header_vectors.rs` reproduces the five version 2 header vectors in
`core/tests/data/block_header_v2.json`, taken from the C implementation: the serialization,
the tagged SHA-256 chain, the BLAKE2b work root, the ASIC input of each of the four profiles
and the XOR mask. `core/tests/decoders.rs` feeds every decoder random and damaged input and
requires that none panics and that whatever decodes re-encodes to a fixed point.

The e2e runs need a Knots build with the BLAKE2b change (`BITCOIND`, `BITCOIN_CLI`);
`DATUM_GATEWAY` or `--gateway` runs another gateway build instead of this workspace's, and
`e2e/e2e.py <run> --help` lists each run's own options (share counts, timeouts, `--keep`).

The `ci` GitHub Actions workflow runs `cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test --workspace --all-targets` on every push and pull request. The `gateway`
workflow builds `ratum-gateway` for x86_64 and aarch64 Linux (static musl) and x86_64
Windows on the same events (each an artifact of the run) and attaches the archives and their
SHA-256 sums to a release on a `v*` tag.

`git config core.hooksPath .githooks` enables the pre-commit hook that bumps the workspace
version's patch component (and `Cargo.lock`) on every commit; a reword-only amend, a commit
that already changes the version line, and `NO_BUMP=1` are left alone.

### Configuration

Every setting is a flag; `--config`, or `ratum.toml` in `--data-dir`, may hold them under the
flags' names without the dashes, and a flag given as well overrides the file.

```toml
rpc = "http://127.0.0.1:8332"   # the node, on this host or a private link
rpc-user = "ratum"              # or --rpc-cookie <file>, or "user:pass@" in the url above
rpc-pass = "..."                # the credential is taken in that order of precedence
min-diff = 16384                # smallest share difficulty credited, a power of two
min-payout = 546                # smallest output written; a miner under it leaves the split
```

`RUST_LOG` selects the level (`info` default; `debug` adds every frame and share).

`--allow-agent` (comma-separated prefixes, e.g. `ratum-gateway/`) refuses at hello any
gateway whose user agent matches none of them; empty (the default) accepts every agent.
The agent is self-reported: this refuses builds known to mishandle the coinbaser (their
blocks pay no split), it does not authenticate anyone.

`--require-split` (`true`, the default, or `false`) refuses with reject code 43 (`NoSplit`)
a share whose job names a coinbaser response this pool sent while its coinbase pays none of
that response's outputs, once 10 seconds have passed since the response: the C gateway
serves its outputs-free coinbase 0 to a miner it notifies while the job's coinbaser is
awaited (a connect, a quick difficulty change, its 5 second timeout), and that miner holds
it until its next notify. A job naming no coinbaser (id 0: the job needed none, or the
request was refused or timed out), a response with no outputs, and subsidy-only work are
exempt, so the check covers builds that fetch the split and then mine coinbase 0; a share
paying any part of the split passes, and so does a block, whose value reached the pool's
script and is recorded as owed. Like `--allow-agent`, it is a check on misbuilt gateways,
not authentication: a build that never requests a coinbaser is not refused.

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
slots and the shares it replays verify. A resume does not postpone a reveal: its delay runs
from the retirement, or from the close of the connection the slot was retired on, since a
gateway that did not receive the rotation notice can build work on that slot until that
connection ends. The reveals it may not have received are sent again on the next connection.
Every reveal, and every rotation, waits for the first 10 seconds of a connection to pass and
for its socket to hold no unread data, so the shares the gateway replays when it is
configured are answered first. A pool restart declines every resume. Every share that is a
block by the node's target or by its job's own `nbits` (the measure of the gateway's reveal
audit) gets a receipt, relayed or not.

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

The window holds at most `2^20` shares whatever their difficulties sum to, which bounds it
to roughly 150 MiB. That count covers `--window` times the network difficulty while the
difficulty stays under `2^20 ÷ --window` times the average assigned share difficulty:
`2^31` at a window of 8 and the default `--min-diff` of 16384, and higher as vardiff
assigns more than the floor. The BLAKE2b chain starts at the pre-fork difficulty divided by
`2^Blake2bTargetShift`, near `2^25` on mainnet, so the count has room at first. Past that
ceiling the window ends at the newest `2^20` shares and spans less work than `--window`
asks for, which raises payout variance; the pool warns the first time it trims on the
count. Raise `--min-diff` and the gateways' `stratum.vardiff_min` (both 16384 by default)
to lift the ceiling.

### The split

One ledger serves every gateway; a block found by any pays the miners of all, in proportion
to their work in the window. A miner's identity is its stratum username up to the first `.`,
and it must be a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address with the prefixes of the chain the
node reported at startup (`bc`, `tb` or `bcrt` for a segwit address); other shares are rejected
with `BadUsername`. The pool decodes the address itself, with the decoder `ratum-gateway` uses
for `stratum.require_address_username`, so a witness version above 1, the pay-to-anchor
address and an address of another chain are refused. A pool that started without an answer
from the node, which only a memory-only ledger does, accepts the prefixes of every chain, for
identities and for `--payout-address`. An identity past the 512 outputs a gateway accepts, or
one whose amount would fall under `--min-payout`, is dropped before the split's denominator is
summed, so the miners that remain divide the whole value between them. An identity in the
window that is not such an address when the split is built (a share an earlier version of the
pool credited) is dropped after the amounts are computed, so its amount stays in the coinbase
value that reaches the pool's payout script as the remainder.

`--fee-bps` (0 to 100, default 0) is deducted from the coinbase before the split and paid to
the pool's payout script as the remainder.

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
other. The reassignment is applied before the 512-output limit and `--min-payout`, and the
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
wallet; afterwards `ratum-prime --settle-block <block-hash>` (with `--ledger` or
`--data-dir`, pool stopped) marks the record settled, and `--settle-block list` prints every
record. A recorded block that was rejected or orphaned (the pool's payout script never
received its value) is removed with `--void-block <block-hash>`, and `--record-owed
<block-hash> --owed <identity>=<sats> ...` adds a record from command-line values for a block in the
history that has none.

The pool finds an orphaned block itself: every five minutes it asks the node
(`getblockheader`) for the confirmation count of each recorded block under 100 confirmations,
at most 32 per pass, oldest first, and stores the answer. A block the node answers with a
negative count is on a branch the best chain does not include, which is logged as an error
naming the amounts owed against it. `/stats.json` shows `confirmations` on both the block and
its owed record: the block's depth below the node's tip (tip height less block height plus
one) while its last reading, if any, is on the best chain, so the figure keeps growing after
the pool stops asking at 100; a negative last reading is shown as read; null only while the
pool has neither a tip nor a reading. `--settle-block` refuses a block
whose last reading was off the best chain and names `--void-block` instead, so a payout is
not recorded against a coinbase that pays nobody. `submitblock` answering null means the node
accepted the block, not that it stayed in the chain, and nothing else in the pool re-read
that.

### Stats interface

`--stats-listen <address>` serves one endpoint, the read-only snapshot at `/stats.json`;
every other path is a 404. It carries the tip, the coinbase value, the fee, the connected gateways, the build (`--version` prints the
same string), an approximate hashrate (accepted-share difficulty over the last 10 minutes,
at 2^32 hashes per difficulty unit, for the pool and per miner) and each miner's share of the
window with `payable`, `unpayable_reason`, `tag` (the secondary coinbase tag of the
miner's newest share in the window, the gateway's `mining.coinbase_tag_secondary`),
and `own_gateway_work`; `public_gateway_fee` (null unless `--public-gateway-fee-bps` is set)
carries the rates, the tag, the public-gateway work, the fee work, the work reassigned, the
own-gateway work it is divided over, and what the fee work and the reassigned work are worth
in sats at the current split. Every accepted block is recorded in the ledger's `blocks` table
and listed with its coinbase
amounts, finder, the secondary coinbase tag its coinbase carried, and the confirmation count
the node last answered for it (see "Owed blocks"); from the record and
a cumulative work counter it derives a luck figure (blocks found over blocks
expected), and from the observed block spacing an expected time to the pool's next block and
the next difficulty adjustment (height, countdown, estimated factor). It also carries the
DATUM address, the public key and the values a `datum_gateway` config block needs to point a
gateway at the pool; `--advertise-address host[:port]` sets the address when the public one
differs. `--public-gateway <url>` names a gateway that accepts miners who do not run their
own (a value without a scheme is read as `https://`); unset, the field is null. It is
unauthenticated: bind it to `127.0.0.1` unless it is behind a reverse proxy.

The node is read for `getmininginfo` once a minute alongside the tip: `hashrate.network_hs`
is its estimate of the network's hashes per second and `hashrate.pool_share` is
`pool_hs / network_hs`, the fraction of the chain this pool directs (null while the node has
given no estimate). `node_warnings` carries the node's `warnings`, one entry each and empty
when it reports none; a change is logged as it happens, since on a chain that has just
hardforked this is where a node that does not know the new rules says so, which decides
whether the blocks the pool relays are accepted.

`hashrate.history` is the pool's hashrate over the last 24 hours as `[unix time, hashes per
second]` pairs, oldest first, one taken every `hashrate.interval_seconds` (60). With
`--data-dir` the samples are written to `hashrate.json` in it whenever one is taken and read
back at startup, so a restart keeps the history rather than starting from an empty chart; a
sample more than 24 hours old is discarded as the file is read, and a file that cannot be
read or parsed is reported and replaced at the next sample. Without a data directory the
history is in memory only.

The response carries `X-Robots-Tag: noindex`, so the snapshot is not a search result of its
own. Rendering it is the job of a separate frontend project, which serves the snapshot from
its own origin so the browser makes no cross-origin request.

## References

https://github.com/OCEAN-xyz/datum_gateway
https://github.com/SiaMining/Stratum/blob/master/Stratum.md
https://github.com/bitcoinknots/bitcoin/pull/359
https://ocean.xyz/docs/datum
https://ocean.xyz/docs/tides
