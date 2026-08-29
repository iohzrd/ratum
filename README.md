# RATUM

RATUM is the pool server of the DATUM protocol, written in Rust. A DATUM Gateway runs beside a
miner's own node, builds the block templates and serves stratum to the hardware; the pool it
connects to, which the gateway calls DATUM Prime, dictates where the coinbase pays, verifies
the shares that come back and relays the blocks. RATUM is a pool for the [Bitcoin Knots BLAKE2b hardfork chain](https://github.com/bitcoinknots/bitcoin/pull/359).

The repository is a Cargo workspace of four crates, one per executable and one library:

- `core/`: the `ratum` library, the code the pool and the gateway share: the DATUM protocol
  (framing, handshake, messages, the share format, validation requests, the client side),
  the version 2 (BLAKE2b) block header, targets, transaction and coinbase parsing, and the
  node RPC client. It holds no pool or gateway logic.
- `prime/`: the `ratum-prime` pool binary, with the pool-only code (`config`, `ledger`,
  `verify`) as a small library the binary and the integration tests in `prime/tests/` are
  built on.
- `miner/`: `sia-test-miner`, the CPU miner the end-to-end tests drive; it depends on the
  `ratum` library alone.
- `gateway/`: the `ratum-gateway` binary, a Rust reimplementation of the DATUM Gateway fork at
  https://github.com/iohzrd/datum_gateway (branch `blake2b`). It reads the C gateway's
  configuration file unchanged and is what the end-to-end tests run; see `gateway/README.md`.

Every dependency version is set once in the root `Cargo.toml` (`[workspace.dependencies]`), so
the crates cannot drift apart; the header hash and share format are byte-coupled between the
pool and the gateway. `build.rs` at the root is the build script of every crate; it records
the git commit that `--version` reports. `tests/e2e/` holds the scripts that run all of it.

## Build and test

```
cargo build --workspace --release        # target/release/ratum-prime, ratum-gateway, sia-test-miner
cargo test --workspace                   # unit, vectors, decoders, integration vs a stand-in node
cargo test --workspace --release -- --ignored  # shares and blocks, ~2^32 hashes each
tests/e2e/full_stack.sh                  # node + gateway + pool + miner: the activation block
tests/e2e/multi_miner.sh                 # three miners, two gateways: credit and payout split
tests/e2e/gateway_fee.sh                 # a gateway charging a fee beside one charging none
```

The three scripts need a Knots build with the BLAKE2b change, whose paths they take from
`BITCOIND` and `BITCOIN_CLI`. They build and run this workspace's `ratum-gateway`;
`DATUM_GATEWAY` names another gateway build to run instead (the C gateway, for comparison).

## Configuration

Every setting is a command-line flag. `--config`, or `ratum.toml` in `--data-dir`, may hold
them under the flags' names without the dashes; a flag given as well overrides the file's value.

```toml
rpc = "http://127.0.0.1:8332"   # plain HTTP: the node on this host or a private link
rpc-user = "ratum"
rpc-pass = "..."                # or --rpc-cookie <file>; --rpc-pass on argv logs a warning
min-diff = 16384                # smallest share difficulty credited, a power of two
min-payout = 546                # smallest output written; a miner under it leaves the split
```

## Ledger and window

Every accepted share is written to a [redb](https://github.com/cberner/redb) database before
it is credited, indexed by its hash and held under an exclusive lock: `--ledger` names the file,
`--data-dir` puts `<chain>.redb` inside (`main.redb`, `testnet4.redb`, `regtest.redb`, ...,
named after the `chain` the node reports), and with neither the window is held in memory only.
`--ledger-keep <n>` keeps the newest `n × 2^20` shares and deletes the rest.

A ledger serves one chain. It is stamped with the node's chain when created and the stamp is
checked on every open: a pool whose node is on another chain refuses to start rather than pay
that chain's coinbase to shares found on this one. A ledger written before stamps existed
(`shares.redb`) has no stamp; rename it to `<chain>.redb` and the first open stamps it. The
pool asks the node for its chain before opening the ledger, and exits if the node's chain
changes while it runs.

A payout is measured over the most recent shares whose difficulties sum to `--window` times the
network difficulty (`8` by default, OCEAN's TIDES rule), never below `--window-floor`, re-sized as
difficulty changes; shares trimmed when it narrows are re-read from the database when it widens.
At the BLAKE2b activation height Knots sets the block's target once, outside the usual
retarget. On mainnet, signet and regtest it shifts the previous target left by
`Blake2bTargetShift` (20) bits, dividing the difficulty by about `2^20`. On testnet3 and
testnet4 it ignores the previous target and sets `nBits` to `0x1a00ffff`, difficulty
`16777216`; from that height the testnet 20-minute minimum-difficulty exception no longer
applies, because it is skipped for v2 headers. Later retargets adjust from whichever value
applied, at most 4x per period. An operator running it should set `--window-floor` to hold
the intended span of work, and keep the whole ledger (the default) so the pre-fork shares are
credited again as the window widens.

## The split

One ledger serves every gateway: a block found by any of them pays the miners of all of them,
in proportion to their work in the window. A miner's identity is its stratum username up to
the first `.`. The outputs total the coinbase to the satoshi; an identity that cannot be paid
(past the 512 outputs the gateway accepts, or under `--min-payout`) leaves the denominator
too, so its value goes to the other miners.

Work is credited only to an identity a coinbase output can pay. The first share from an
identity is resolved through the node's `validateaddress` and the answer is kept for the rest
of the run: an identity that is not an address, or that resolves to a script over the coinbase
output limit (34 bytes, or 83 beginning OP_RETURN), has its shares rejected with
`BadUsername`, which the gateway reports to the miner, rather than credited for work no output
can pay. A gateway with `pool_pass_full_users` sends the miner's own stratum username, so that
username must be an address this chain's node accepts, optionally followed by `.workername`.
A node the pool cannot reach leaves the identity unresolved rather than unpayable and the
share is credited as usual, so an RPC outage does not reject valid miners. An identity in the
window that is unresolved or unpayable when the split is built (credited before this check, or
while the node was unreachable) is left out after the split, so its amount is paid to the pool
rather than to the other miners; the gateway drops such an output as well, for the same
reason.

The operator fee defaults to 0 (`--fee-bps 0`): with no fee, the pool's own script is paid
only when something has failed, and each such case is logged. A fee is set with `--fee-bps` in
basis points (hundredths of a percent, 0 to 100, so at most 1%); it is deducted from the
coinbase value before the split, and the gateway pays it to the pool's payout script as the
remainder.

## Stats interface

`--stats-listen <address>` starts a read-only HTTP interface (off unless the address is
given): `/stats.json` is a snapshot of the tip, the coinbase value, the operator fee, the
connected gateways, the build the pool is running and the per-miner share of the window; `/`
is a page that fetches and renders it. `pool.version` is the package version and the git
commit the binary was compiled from (`0.1.0 (1d6a05b59172)`, with `-dirty` appended when a
tracked file differed from that commit and `unknown` in place of the hash when the source was
not a git checkout); the page shows it under the update time, and `--version` prints the same
string. A miner carries `payable`: `false` marks an identity the node resolved and the
coinbase cannot pay, with `unpayable_reason` naming why, and the page shows it as unpaid in
place of a payout it would not receive; `null` is an identity the pool has not resolved, since
the snapshot reads the cache the share path and the split fill and never calls the node
itself. It serves only GET and takes no action, and it exposes no secret (not the node
credentials, not the pool signing key). Bind it to `127.0.0.1` unless it is behind a reverse
proxy, since the page is unauthenticated: `--stats-listen 127.0.0.1:28917`.

The page also shows how to point a gateway at the pool: the DATUM address, the public key, and
a `datum_gateway` config block. The address host is the one the page was reached on, which is
correct when the page is opened at the pool's public host; set `--advertise-address` (a host,
or `host:port`) when the public address differs, for example the pool is behind NAT or a
port-mapping proxy: `--advertise-address pool.example.com:28915`.

## Logging

`RUST_LOG` selects the level through `env_logger`: `info`, the default, for settings, node
tips and sessions; `debug` adds every frame and share; `warn` leaves blocks and what is
degraded or failed. Argument errors are printed on stderr regardless and set the exit code.

## References

https://github.com/OCEAN-xyz/datum_gateway
https://github.com/iohzrd/datum_gateway
https://github.com/SiaMining/Stratum/blob/master/Stratum.md
https://github.com/bitcoinknots/bitcoin/pull/359
https://github.com/stratum-mining/stratum
https://ocean.xyz/docs/datum
https://ocean.xyz/docs/tides
