# RATUM

RATUM is the pool server of the DATUM protocol, written in Rust. A DATUM Gateway runs beside a
miner's own node, builds the block templates and serves stratum to the hardware; the pool it
connects to, which the gateway calls DATUM Prime, dictates where the coinbase pays, verifies
the shares that come back and relays the blocks. RATUM is a pool for the [Bitcoin Knots BLAKE2b hardfork chain](https://github.com/bitcoinknots/bitcoin/pull/359).

RATUM pairs with the DATUM Gateway fork at https://github.com/iohzrd/datum_gateway (branch
`blake2b`), which sends the version 2 header section.

## Build and test

```
cargo test                               # unit, vectors, decoders, integration vs a stand-in node
cargo test --release -- --ignored        # shares and blocks, ~2^32 hashes each
tests/e2e/full_stack.sh                  # node + gateway + pool + miner: the activation block
tests/e2e/multi_miner.sh                 # three miners, two gateways: credit and payout split
```

The two scripts need a Knots build with the BLAKE2b change and a DATUM Gateway build, whose
paths they take from `BITCOIND`, `BITCOIN_CLI` and `DATUM_GATEWAY`.

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
`--data-dir` puts `shares.redb` inside, and with neither the window is held in memory only.
`--ledger-keep <n>` keeps the newest `n × 2^20` shares and deletes the rest.

A payout is measured over the most recent shares whose difficulties sum to `--window` times the
network difficulty (`8` by default, OCEAN's TIDES rule), never below `--window-floor`, re-sized as
difficulty changes; shares trimmed when it narrows are re-read from the database when it widens.
At the BLAKE2b activation height Knots shifts the target left by `Blake2bTargetShift` (20)
bits, dividing the difficulty by about `2^20`; later retargets adjust from there, at most
4x per period. An operator running it should set `--window-floor` to hold the intended span of
work, and keep the whole ledger (the default) so the pre-fork shares are credited again as the
window widens.

## The split

One ledger serves every gateway: a block found by any of them pays the miners of all of them,
in proportion to their work in the window. A miner's identity is its stratum username up to
the first `.`. The outputs total the coinbase to the satoshi; an identity that cannot be paid
(past the 512 outputs the gateway accepts, or under `--min-payout`) leaves the denominator
too, so its value goes to the other miners. There is no pool fee: the pool's own script is
paid only when something has failed, and each such case is logged.

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
