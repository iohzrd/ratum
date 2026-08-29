# ratum-gateway

The DATUM Gateway for the [Bitcoin Knots BLAKE2b hardfork chain](https://github.com/bitcoinknots/bitcoin/pull/359),
written in Rust. It is the client half of the DATUM protocol whose pool half is
[RATUM](https://github.com/iohzrd/ratum): it builds block templates from a local Knots node
over RPC, serves version 2 (164-byte) block headers to BLAKE2b mining hardware over the
Siacoin dialect of Stratum v1, connects to a RATUM pool over the encrypted DATUM protocol
for the coinbase payout split, and submits blocks to the node directly.

It is a reimplementation of the C gateway at https://github.com/iohzrd/datum_gateway
(branch `blake2b`), and reads that gateway's configuration file unchanged: a deployment
can replace the binary and keep its `gateway.json`. The wire formats (DATUM frames, share
messages, stratum jobs, the coinbase layout) are the C gateway's byte for byte. The crate is
a member of the `ratum` workspace and takes the protocol code from the `ratum` crate rather
than duplicating it, so the pool and the gateway are one version and one release; the header
hash and share format are byte-coupled between them.

## Build and test

From the workspace root (`..`):

```
cargo build --workspace --release        # target/release/ratum-gateway
cargo test -p ratum-gateway              # unit tests
tests/e2e/full_stack.sh                  # node + gateway + pool + miner: the activation block
tests/e2e/multi_miner.sh                 # three miners, two gateways: credit and payout split
tests/e2e/gateway_fee.sh                 # a gateway charging a fee beside one charging none
```

The end-to-end scripts need a Knots build with the BLAKE2b change (`BITCOIND`, `BITCOIN_CLI`).

## Running

```
ratum-gateway -c gateway.json
```

The configuration file is the C gateway's JSON schema (sections `bitcoind`, `stratum`,
`mining`, `api`, `logger`, `datum`, `extra_block_submissions`), with the same defaults and
the same required keys: `bitcoind.rpcurl`, a credential (`rpcuser` and `rpcpassword`, or
`rpccookiefile`), `mining.pool_address`, `mining.blake2b_activation_height` and
`mining.blake2b_headline`. The two BLAKE2b values are properties of the network being mined:
below the activation height no work is served, and at that height the headline replaces the
coinbase tags, since the node rejects an activation block without it.

`RUST_LOG` overrides `logger.log_level_console` (`debug` prints every share).

## What is and is not carried over from the C gateway

Carried over: the DATUM handshake, channel and every mining message, with the random
padding the C gateway puts after each; the coinbaser request per job and the six coinbase
size classes; the job, coinbase and BLAKE2b share sections; the pool's validation requests
(short transaction list, transactions by index, block transactions); the pool's blocknotify;
the `!blake2b`, headline and `reduced_data` template checks; the new-tip job sequence (empty
work, then full work with the blank coinbase, then the coinbaser job); the stratum methods
and their replies, vardiff including the quick raise, the username modifiers, the username
the pool is sent (`datum.pool_pass_full_users`, `datum.pool_pass_workers`), the gateway fee
accounting (`datum.gateway_fee_bps`), `stratum.require_address_username`, the idle timeouts,
the PROXY-less connection handling; `submitblock` with `preciousblock` to the node and to
`extra_block_submissions.urls`; `mining.save_submitblocks_dir`; `datum.pooled_mining_only`;
`SIGUSR1` as a block notification and `SIGHUP` to reopen the log file; the console and file
log levels; the status page, `/clients`, `/coinbaser`, `/NOTIFY`, `/cmd`, and the miner
lookup page with its JSON form; the startup diagnostics (open-file limit, no first job) and
the five-minute statistics line; a panic on any thread ends the process, as the C gateway's
`panic_from_thread` does.

Deliberate differences:

- The C gateway sends a block-solving share to the pool under the miner's own username
  before its share checks, so the gateway fee is never charged on a block. Here the block
  goes to the node at once, and its pool submission follows the share checks: a block share
  that passes them is charged the fee like any other share, and one a check refuses is sent
  under the miner's own name, as in C. On regtest, where every share is a block, the fee
  would otherwise never be charged, which `tests/e2e/gateway_fee.sh` checks for.
- One thread per stratum connection instead of `stratum.max_threads` threads of
  `stratum.max_clients_per_thread` clients; `stratum.max_clients` still limits the total,
  and the two per-thread values size the duplicate-share table and the share queue as they
  do in C. `/cmd`'s `empty_thread` therefore disconnects every client, and `/threads` is
  not served.
- The session id in extranonce1 is the whole 32-bit connection counter rather than a 22-bit
  index beside a thread id, so it cannot repeat for a live connection.
- A new tip builds three jobs (the empty job, the priority job with the blank coinbase, and
  the coinbaser job) where the C gateway builds one and rewrites its coinbase in place, so
  the DATUM job ring turns over faster; the `datum.protocol_job_slots` check reserves two
  slots for them. Jobs are immutable, so the pool never holds a coinbase section for a slot
  whose job changed under it.
- The "Antminer S19" coinbase class (type 2) puts every output after the OP_RETURN
  extranonce output rather than packing the first 150 bytes of outputs ahead of it, and
  keeps the OP_RETURN output when the payout split is empty, where the C gateway copies the
  scriptSig-extranonce form over it. The transaction is valid and pays the same; the txid
  differs from what the C gateway would build from the same template.
- `mining.pool_address` and `datum.pool_pubkey` are checked at startup rather than at first
  use.
- The logger's level 5 keeps error-level records (Rust has no level above error); higher
  values silence the sink. Timestamps are UTC (the C gateway's are local time) and the
  record layout is `time level [target] message`.
- Every mining message to the pool is padded with 1 to 100 random bytes, including the
  block-transactions response, which the C gateway sends unpadded.
- A refused template (BLAKE2b rule, headline, `reduced_data` payout script) is logged once
  per reason rather than on every poll.

Not carried over: `api.modify_conf` (the configuration is not editable over HTTP; the
`/config` page is not served), HTTP Digest authentication (the admin pages use HTTP Basic
authentication with `api.admin_password`, so the password crosses the wire on every
request: put the API behind TLS or on a private interface; `/cmd` takes the form fields
only, not the JSON command with a `password`, requires the form token every page embeds, and
is refused when no admin password is set, as in C), the PROXY protocol
(`stratum.trust_proxy`; a set value is reported at startup and a PROXY line closes the
connection), daily log rotation (`logger.log_rotate_daily` is reported at startup; reopen
the file with `SIGHUP` from logrotate instead), the per-client pacing of standard
job updates (every subscriber is notified at once), the testnet fast-forward hack, the
`--help` configuration reference and `--example-conf`, `--test`, and the `/assets` files.

## Layout

- `src/datum.rs`: the pool connection: connect, handshake, configuration, coinbaser
  requests, the share queue, validation responses, reconnection.
- `src/template.rs`: `getblocktemplate`, its checks, the template thread, block notification.
- `src/coinbase.rs`: the generation transaction, split around the twelve bytes the C layout
  reserves for a version 1 extranonce.
- `src/job.rs`: a job: template, coinbases, merkle branches, the version 2 header commitment
  a miner receives.
- `src/stratum.rs`: the stratum server, one thread per connection.
- `src/submit.rs`: block assembly and `submitblock`.
- `src/api.rs`: the HTTP interfaces.
- `src/address.rs`: addresses to output scripts.
- `src/config.rs`: the configuration file.
