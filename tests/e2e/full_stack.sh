#!/usr/bin/env bash
# Mine the activation block through the whole stack, on regtest.
#
#   bitcoind (Knots, BLAKE2b branch) <- RPC - datum_gateway - DATUM -> ratum-prime - RPC -> bitcoind
#                                                  ^ sia-test-miner
#
# The pool's own tests cover the pool. This covers the parts only the real programs can:
# that the gateway accepts what the pool dictates, that a share the pool verifies is a
# block the node accepts, and that the activation block carries the headline.
#
# usage: tests/e2e/full_stack.sh [--keep]
#
# Needs a Bitcoin Knots build with the BLAKE2b change; the gateway is this workspace's
# ratum-gateway crate unless DATUM_GATEWAY names another build (the C gateway, say):
#   BITCOIND        default ~/src/bitcoin/build/bin/bitcoind
#   BITCOIN_CLI     default ~/src/bitcoin/build/bin/bitcoin-cli
#   DATUM_GATEWAY   default the ratum-gateway crate in this workspace, built below
#   TIMEOUT         seconds to wait for the block, default 900
#
# Exits 0 only if the node accepted a block the pool verified.

set -euo pipefail

BITCOIND=${BITCOIND:-$HOME/src/bitcoin/build/bin/bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-$HOME/src/bitcoin/build/bin/bitcoin-cli}
DATUM_GATEWAY=${DATUM_GATEWAY:-}
TIMEOUT=${TIMEOUT:-900}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# BIP34 writes the height as a minimal push, which for a height of 16 or less is OP_N
# rather than a one-byte push, and the node requires OP_N. Activating above 16 keeps the
# test on the encoding real heights use.
ACTIVATION_HEIGHT=20
HEADLINE="RATUM full stack test"
POOL_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
MINER_ADDRESS=bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lgth6c

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratum-e2e-XXXXXX")

# A port nothing else is holding. Picking one at random collides with whatever else is on
# the machine, and a collision is reported as a program that exits during startup rather than
# as a message naming the port, so bind the port first to check that it is free.
free_port() {
    local port
    port=$(python3 - "$1" "$2" <<'PORTPY'
import random, socket, sys

base, span = int(sys.argv[1]), int(sys.argv[2])
for _ in range(200):
    port = base + random.randrange(span)
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        continue
    finally:
        probe.close()
    print(port)
    break
else:
    sys.exit(1)
PORTPY
    )
    [ -n "$port" ] || { printf 'no free port in %s..%s\n' "$1" "$(($1 + $2))" >&2; exit 1; }
    printf '%s\n' "$port"
}

RPC_PORT=$(free_port 18400 150)
POOL_PORT=$(free_port 28900 90)
STRATUM_PORT=$(free_port 23300 90)
API_PORT=$(free_port 7100 90)
PIDS=()

step() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

cleanup() {
    local status=$?
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    "$BITCOIN_CLI" -datadir="$WORK/node" stop >/dev/null 2>&1 || true
    sleep 1
    if [ "$KEEP" = 1 ]; then
        printf '\nlogs kept in %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
    exit $status
}
trap cleanup EXIT

for tool in "$BITCOIND" "$BITCOIN_CLI" ${DATUM_GATEWAY:+"$DATUM_GATEWAY"}; do
    [ -x "$tool" ] || fail "$tool is not executable; set BITCOIND, BITCOIN_CLI or DATUM_GATEWAY"
done
command -v python3 >/dev/null || fail "python3 is not on PATH"

DATUM_GATEWAY=${DATUM_GATEWAY:-$ROOT/target/release/ratum-gateway}
step "building the pool, the gateway and the test miner"
(cd "$ROOT" && cargo build --workspace --release --bin ratum-prime --bin sia-test-miner --bin ratum-gateway) \
    || fail "cargo build"

step "starting a regtest node with BLAKE2b active at height $ACTIVATION_HEIGHT"
mkdir -p "$WORK/node"
cat > "$WORK/node/bitcoin.conf" <<EOF
regtest=1
server=1
# No peers, so no P2P listener. It also prevents the node from binding ports 18444 and 18445,
# either of which the randomly chosen RPC port below could otherwise collide with.
listen=0
rpcuser=ratum
rpcpassword=ratumtest
[regtest]
rpcbind=127.0.0.1
rpcport=$RPC_PORT
testactivationheight=blake2b@$ACTIVATION_HEIGHT
blake2b_headline=$HEADLINE
EOF
"$BITCOIND" -datadir="$WORK/node" > "$WORK/bitcoind.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
    "$BITCOIN_CLI" -datadir="$WORK/node" getblockchaininfo >/dev/null 2>&1 && break
    sleep 0.5
done
"$BITCOIN_CLI" -datadir="$WORK/node" getblockchaininfo >/dev/null \
    || fail "the node never responded on port $RPC_PORT"

step "mining $((ACTIVATION_HEIGHT - 1)) blocks before the fork, with SHA256d"
"$BITCOIN_CLI" -datadir="$WORK/node" generatetoaddress $((ACTIVATION_HEIGHT - 1)) "$POOL_ADDRESS" \
    >/dev/null
height=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount)
[ "$height" = "$((ACTIVATION_HEIGHT - 1))" ] || fail "expected height $((ACTIVATION_HEIGHT - 1)), got $height"

step "starting ratum-prime on port $POOL_PORT"
mkdir -p "$WORK/pool"
# "<- accepted" is logged at debug, which the default info level would not print, and the count
# of accepted shares is one of the things this test checks.
RUST_LOG="${RUST_LOG:-debug}" \
"$ROOT/target/release/ratum-prime" \
    --listen "127.0.0.1:$POOL_PORT" \
    --data-dir "$WORK/pool" \
    --rpc "http://127.0.0.1:$RPC_PORT" --rpc-user ratum --rpc-pass ratumtest \
    --payout-address "$POOL_ADDRESS" \
    --min-diff 1 --min-payout 1 --poll 1 \
    --activation-height "$ACTIVATION_HEIGHT" --headline "$HEADLINE" \
    > "$WORK/pool.log" 2>&1 &
POOL_PID=$!
PIDS+=($POOL_PID)

for _ in $(seq 1 60); do
    grep -q 'listening on' "$WORK/pool.log" 2>/dev/null && break
    sleep 0.5
done
# The public key is printed before the listener binds, so the key alone does not mean the
# pool started. A port already in use ends the process right after it prints the key.
grep -q 'listening on' "$WORK/pool.log" \
    || fail "the pool never listened on 127.0.0.1:$POOL_PORT; see $WORK/pool.log"
# Keyed on the label rather than a field number: the pool logs through env_logger, so the
# message follows a "[<timestamp> <LEVEL> ratum_prime]" prefix rather than starting the line.
PUBKEY=$(awk '{for (i = 1; i < NF; i++) if ($i == "pool_pubkey:") {print $(i + 1); exit}}' \
    "$WORK/pool.log")
[ -n "$PUBKEY" ] || fail "the pool never printed its public key; see $WORK/pool.log"

step "starting the gateway on stratum port $STRATUM_PORT"
cat > "$WORK/gateway.json" <<EOF
{
  "bitcoind": {
    "rpcuser": "ratum",
    "rpcpassword": "ratumtest",
    "rpcurl": "http://127.0.0.1:$RPC_PORT",
    "notify_fallback": true
  },
  "stratum": { "listen_port": $STRATUM_PORT, "vardiff_min": 1, "vardiff_target_shares_min": 4 },
  "mining": {
    "pool_address": "$MINER_ADDRESS",
    "coinbase_tag_primary": "RATUM",
    "coinbase_tag_secondary": "e2e",
    "blake2b_activation_height": $ACTIVATION_HEIGHT,
    "blake2b_headline": "$HEADLINE"
  },
  "api": { "admin_password": "", "listen_port": $API_PORT, "modify_conf": false },
  "logger": { "log_to_console": true, "log_to_file": false, "log_level_console": 1 },
  "datum": {
    "pool_host": "127.0.0.1",
    "pool_port": $POOL_PORT,
    "pool_pubkey": "$PUBKEY",
    "pool_pass_workers": true,
    "pool_pass_full_users": true,
    "pooled_mining_only": true
  }
}
EOF
"$DATUM_GATEWAY" -c "$WORK/gateway.json" > "$WORK/gateway.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
    grep -q 'Stratum V1 Server Init complete' "$WORK/gateway.log" 2>/dev/null && break
    sleep 0.5
done
grep -q 'DATUM Server MOTD' "$WORK/gateway.log" \
    || fail "the gateway never completed the handshake; see $WORK/gateway.log"

step "mining with sia-test-miner until height $ACTIVATION_HEIGHT (up to ${TIMEOUT}s)"
"$ROOT/target/release/sia-test-miner" "127.0.0.1:$STRATUM_PORT" "$MINER_ADDRESS.rig1" \
    > "$WORK/miner.log" 2>&1 &
PIDS+=($!)

deadline=$((SECONDS + TIMEOUT))
started=$SECONDS
last_report=$SECONDS
while [ "$SECONDS" -lt "$deadline" ]; do
    height=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount 2>/dev/null || echo 0)
    [ "$height" -ge "$ACTIVATION_HEIGHT" ] && break
    if [ $((SECONDS - last_report)) -ge 30 ]; then
        last_report=$SECONDS
        printf '  %4ds: height %s of %s\n' $((SECONDS - started)) "$height" "$ACTIVATION_HEIGHT"
    fi
    sleep 2
done
[ "$height" -ge "$ACTIVATION_HEIGHT" ] \
    || fail "no block at height $ACTIVATION_HEIGHT within ${TIMEOUT}s; see $WORK/pool.log and $WORK/miner.log"

step "checking the activation block"
HASH=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockhash "$ACTIVATION_HEIGHT")
HEADER=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockheader "$HASH" false)
[ "${#HEADER}" = 328 ] || fail "the header is ${#HEADER} hex characters, not 328 (164 bytes)"

COINBASE=$("$BITCOIN_CLI" -datadir="$WORK/node" getblock "$HASH" 2 \
    | grep -m1 '"coinbase"' | cut -d'"' -f4)
HEADLINE_HEX=$(printf '%s' "$HEADLINE" | od -An -tx1 | tr -d ' \n')
case "$COINBASE" in
    *"$HEADLINE_HEX"*) ;;
    *) fail "the activation block's coinbase does not carry the headline" ;;
esac

grep -q "BLOCK at height $ACTIVATION_HEIGHT" "$WORK/pool.log" \
    || fail "the pool did not record a block at height $ACTIVATION_HEIGHT"
grep -q "$HASH" "$WORK/pool.log" \
    || fail "the block on the chain is not one the pool verified"
grep -q '<- accepted' "$WORK/pool.log" || fail "the pool accepted no shares"

ACCEPTED=$(grep -c '<- accepted' "$WORK/pool.log")
step "passed: height $ACTIVATION_HEIGHT is $HASH: a 164-byte header, headline in its coinbase"
printf 'shares accepted: %s\n' "$ACCEPTED"
printf 'ledger:\n'
# The ledger is a redb database; stop the pool to release its lock, then dump it as text.
kill "$POOL_PID" 2>/dev/null || true
sleep 1
"$ROOT/target/release/ratum-prime" --dump-ledger --ledger "$WORK/pool/regtest.redb" 2>/dev/null \
    || true
