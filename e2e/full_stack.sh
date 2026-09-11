#!/usr/bin/env bash
# Mine the first post-activation block through the whole stack, on regtest.
#
#   bitcoind (Knots, BLAKE2b branch) <- RPC - datum_gateway - DATUM -> ratum-prime - RPC -> bitcoind
#                                                  ^ sia-test-miner
#
# The pool's own tests cover the pool. This covers the parts only the real programs can:
# that the gateway accepts what the pool dictates and that a share the pool verifies is a
# block the node accepts. The node itself mines through the activation height first, as
# happened on mainnet; the stack serves only version 2 work.
#
# usage: e2e/full_stack.sh [--keep]
#
# Needs a Bitcoin Knots build with the BLAKE2b change; the gateway is this workspace's
# ratum-gateway crate unless DATUM_GATEWAY names another build (the C gateway, say):
#   BITCOIND        default ~/src/bitcoin/build/bin/bitcoind
#   BITCOIN_CLI     default ~/src/bitcoin/build/bin/bitcoin-cli
#   DATUM_GATEWAY   default the ratum-gateway crate in this workspace, built below
#   TIMEOUT         seconds to wait for the block, default 900
#   BLOCKS          pooled blocks to mine past the activation, default 1
#   GATEWAY_POOL_ADDRESS
#                   the gateway's mining.pool_address, default the miner's regtest address;
#                   the C gateway decodes bc1/tb1 only, so give it the tb1 form of one
#   PRIME_ARGS      extra ratum-prime flags, split on whitespace ("--abw-reveal-after 20"
#                   reveals each retired ABW slot 20 s after the rotation, so a short run
#                   exercises the gateway's reveal audit)
#
# Exits 0 only if the node accepted a block the pool verified.

set -euo pipefail

BITCOIND=${BITCOIND:-$HOME/src/bitcoin/build/bin/bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-$HOME/src/bitcoin/build/bin/bitcoin-cli}
DATUM_GATEWAY=${DATUM_GATEWAY:-}
TIMEOUT=${TIMEOUT:-900}
# PROTOCOL_V3=true (the default, as in the gateway) runs the whole stack on the version 3
# protocol: the gateway sends the DRS hello and version 3 config, and mines under the pool's
# anti-block-withholding assignment, which the pool submits blocks for. PROTOCOL_V3=false
# runs the version 1 protocol.
PROTOCOL_V3=${PROTOCOL_V3:-true}
BLOCKS=${BLOCKS:-1}
PRIME_ARGS=${PRIME_ARGS:-}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# BIP34 writes the height as a minimal push, which for a height of 16 or less is OP_N
# rather than a one-byte push, and the node requires OP_N. Activating above 16 keeps the
# test on the encoding real heights use.
ACTIVATION_HEIGHT=20
POOL_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
MINER_ADDRESS=bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lgth6c
GATEWAY_POOL_ADDRESS=${GATEWAY_POOL_ADDRESS:-$MINER_ADDRESS}

. "$(dirname "$0")/lib.sh"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratum-e2e-XXXXXX")

RPC_PORT=$(free_port 18400 150)
POOL_PORT=$(free_port 28900 90)
STRATUM_PORT=$(free_port 23300 90)
API_PORT=$(free_port 7100 90)
PIDS=()

trap cleanup EXIT

require_tools python3

DATUM_GATEWAY=${DATUM_GATEWAY:-$ROOT/target/release/ratum-gateway}
build_release

start_node

step "mining $ACTIVATION_HEIGHT blocks with the node, through the activation"
cli generatetoaddress "$ACTIVATION_HEIGHT" "$POOL_ADDRESS" \
    >/dev/null
height=$(cli getblockcount)
[ "$height" = "$ACTIVATION_HEIGHT" ] || fail "expected height $ACTIVATION_HEIGHT, got $height"
TARGET_HEIGHT=$((ACTIVATION_HEIGHT + BLOCKS))

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
    --coinbase-tag RATUM \
    --min-diff 1 --min-payout 1 --poll 1 \
    $PRIME_ARGS \
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
    "pool_address": "$GATEWAY_POOL_ADDRESS",
    "coinbase_tag_primary": "RATUM",
    "coinbase_tag_secondary": "e2e"
  },
  "api": { "admin_password": "", "listen_port": $API_PORT, "modify_conf": false },
  "logger": { "log_to_console": true, "log_to_file": false, "log_level_console": 1 },
  "datum": {
    "pool_host": "127.0.0.1",
    "pool_port": $POOL_PORT,
    "pool_pubkey": "$PUBKEY",
    "pool_pass_workers": true,
    "pool_pass_full_users": true,
    "pooled_mining_only": true,
    "protocol_v3": $PROTOCOL_V3
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

step "mining with sia-test-miner until height $TARGET_HEIGHT (up to ${TIMEOUT}s)"
"$ROOT/target/release/sia-test-miner" "127.0.0.1:$STRATUM_PORT" "$MINER_ADDRESS.rig1" \
    > "$WORK/miner.log" 2>&1 &
PIDS+=($!)

deadline=$((SECONDS + TIMEOUT))
started=$SECONDS
last_report=$SECONDS
while [ "$SECONDS" -lt "$deadline" ]; do
    height=$(cli getblockcount 2>/dev/null || echo 0)
    [ "$height" -ge "$TARGET_HEIGHT" ] && break
    if [ $((SECONDS - last_report)) -ge 30 ]; then
        last_report=$SECONDS
        printf '  %4ds: height %s of %s\n' $((SECONDS - started)) "$height" "$TARGET_HEIGHT"
    fi
    sleep 2
done
[ "$height" -ge "$TARGET_HEIGHT" ] \
    || fail "no block at height $TARGET_HEIGHT within ${TIMEOUT}s; see $WORK/pool.log and $WORK/miner.log"

step "checking the last pooled block"
HASH=$(cli getblockhash "$TARGET_HEIGHT")
HEADER=$(cli getblockheader "$HASH" false)
[ "${#HEADER}" = 328 ] || fail "the header is ${#HEADER} hex characters, not 328 (164 bytes)"

grep -q "BLOCK at height $TARGET_HEIGHT" "$WORK/pool.log" \
    || fail "the pool did not record a block at height $TARGET_HEIGHT"
grep -q "$HASH" "$WORK/pool.log" \
    || fail "the block on the chain is not one the pool verified"
grep -q '<- accepted' "$WORK/pool.log" || fail "the pool accepted no shares"

ACCEPTED=$(grep -c '<- accepted' "$WORK/pool.log")
step "passed: height $TARGET_HEIGHT is $HASH: a 164-byte header mined through the stack ($BLOCKS pooled block(s))"
printf 'shares accepted: %s\n' "$ACCEPTED"
printf 'ledger:\n'
# The ledger is a redb database; stop the pool to release its lock, then dump it as text.
kill "$POOL_PID" 2>/dev/null || true
sleep 1
"$ROOT/target/release/ratum-prime" --dump-ledger --ledger "$WORK/pool/regtest.redb" 2>/dev/null \
    || true
