#!/usr/bin/env bash
# Mine past the activation height with three concurrent miners spread across two gateways,
# on regtest, and check that the pool credits each miner separately and divides the coinbase
# in proportion to the difficulty each contributed.
#
#                              datum_gateway A - DATUM -> ratum-prime -> RPC
#   bitcoind (Knots, BLAKE2b) <       ^ alice                  |
#                       ^ RPC  datum_gateway B - DATUM --------+
#                                     ^  ^ bob, carol
#
# full_stack.sh runs one miner behind one gateway and proves the stack produces a block the
# node accepts. This runs three miners, each with its own payout address, behind two
# gateways, and checks the accounting that only appears when more than one miner is present:
# that shares are attributed per identity, that the coinbaser outputs match the pro-rata
# split of the share window, and that the amount the pool recorded for a block equals the
# amount its coinbase pays out on chain.
#
# Two gateways rather than one because the pool keeps its jobs, its tip and its tip grace
# (`TIP_GRACE_SECS`) per connection. One gateway exercises one instance of that state. Two
# produce the case that only a real deployment has: a block found behind one gateway replaces
# the tip for the other's session, so work that was current when it was issued goes stale
# through no act of the miner doing it.
#
# usage: tests/e2e/multi_miner.sh [--keep]
#
# Needs a Bitcoin Knots build with the BLAKE2b change; the gateway is this workspace's
# ratum-gateway crate unless DATUM_GATEWAY names another build (the C gateway, say):
#   BITCOIND        default ~/src/bitcoin/build/bin/bitcoind
#   BITCOIN_CLI     default ~/src/bitcoin/build/bin/bitcoin-cli
#   DATUM_GATEWAY   default the ratum-gateway crate in this workspace, built below
#   SHARE_COUNT     shares to accumulate before checking, default 6
#   TIMEOUT         seconds to wait for them, default 5400
#
# Exits 0 only if every accepted share was credited to the miner that submitted it and every
# post-activation coinbase paid out the split the ledger dictates.

set -euo pipefail

BITCOIND=${BITCOIND:-$HOME/src/bitcoin/build/bin/bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-$HOME/src/bitcoin/build/bin/bitcoin-cli}
DATUM_GATEWAY=${DATUM_GATEWAY:-}
SHARE_COUNT=${SHARE_COUNT:-6}
TIMEOUT=${TIMEOUT:-5400}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

ACTIVATION_HEIGHT=20
HEADLINE="RATUM multi miner test"

# Four distinct addresses. The three miners are paid by the pool out of the share window;
# the gateway is configured with a fourth for the remainder, so that a miner's payout and
# the remainder are never written to the same output and can be distinguished on chain.
ALICE=bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc
BOB=bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a
CAROL=bcrt1qc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rpz2hyw
GATEWAY_ADDRESS=bcrt1q6n2df4x56n2df4x56n2df4x56n2df4x5jumwup
POOL_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080

# The share window is set far above the work this run produces, so no share is trimmed and
# the split for every block is computable from a prefix of shares.log.
WINDOW_FLOOR=1048576
MIN_PAYOUT=1

# Each miner sizes its thread pool from its CPU affinity, so pinning gives the three
# different hash rates and an unequal split to check.
CORES=$(nproc)
ALICE_CPUS=0-$(( CORES / 2 - 1 ))
BOB_CPUS=$(( CORES / 2 ))-$(( CORES * 5 / 6 - 1 ))
CAROL_CPUS=$(( CORES * 5 / 6 ))-$(( CORES - 1 ))

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratum-multi-XXXXXX")

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
STRATUM_PORT_A=$(free_port 23300 90)
STRATUM_PORT_B=$(free_port 23400 90)
API_PORT_A=$(free_port 7100 90)
API_PORT_B=$(free_port 7200 90)
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
for tool in jq taskset python3; do
    command -v "$tool" >/dev/null || fail "$tool is not on PATH"
done

# ledger::split in Python, to check the coinbase against. Which prefix of shares.log the
# window was is not fixed: a gateway requests a coinbaser only for the jobs whose state sets
# `need_coinbaser` (datum_stratum.c), builds the other jobs without a new request, and
# each gateway holds its own. So try every prefix and report the match.
cat > "$WORK/match_split.py" <<'MATCHPY'
import sys

ledger, max_prefix, value, min_payout = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
)

paid = {}
for line in sys.stdin:
    if line.split():
        identity, amount = line.split()
        paid[identity] = int(amount)


def split(work, total):
    out = {}
    if total == 0 or value == 0:
        return out
    kept = sorted(work.items(), key=lambda kv: (-kv[1], kv[0]))
    left_work = total
    while kept and value * kept[-1][1] // left_work < min_payout:
        left_work -= kept[-1][1]
        kept.pop()
    left = value
    for identity, w in kept:
        if left_work == 0:
            break
        amount = left * w // left_work
        left -= amount
        left_work -= w
        if amount:
            out[identity] = amount
    return out


with open(ledger) as f:
    shares = [line.split() for line in f]

work, total = {}, 0
for prefix in range(0, max_prefix + 1):
    if prefix:
        parts = shares[prefix - 1]
        if len(parts) == 4:
            identity = parts[2].split('.')[0]
            work[identity] = work.get(identity, 0) + int(parts[1])
            total += int(parts[1])
    if split(work, total) == paid:
        print(prefix)
        break
else:
    sys.exit(1)
MATCHPY

DATUM_GATEWAY=${DATUM_GATEWAY:-$ROOT/target/release/ratum-gateway}
step "building the pool, the gateway and the test miner"
(cd "$ROOT" && cargo build --workspace --release --bin ratum-prime --bin sia-test-miner --bin ratum-gateway) || fail "cargo build"

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

for address in "$ALICE" "$BOB" "$CAROL" "$GATEWAY_ADDRESS" "$POOL_ADDRESS"; do
    valid=$("$BITCOIN_CLI" -datadir="$WORK/node" validateaddress "$address" | jq -r .isvalid)
    [ "$valid" = "true" ] || fail "$address is not an address this node accepts"
done

step "mining $((ACTIVATION_HEIGHT - 1)) blocks before the fork, with SHA256d"
"$BITCOIN_CLI" -datadir="$WORK/node" generatetoaddress $((ACTIVATION_HEIGHT - 1)) "$POOL_ADDRESS" >/dev/null
height=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount)
[ "$height" = "$((ACTIVATION_HEIGHT - 1))" ] || fail "expected height $((ACTIVATION_HEIGHT - 1)), got $height"

step "starting ratum-prime on port $POOL_PORT, window floor $WINDOW_FLOOR"
mkdir -p "$WORK/pool"
# "<- accepted" is logged at debug, which the default info level would not print, and every
# accounting check below reads those lines.
RUST_LOG="${RUST_LOG:-debug}" \
"$ROOT/target/release/ratum-prime" \
    --listen "127.0.0.1:$POOL_PORT" \
    --data-dir "$WORK/pool" \
    --rpc "http://127.0.0.1:$RPC_PORT" --rpc-user ratum --rpc-pass ratumtest \
    --payout-address "$POOL_ADDRESS" \
    --min-diff 1 --min-payout "$MIN_PAYOUT" --poll 1 --window-floor "$WINDOW_FLOOR" \
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

start_gateway() {
    local name=$1 stratum_port=$2 api_port=$3
    cat > "$WORK/gateway-$name.json" <<EOF
{
  "bitcoind": {
    "rpcuser": "ratum",
    "rpcpassword": "ratumtest",
    "rpcurl": "http://127.0.0.1:$RPC_PORT",
    "notify_fallback": true
  },
  "stratum": { "listen_port": $stratum_port, "vardiff_min": 1, "vardiff_target_shares_min": 4 },
  "mining": {
    "pool_address": "$GATEWAY_ADDRESS",
    "coinbase_tag_primary": "RATUM",
    "coinbase_tag_secondary": "$name",
    "blake2b_activation_height": $ACTIVATION_HEIGHT,
    "blake2b_headline": "$HEADLINE"
  },
  "api": { "admin_password": "", "listen_port": $api_port, "modify_conf": false },
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
    "$DATUM_GATEWAY" -c "$WORK/gateway-$name.json" > "$WORK/gateway-$name.log" 2>&1 &
    PIDS+=($!)

    for _ in $(seq 1 60); do
        grep -q 'Stratum V1 Server Init complete' "$WORK/gateway-$name.log" 2>/dev/null && break
        sleep 0.5
    done
    grep -q 'DATUM Server MOTD' "$WORK/gateway-$name.log" \
        || fail "gateway $name never completed the handshake; see $WORK/gateway-$name.log"
}

step "starting gateway A on stratum port $STRATUM_PORT_A"
start_gateway A "$STRATUM_PORT_A" "$API_PORT_A"
step "starting gateway B on stratum port $STRATUM_PORT_B"
start_gateway B "$STRATUM_PORT_B" "$API_PORT_B"

# Each gateway holds its own DATUM session, and the pool prefixes every connection log line with the
# peer address of the session it belongs to.
sessions=$(grep -c 'hello ok:' "$WORK/pool.log" || true)
[ "$sessions" -ge 2 ] || fail "the pool completed $sessions handshake(s), not 2; see $WORK/pool.log"

# alice behind one gateway and bob with carol behind the other splits the machine evenly
# between the two sessions, so each gateway finds roughly half the blocks and each one
# regularly invalidates the work the other has outstanding.
step "starting miners: alice on gateway A, bob and carol on gateway B"
MINERS=()
start_miner() {
    local address=$1 cpus=$2 name=$3 port=$4
    taskset -c "$cpus" "$ROOT/target/release/sia-test-miner" \
        "127.0.0.1:$port" "$address.rig" > "$WORK/miner-$name.log" 2>&1 &
    PIDS+=($!)
    MINERS+=($!)
}
start_miner "$ALICE" "$ALICE_CPUS" alice "$STRATUM_PORT_A"
start_miner "$BOB" "$BOB_CPUS" bob "$STRATUM_PORT_B"
start_miner "$CAROL" "$CAROL_CPUS" carol "$STRATUM_PORT_B"

# The ledger is a redb database the running pool holds an exclusive lock on, so it cannot be
# read while the pool runs. During mining, count and attribute accepted shares from the pool
# log ("<- accepted ...; <user> credited"); after the pool is stopped, dump the database to a
# text file the checks below read.
LEDGER_DB="$WORK/pool/regtest.redb"
LEDGER="$WORK/pool/shares.txt"
# A share is 2^32 BLAKE2b hashes (difficulty 1 is the protocol's floor), so each one costs a
# CPU miner tens of seconds.
step "accumulating $SHARE_COUNT shares (up to ${TIMEOUT}s)"
# Wait for the target, and for every miner to hold at least one share, so that the split
# being checked is a split between three miners rather than however many had found one.
deadline=$((SECONDS + TIMEOUT))
started=$SECONDS
last_report=$SECONDS
recorded=0
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ $((SECONDS - last_report)) -ge 30 ]; then
        last_report=$SECONDS
        printf '  %4ds: %s/%s shares accepted at height %s\n' $((SECONDS - started)) "$recorded" "$SHARE_COUNT" \
            "$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount 2>/dev/null || echo '?')"
    fi
    recorded=$(grep -c '<- accepted' "$WORK/pool.log" 2>/dev/null || echo 0)
    if [ "$recorded" -ge "$SHARE_COUNT" ]; then
        all=1
        for miner in "$ALICE" "$BOB" "$CAROL"; do
            grep -q "<- accepted .*$miner" "$WORK/pool.log" || all=0
        done
        [ "$all" = 1 ] && break
    fi
    sleep 2
done
[ "$recorded" -ge "$SHARE_COUNT" ] \
    || fail "only $recorded shares in ${TIMEOUT}s, wanted $SHARE_COUNT; see $WORK/pool.log"

# Stop the miners, then the pool, so no share is credited after the last block on the chain
# and the pool releases the ledger's lock; then dump the ledger to a text file.
for pid in "${MINERS[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 2
kill "$POOL_PID" 2>/dev/null || true
sleep 2
"$ROOT/target/release/ratum-prime" --dump-ledger --ledger "$LEDGER_DB" > "$LEDGER" \
    || fail "could not dump the ledger $LEDGER_DB"

step "shares recorded per miner"
awk '{ split($3, u, "."); work[u[1]] += $2; count[u[1]]++ }
     END { for (m in work) printf "  %-45s %3d shares %6d work\n", m, count[m], work[m] }' \
    "$LEDGER" | sort -k2

for miner in "$ALICE" "$BOB" "$CAROL"; do
    grep -q " $miner " "$LEDGER" || fail "$miner submitted no share the pool credited"
done

step "every accepted share was credited to the miner that submitted it"
accepted=$(grep -c '<- accepted' "$WORK/pool.log" || true)
[ "$accepted" = "$(wc -l < "$LEDGER")" ] \
    || fail "the pool accepted $accepted shares but wrote $(wc -l < "$LEDGER") ledger lines"

# Every acceptance names the user that submitted the share, its difficulty and
# the hash it produced. The ledger line for that hash must carry the same difficulty and the
# identity part of that user.
sed -n 's/.*<- accepted diff=\([0-9]*\) hash=\([0-9a-f]*\).*; \([^ ]*\) credited.*/\2 \1 \3/p' \
    "$WORK/pool.log" | sed 's/\.[^ ]*$//' | sort > "$WORK/accepted.txt"
awk '{ split($3, u, "."); print $4, $2, u[1] }' "$LEDGER" | sort > "$WORK/credited.txt"
[ "$(wc -l < "$WORK/accepted.txt")" = "$accepted" ] \
    || fail "an acceptance line did not name its difficulty, hash and miner"
diff -u "$WORK/accepted.txt" "$WORK/credited.txt" > "$WORK/credit.diff" \
    || fail "the shares the pool accepted are not the shares it credited; see $WORK/credit.diff"
printf '  %s shares accepted, each credited to its submitter at its difficulty\n' "$accepted"

step "both gateways delivered shares the pool credited"
# The pool prefixes each message with the peer address of the session it came in on, so the
# distinct addresses across the accepted shares are the sessions that contributed work. The
# env_logger prefix is bracketed too and comes first, so match the address by its pattern
# (`[digits.digits:port]`) rather than by position.
contributing=$(grep '<- accepted' "$WORK/pool.log" \
    | sed -n 's/.*\[\([0-9.]*:[0-9]*\)\].*/\1/p' | sort -u | wc -l)
[ "$contributing" -ge 2 ] \
    || fail "credited shares came from $contributing session(s); the second gateway contributed none"
printf '  %s sessions contributed credited shares\n' "$contributing"

step "each block pays out what the pool recorded for it"
checked=0
proportional=0
for h in $(seq "$ACTIVATION_HEIGHT" "$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount)"); do
    hash=$("$BITCOIN_CLI" -datadir="$WORK/node" getblockhash "$h")
    block=$("$BITCOIN_CLI" -datadir="$WORK/node" getblock "$hash" 2)

    # What the pool recorded when it accepted the share that solved this block.
    line=$(grep "<- accepted .*hash=$hash" "$WORK/pool.log" || true)
    [ -n "$line" ] || fail "the pool has no acceptance line for the block at height $h"
    split_sats=$(sed -n 's/.*split=\([0-9]*\).*/\1/p' <<<"$line")

    # What its coinbase pays the three miners on chain.
    paid=$(jq -r --arg a "$ALICE" --arg b "$BOB" --arg c "$CAROL" '
        .tx[0].vout[] | select(.scriptPubKey.address == $a or .scriptPubKey.address == $b
                               or .scriptPubKey.address == $c)
        | "\(.scriptPubKey.address) \((.value * 100000000) | round)"' <<<"$block")
    paid_total=$(awk '{ t += $2 } END { print t + 0 }' <<<"$paid")
    [ "$paid_total" = "$split_sats" ] \
        || fail "height $h: the pool recorded split=$split_sats but the coinbase pays $paid_total"

    # The split itself, against the ledger as it stood when the template was built. That is
    # the shares before this block's own, allowing for a template built one share earlier.
    k=$(grep -n " $hash\$" "$LEDGER" | cut -d: -f1)
    [ -n "$k" ] || fail "height $h: no ledger line records the share that solved $hash"
    value=$(jq -r '[.tx[0].vout[].value] | add | . * 100000000 | round' <<<"$block")
    matched=$(printf '%s\n' "$paid" \
        | python3 "$WORK/match_split.py" "$LEDGER" "$((k - 1))" "$value" "$MIN_PAYOUT") || matched=""
    checked=$((checked + 1))
    if [ -n "$matched" ]; then
        proportional=$((proportional + 1))
        printf '  height %-3s %s sats to %s miner(s), pro rata over %s shares\n' \
            "$h" "$split_sats" "$(grep -c . <<<"$paid")" "$matched"
    else
        printf '  height %-3s %s sats to %s miner(s), NOT the split of any recent window\n' \
            "$h" "$split_sats" "$(grep -c . <<<"$paid")"
    fi
done

[ "$proportional" = "$checked" ] \
    || fail "$((checked - proportional)) of $checked coinbases did not match the ledger split"

step "passed: $checked blocks, each crediting its miner and paying the window pro rata"
printf 'ledger:\n'
cat "$LEDGER"
