#!/usr/bin/env bash
# Mine past the activation height with two gateways on regtest, one charging a Gateway fee
# and one charging nothing, and check that the pool credits the fee address exactly the
# portion of the paying gateway's work that datum.gateway_fee_bps names, and none of the
# other gateway's.
#
#                              datum_gateway A (fee 50%, require_address_username)
#   bitcoind (Knots, BLAKE2b) <    ^ alice, lazyminer          |
#                       ^ RPC  datum_gateway B (no fee) - DATUM +-> ratum-prime -> RPC
#                                     ^ bob
#
# usage: tests/e2e/gateway_fee.sh [--keep]
#
# Needs a Bitcoin Knots build with the BLAKE2b change; the gateway is this workspace's
# ratum-gateway crate unless DATUM_GATEWAY names another build (the C gateway, say):
#   BITCOIND        default ~/src/bitcoin/build/bin/bitcoind
#   BITCOIN_CLI     default ~/src/bitcoin/build/bin/bitcoin-cli
#   DATUM_GATEWAY   default the ratum-gateway crate in this workspace, built below
#   ALICE_SHARES    shares from the paying miner before checking, default 6
#   BOB_SHARES      shares from the miner on the free gateway, default 2
#   TIMEOUT         seconds to wait for them, default 5400
#
# Exits 0 only if the fee address was credited half of gateway A's work to within one share,
# gateway B's miner paid nothing, and the miner whose username is not an address was refused.

set -euo pipefail

BITCOIND=${BITCOIND:-$HOME/src/bitcoin/build/bin/bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-$HOME/src/bitcoin/build/bin/bitcoin-cli}
DATUM_GATEWAY=${DATUM_GATEWAY:-}
ALICE_SHARES=${ALICE_SHARES:-6}
BOB_SHARES=${BOB_SHARES:-2}
TIMEOUT=${TIMEOUT:-5400}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

ACTIVATION_HEIGHT=20
HEADLINE="RATUM gateway fee test"

# 5000 basis points: half of each miner's work on gateway A. A rate this high is what makes
# the check exact over the few shares a CPU miner produces; the accounting is the same at any
# rate.
FEE_BPS=5000

ALICE=bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc
BOB=bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a
FEE_ADDRESS=bcrt1qc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rpz2hyw
GATEWAY_ADDRESS=bcrt1q6n2df4x56n2df4x56n2df4x56n2df4x5jumwup
POOL_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
LAZY_USER=lazyminer

# Every share is difficulty 1: the pool's floor is 1 and the vardiff target is set so far
# above what a CPU miner reaches that the Gateway never raises it. Equal difficulties make
# the fee an exact count of shares rather than a ratio of work that only converges.
WINDOW_FLOOR=1048576
MIN_PAYOUT=1
VARDIFF_TARGET=4

CORES=$(nproc)
ALICE_CPUS=0-$(( CORES / 2 - 1 ))
BOB_CPUS=$(( CORES / 2 ))-$(( CORES * 3 / 4 - 1 ))
LAZY_CPUS=$(( CORES * 3 / 4 ))-$(( CORES - 1 ))

ROOT=${ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratum-fee-XXXXXX")

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

DATUM_GATEWAY=${DATUM_GATEWAY:-$ROOT/target/release/ratum-gateway}
step "building the pool, the gateway and the test miner"
(cd "$ROOT" && cargo build --workspace --release --bin ratum-prime --bin sia-test-miner --bin ratum-gateway) || fail "cargo build"

step "starting a regtest node with BLAKE2b active at height $ACTIVATION_HEIGHT"
mkdir -p "$WORK/node"
cat > "$WORK/node/bitcoin.conf" <<EOF
regtest=1
server=1
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
"$BITCOIN_CLI" -datadir="$WORK/node" generatetoaddress $((ACTIVATION_HEIGHT - 1)) "$POOL_ADDRESS" >/dev/null

step "starting ratum-prime on port $POOL_PORT"
mkdir -p "$WORK/pool"
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
grep -q 'listening on' "$WORK/pool.log" \
    || fail "the pool never listened on 127.0.0.1:$POOL_PORT; see $WORK/pool.log"
PUBKEY=$(awk '{for (i = 1; i < NF; i++) if ($i == "pool_pubkey:") {print $(i + 1); exit}}' \
    "$WORK/pool.log")
[ -n "$PUBKEY" ] || fail "the pool never printed its public key; see $WORK/pool.log"

# Gateway A is the public one: it charges a fee and refuses a username the pool could not
# pay. Gateway B is what a miner runs beside its own node: neither option is set, so its
# configuration is the one this build ships with.
start_gateway() {
    local name=$1 stratum_port=$2 api_port=$3 fee_json=$4 stratum_json=$5
    cat > "$WORK/gateway-$name.json" <<EOF
{
  "bitcoind": {
    "rpcuser": "ratum",
    "rpcpassword": "ratumtest",
    "rpcurl": "http://127.0.0.1:$RPC_PORT",
    "notify_fallback": true
  },
  "stratum": {
    "listen_port": $stratum_port,
    "vardiff_min": 1,
    "vardiff_target_shares_min": $VARDIFF_TARGET$stratum_json
  },
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
    "pooled_mining_only": true$fee_json
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

step "starting gateway A on stratum port $STRATUM_PORT_A, fee $FEE_BPS bps to $FEE_ADDRESS"
start_gateway A "$STRATUM_PORT_A" "$API_PORT_A" ",
    \"gateway_fee_bps\": $FEE_BPS,
    \"gateway_fee_address\": \"$FEE_ADDRESS\"" ",
    \"require_address_username\": true"
grep -q "Gateway fee: $FEE_BPS basis points" "$WORK/gateway-A.log" \
    || fail "gateway A did not report the configured fee; see $WORK/gateway-A.log"

step "starting gateway B on stratum port $STRATUM_PORT_B, no fee"
start_gateway B "$STRATUM_PORT_B" "$API_PORT_B" "" ""
if grep -q "Gateway fee:" "$WORK/gateway-B.log"; then
    fail "gateway B reported a fee it was not configured with; see $WORK/gateway-B.log"
fi

step "starting miners: alice and $LAZY_USER on gateway A, bob on gateway B"
MINERS=()
start_miner() {
    local user=$1 cpus=$2 name=$3 port=$4
    taskset -c "$cpus" "$ROOT/target/release/sia-test-miner" \
        "127.0.0.1:$port" "$user" > "$WORK/miner-$name.log" 2>&1 &
    PIDS+=($!)
    MINERS+=($!)
}
start_miner "$ALICE.rig" "$ALICE_CPUS" alice "$STRATUM_PORT_A"
start_miner "$LAZY_USER.rig" "$LAZY_CPUS" lazy "$STRATUM_PORT_A"
start_miner "$BOB.rig" "$BOB_CPUS" bob "$STRATUM_PORT_B"

LEDGER_DB="$WORK/pool/regtest.redb"
LEDGER="$WORK/pool/shares.txt"

# A share is 2^32 BLAKE2b hashes (difficulty 1 is the protocol's floor), so each one costs a
# CPU miner tens of seconds; the counts above are the fewest that make the checks exact.
step "accumulating $ALICE_SHARES shares from alice and $BOB_SHARES from bob (up to ${TIMEOUT}s)"
deadline=$((SECONDS + TIMEOUT))
started=$SECONDS
last_report=$SECONDS
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ $((SECONDS - last_report)) -ge 30 ]; then
        last_report=$SECONDS
        printf '  %4ds: alice %s/%s, fee %s, bob %s/%s, %s refused at height %s\n' \
            $((SECONDS - started)) "${alice_n:-0}" "$ALICE_SHARES" "${fee_n:-0}" "${bob_n:-0}" "$BOB_SHARES" "$LAZY_USER" \
            "$("$BITCOIN_CLI" -datadir="$WORK/node" getblockcount 2>/dev/null || echo '?')"
    fi
    alice_n=$(grep -c "<- accepted .*; $ALICE" "$WORK/pool.log" 2>/dev/null || true)
    bob_n=$(grep -c "<- accepted .*; $BOB" "$WORK/pool.log" 2>/dev/null || true)
    fee_n=$(grep -c "<- accepted .*; $FEE_ADDRESS" "$WORK/pool.log" 2>/dev/null || true)
    lazy_rejects=$(grep -c 'unauthorized-worker' "$WORK/miner-lazy.log" 2>/dev/null || true)
    if [ "$alice_n" -ge "$ALICE_SHARES" ] && [ "$bob_n" -ge "$BOB_SHARES" ] \
       && [ "$fee_n" -ge 1 ] && [ "$lazy_rejects" -ge 1 ]; then
        break
    fi
    sleep 2
done
printf '  alice %s, fee %s, bob %s, rejected shares from %s: %s\n' \
    "$alice_n" "$fee_n" "$bob_n" "$LAZY_USER" "$lazy_rejects"
[ "$alice_n" -ge "$ALICE_SHARES" ] || fail "alice produced $alice_n shares in ${TIMEOUT}s, wanted $ALICE_SHARES"
[ "$bob_n" -ge "$BOB_SHARES" ] || fail "bob produced $bob_n shares in ${TIMEOUT}s, wanted $BOB_SHARES"
[ "$fee_n" -ge 1 ] || fail "no share was credited to the fee address $FEE_ADDRESS"
[ "$lazy_rejects" -ge 1 ] \
    || fail "gateway A never rejected a share from $LAZY_USER; see $WORK/miner-lazy.log"

for pid in "${MINERS[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 2
kill "$POOL_PID" 2>/dev/null || true
sleep 2
"$ROOT/target/release/ratum-prime" --dump-ledger --ledger "$LEDGER_DB" > "$LEDGER" \
    || fail "could not dump the ledger $LEDGER_DB"

step "work credited per identity"
awk '{ split($3, u, "."); work[u[1]] += $2; count[u[1]]++ }
     END { for (m in work) printf "  %-45s %3d shares %6d work\n", m, count[m], work[m] }' \
    "$LEDGER" | sort -k2

alice_work=$(awk -v a="$ALICE" '{ split($3, u, "."); if (u[1] == a) w += $2 } END { print w + 0 }' "$LEDGER")
fee_work=$(awk -v a="$FEE_ADDRESS" '{ split($3, u, "."); if (u[1] == a) w += $2 } END { print w + 0 }' "$LEDGER")
bob_work=$(awk -v a="$BOB" '{ split($3, u, "."); if (u[1] == a) w += $2 } END { print w + 0 }' "$LEDGER")
max_diff=$(awk '{ if ($2 > m) m = $2 } END { print m + 0 }' "$LEDGER")

step "the fee address was credited $FEE_BPS basis points of gateway A's work"
# The fee is charged on what the Gateway submits, which is not the same as what the pool
# credits: a share the pool rejects was charged the same as one it accepted. So measure
# against everything gateway A's session sent, accepted or not, and allow the fee to have
# landed on a rejected share. The pool prefixes each line with the session's peer address,
# and a rejection does not name a difficulty, so count those at the largest difficulty
# credited.
fee_peer=$(grep "<- accepted .*; $FEE_ADDRESS" "$WORK/pool.log" \
    | sed -n 's/.*\[\([0-9.]*:[0-9]*\)\].*/\1/p' | sort -u | head -1)
[ -n "$fee_peer" ] || fail "no share credited to the fee address names a session"
accepted_a=$(grep "<- accepted" "$WORK/pool.log" | grep -c "\[$fee_peer\]" || true)
rejected_a=$(grep "<- rejected" "$WORK/pool.log" | grep -c "\[$fee_peer\]" || true)
submitted_work=$(( alice_work + fee_work + rejected_a * max_diff ))
[ "$submitted_work" -gt 0 ] || fail "gateway A produced no credited work"
# work_owed carries what the fee has taken and not yet charged, so the charge is within one
# share of the rate whatever difficulty each share was served at.
lo=$(( submitted_work * FEE_BPS / 10000 - max_diff - rejected_a * max_diff ))
hi=$(( submitted_work * FEE_BPS / 10000 + max_diff ))
[ "$fee_work" -ge "$lo" ] && [ "$fee_work" -le "$hi" ] \
    || fail "the fee address holds $fee_work of the $submitted_work work gateway A submitted; expected $lo to $hi"
printf '  %s of the %s work gateway A submitted (%s accepted, %s rejected), within one share (%s) of %s bps\n' \
    "$fee_work" "$submitted_work" "$accepted_a" "$rejected_a" "$max_diff" "$FEE_BPS"

step "the miner on the gateway with no fee paid nothing"
[ "$bob_work" -gt 0 ] || fail "bob produced no credited work"
# Every share credited to the fee address came in on gateway A's session, so none of bob's
# work was taken. The pool prefixes each line with the peer address of the session.
fee_peers=$(grep "<- accepted .*; $FEE_ADDRESS" "$WORK/pool.log" \
    | sed -n 's/.*\[\([0-9.]*:[0-9]*\)\].*/\1/p' | sort -u)
bob_peers=$(grep "<- accepted .*; $BOB" "$WORK/pool.log" \
    | sed -n 's/.*\[\([0-9.]*:[0-9]*\)\].*/\1/p' | sort -u)
[ "$(wc -l <<<"$fee_peers")" = 1 ] \
    || fail "shares credited to the fee address arrived on more than one session: $fee_peers"
if comm -12 <(printf '%s\n' "$fee_peers") <(printf '%s\n' "$bob_peers") | grep -q .; then
    fail "a share from bob's gateway was credited to the fee address"
fi
printf '  bob holds %s work, all of it his own\n' "$bob_work"

step "the miner whose username is not an address was refused"
grep -q "Refusing authorization of \"$LAZY_USER" "$WORK/gateway-A.log" \
    || fail "gateway A did not refuse to authorize $LAZY_USER; see $WORK/gateway-A.log"
if grep -q "$LAZY_USER" "$LEDGER"; then
    fail "the pool credited work to $LAZY_USER; gateway A should have rejected those shares"
fi
# A share that solves a block is submitted before the username is checked, since a block is
# worth relaying whoever found it. On regtest the network target is easier than the share
# target, so nearly every share is a block and some of this miner's shares do reach the pool,
# which rejects them as unpayable. What the check prevents is work being credited to a
# username no coinbase output can pay, and that is what is asserted above.
printf '  %s was refused at authorization, rejected %s shares, and was credited no work\n' \
    "$LAZY_USER" "$lazy_rejects"

step "PASS"
