# Setup every e2e script shares: a regtest node with BLAKE2b active at a chosen height, a way
# to pick ports nothing else holds, and one cleanup that stops what the script started.
#
# Sourced, not run. The caller sets BITCOIND, BITCOIN_CLI, ROOT, WORK, KEEP, PIDS and
# ACTIVATION_HEIGHT before calling anything here, and installs the trap itself:
#
#   . "$(dirname "$0")/lib.sh"
#   PIDS=()
#   trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# The node's own RPC, which every script reaches the same way.
cli() { "$BITCOIN_CLI" -datadir="$WORK/node" "$@"; }

# Stops the node and everything else the script started, and keeps or removes its logs.
cleanup() {
    local status=$?
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    cli stop >/dev/null 2>&1 || true
    sleep 1
    if [ "$KEEP" = 1 ]; then
        printf '\nlogs kept in %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
    exit $status
}

# A port nothing else is holding, from the span starting at $1 and $2 wide. Picking one at
# random collides with whatever else is on the machine, and a collision is reported as a
# program that exits during startup rather than as a message naming the port, so bind the
# port first to check that it is free.
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

# Refuses to start unless every program the run needs is there. The named executables are
# checked as paths, the rest as commands on PATH.
require_tools() {
    for tool in "$BITCOIND" "$BITCOIN_CLI" ${DATUM_GATEWAY:+"$DATUM_GATEWAY"}; do
        [ -x "$tool" ] || fail "$tool is not executable; set BITCOIND, BITCOIN_CLI or DATUM_GATEWAY"
    done
    for tool in "$@"; do
        command -v "$tool" >/dev/null || fail "$tool is not on PATH"
    done
}

build_release() {
    step "building the pool, the gateway and the test miner"
    (cd "$ROOT" && cargo build --workspace --release \
        --bin ratum-prime --bin sia-test-miner --bin ratum-gateway) || fail "cargo build"
}

# A regtest node in $WORK/node, listening for RPC on $RPC_PORT, with BLAKE2b activating at
# $ACTIVATION_HEIGHT. Returns once the node answers RPC.
start_node() {
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
blake2b_headline=RATUM e2e headline
EOF
    "$BITCOIND" -datadir="$WORK/node" > "$WORK/bitcoind.log" 2>&1 &
    PIDS+=($!)

    for _ in $(seq 1 60); do
        cli getblockchaininfo >/dev/null 2>&1 && break
        sleep 0.5
    done
    cli getblockchaininfo >/dev/null || fail "the node never responded on port $RPC_PORT"
}
