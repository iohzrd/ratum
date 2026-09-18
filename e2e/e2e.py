#!/usr/bin/env python3
"""End-to-end runs of the whole stack on regtest.

  bitcoind (Knots, BLAKE2b branch) <- RPC - ratum-gateway - DATUM -> ratum-prime - RPC -> bitcoind
                                                  ^ sia-test-miner

The pool's own tests cover the pool. These runs cover what only the real programs can: that
the gateway accepts what the pool dictates, that a share the pool verifies is a block the
node accepts, and the accounting that appears only with several miners. The node itself
mines through the activation height first, as happened on mainnet; the stack serves only
version 2 work.

  e2e/e2e.py full-stack          the activation block through one gateway and one miner
  e2e/e2e.py multi-miner         three miners behind two gateways: credit and payout split
  e2e/e2e.py public-gateway-fee  a tagged gateway's shares charged, the fee paid to the
                                 other gateway's miner

Every run needs a Bitcoin Knots build with the BLAKE2b change, named by BITCOIND and
BITCOIN_CLI (default ~/src/bitcoin/build/bin/); the gateway is this workspace's
ratum-gateway crate, built here, unless DATUM_GATEWAY or --gateway names another build (the
C gateway, say). --keep leaves the work directory with every log. A run exits 0 only when
each of its checks passed.
"""

import argparse
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# BIP34 writes the height as a minimal push, which for a height of 16 or less is OP_N rather
# than a one-byte push, and the node requires OP_N. Activating above 16 keeps the runs on the
# encoding real heights use.
ACTIVATION_HEIGHT = 20

POOL_ADDRESS = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
MINER_ADDRESS = "bcrt1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3lgth6c"
# Distinct addresses for the multi-miner runs: the miners are paid by the pool out of the
# share window, and the gateways are configured with another address for the remainder, so
# that a miner's payout and the remainder are never written to the same output and can be
# distinguished on chain.
ALICE = "bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc"
BOB = "bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a"
CAROL = "bcrt1qc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rpz2hyw"
GATEWAY_ADDRESS = "bcrt1q6n2df4x56n2df4x56n2df4x56n2df4x5jumwup"

# The share window is set far above the work a run produces, so no share is trimmed and the
# split for every block is computable from a prefix of the ledger.
WINDOW_FLOOR = 1 << 20
MIN_PAYOUT = 1

SATS_PER_BTC = 100_000_000
MAX_OUTPUTS = 512
BASIS_POINTS = 10_000
STARTUP_WAIT = 30.0
PROGRESS_INTERVAL = 30.0


class Failed(Exception):
    """A check that did not pass; its message names what and where to look."""


def step(text: str) -> None:
    print(f"\n=== {text}", flush=True)


def fail(text: str) -> None:
    raise Failed(text)


def free_port(base: int, span: int) -> int:
    """A port nothing else holds, from the span starting at `base`. Picking one at random
    collides with whatever else is on the machine, and a collision is reported as a program
    that exits during startup rather than as a message naming the port, so bind first."""
    for _ in range(200):
        port = base + random.randrange(span)
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            probe.close()
        return port
    fail(f"no free port in {base}..{base + span}")


def sats(btc: Decimal) -> int:
    return int((btc * SATS_PER_BTC).to_integral_value())


@dataclass
class Share:
    """One line of the pool's dumped ledger: "at difficulty identity hash tag", the tag
    empty for a share without one."""

    accepted_at: int
    difficulty: int
    identity: str
    block_hash: str
    tag: str

    @classmethod
    def parse(cls, line: str) -> "Share":
        parts = line.split()
        return cls(
            int(parts[0]),
            int(parts[1]),
            parts[2].split(".")[0],
            parts[3],
            parts[4] if len(parts) > 4 else "",
        )


ACCEPTED = re.compile(
    r"\[(?P<peer>[^\]]+)\]\s+<- accepted diff=(?P<difficulty>\d+) hash=(?P<hash>[0-9a-f]+) "
    r"height=(?P<height>\d+) split=(?P<split>\d+) pool=(?P<pool>\d+) sats from (?P<user>\S+)"
)


@dataclass
class Acceptance:
    """What the pool logged when it accepted a share. The pool prefixes each line with the
    peer address of the DATUM session the share came in on, after env_logger's own bracketed
    prefix, so the address is matched by its pattern rather than by position."""

    peer: str
    difficulty: int
    block_hash: str
    height: int
    split: int
    pool: int
    username: str

    @property
    def identity(self) -> str:
        return self.username.split(".")[0]


def split(work, own, value, min_payout, fee_bps, subsidy_bps):
    """ledger::split in Python: the amounts the pool dictates by identity, and the remainder
    its own script receives. `own` is each identity's work on gateways other than the public
    one; with a fee of 0 it does not matter."""
    charged = {i: (w - own.get(i, 0)) * fee_bps // BASIS_POINTS for i, w in work.items()}
    fee_work = sum(charged.values())
    own_total = sum(own.values())
    reassigned = fee_work * subsidy_bps // BASIS_POINTS if own_total else 0
    given = 0
    weights = {}
    for identity, w in work.items():
        extra = reassigned * own.get(identity, 0) // own_total if own_total else 0
        given += extra
        weights[identity] = w - charged[identity] + extra
    retained = fee_work - given
    kept = sorted(weights.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_OUTPUTS]
    left_work = sum(w for _, w in kept) + retained
    while kept:
        if left_work == 0:
            kept = []
            break
        if value * kept[-1][1] // left_work >= min_payout:
            break
        left_work -= kept[-1][1]
        kept.pop()
    left = value
    out = {}
    for identity, w in kept:
        if left_work == 0:
            break
        amount = left * w // left_work
        left -= amount
        left_work -= w
        if amount:
            out[identity] = amount
    return out, left


def match_split(ledger, max_prefix, value, min_payout, paid, fee=None, pool=None):
    """The prefix of the ledger whose split reproduces `paid` (sats by address), with the
    amounts under the fee and without it, or None. The window a coinbase was built from is
    some prefix of the ledger: a gateway requests a coinbaser only for the jobs whose state
    sets need_coinbaser (datum_stratum.c), builds the other jobs without a new request, and
    each gateway holds its own. `fee` is (fee_bps, subsidy_bps, public_tag); with `pool` the
    remainder is expected under that address, so `paid` must carry the pool's output too."""
    fee_bps, subsidy_bps, tag = fee or (0, 0, None)
    work, own = {}, {}
    for prefix in range(0, max_prefix + 1):
        if prefix:
            s = ledger[prefix - 1]
            work[s.identity] = work.get(s.identity, 0) + s.difficulty
            if tag is not None and s.tag != tag:
                own[s.identity] = own.get(s.identity, 0) + s.difficulty
        out, remainder = split(work, own, value, min_payout, fee_bps, subsidy_bps)
        expected = dict(out)
        if pool:
            expected[pool] = expected.get(pool, 0) + remainder
        expected = {k: v for k, v in expected.items() if v}
        if expected == paid:
            plain, _ = split(work, own, value, min_payout, 0, 0)
            return prefix, out, plain
    return None


class Stack:
    """The programs one run starts, in a work directory of their own, and the reads the
    checks make of them."""

    def __init__(self, label: str, args: argparse.Namespace):
        self.keep = args.keep
        self.bitcoind = Path(args.bitcoind)
        self.bitcoin_cli = Path(args.bitcoin_cli)
        self.gateway_bin = Path(args.gateway) if args.gateway else ROOT / "target/release/ratum-gateway"
        self.work = Path(tempfile.mkdtemp(prefix=f"ratum-{label}-"))
        self.processes: list[subprocess.Popen] = []
        self.miners: list[subprocess.Popen] = []
        self.rpc_port = free_port(18400, 150)
        self.pool_port = free_port(28900, 90)
        self.pool: subprocess.Popen | None = None
        self.pubkey = ""
        self.ledger_path = self.work / "pool" / "shares.txt"

    def require_tools(self, *commands: str) -> None:
        for path in [self.bitcoind, self.bitcoin_cli] + (
            [self.gateway_bin] if self.gateway_bin != ROOT / "target/release/ratum-gateway" else []
        ):
            if not os.access(path, os.X_OK):
                fail(f"{path} is not executable; set BITCOIND, BITCOIN_CLI or DATUM_GATEWAY")
        for command in commands:
            if shutil.which(command) is None:
                fail(f"{command} is not on PATH")

    def build_release(self) -> None:
        step("building the pool, the gateway and the test miner")
        argv = ["cargo", "build", "--workspace", "--release"]
        argv += ["--bin", "ratum-prime", "--bin", "sia-test-miner", "--bin", "ratum-gateway"]
        if subprocess.run(argv, cwd=ROOT).returncode != 0:
            fail("cargo build")

    def spawn(self, argv, log: Path, cpus: str | None = None, env=None) -> subprocess.Popen:
        """Starts the program with its output in `log`, pinned to the CPUs `cpus` names
        when given. A miner sizes its thread pool from its CPU affinity, so pinning gives
        miners different hash rates."""
        if cpus:
            argv = ["taskset", "-c", cpus] + list(argv)
        with open(log, "ab") as out:
            p = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)
        self.processes.append(p)
        return p

    def cleanup(self) -> None:
        """Stops everything the run started, and keeps or removes its logs."""
        for p in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
        try:
            self.cli("stop")
        except (Failed, OSError):
            pass
        for p in self.processes:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if self.keep:
            print(f"\nlogs kept in {self.work}")
        else:
            shutil.rmtree(self.work, ignore_errors=True)

    def cli(self, *args: str) -> str:
        """The node's own RPC, which every check reaches the same way."""
        argv = [str(self.bitcoin_cli), f"-datadir={self.work / 'node'}", *args]
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"bitcoin-cli {' '.join(args)}: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    def cli_json(self, *args: str):
        return json.loads(self.cli(*args), parse_float=Decimal)

    def height(self) -> int:
        try:
            return int(self.cli("getblockcount"))
        except Failed:
            return 0

    def wait_for_log(self, log: Path, pattern: str, timeout: float = STARTUP_WAIT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if log.exists() and pattern in log.read_text(errors="replace"):
                return True
            time.sleep(0.5)
        return False

    def wait_until(self, condition, timeout: float, progress) -> bool:
        """Polls `condition` every two seconds until it holds or `timeout` seconds pass,
        printing `progress()` every thirty seconds."""
        started = time.monotonic()
        last_report = started
        while time.monotonic() - started < timeout:
            if condition():
                return True
            if time.monotonic() - last_report >= PROGRESS_INTERVAL:
                last_report = time.monotonic()
                print(f"  {int(time.monotonic() - started):4d}s: {progress()}", flush=True)
            time.sleep(2)
        return condition()

    def start_node(self) -> None:
        """A regtest node in the work directory with BLAKE2b activating at
        ACTIVATION_HEIGHT; returns once it answers RPC."""
        step(f"starting a regtest node with BLAKE2b active at height {ACTIVATION_HEIGHT}")
        node = self.work / "node"
        node.mkdir()
        # No peers, so no P2P listener. It also prevents the node from binding ports 18444
        # and 18445, either of which the randomly chosen RPC port could otherwise collide
        # with.
        (node / "bitcoin.conf").write_text(
            "regtest=1\nserver=1\nlisten=0\nrpcuser=ratum\nrpcpassword=ratumtest\n"
            f"[regtest]\nrpcbind=127.0.0.1\nrpcport={self.rpc_port}\n"
            f"testactivationheight=blake2b@{ACTIVATION_HEIGHT}\n"
            "blake2b_headline=RATUM e2e headline\n"
        )
        self.spawn([str(self.bitcoind), f"-datadir={node}"], self.work / "bitcoind.log")
        for _ in range(60):
            if subprocess.run(
                [str(self.bitcoin_cli), f"-datadir={node}", "getblockchaininfo"],
                capture_output=True,
            ).returncode == 0:
                return
            time.sleep(0.5)
        fail(f"the node never responded on port {self.rpc_port}")

    def mine_through_activation(self) -> None:
        step(f"mining {ACTIVATION_HEIGHT} blocks with the node, through the activation")
        self.cli("generatetoaddress", str(ACTIVATION_HEIGHT), POOL_ADDRESS)
        height = self.height()
        if height != ACTIVATION_HEIGHT:
            fail(f"expected height {ACTIVATION_HEIGHT}, got {height}")

    def start_pool(self, *extra_args: str) -> None:
        """ratum-prime on the pool port against the node, paying POOL_ADDRESS, with the
        flags every run gives plus `extra_args`. "<- accepted" is logged at debug, which the
        default info level would not print, and the checks read those lines."""
        (self.work / "pool").mkdir()
        argv = [
            str(ROOT / "target/release/ratum-prime"),
            "--listen", f"127.0.0.1:{self.pool_port}",
            "--data-dir", str(self.work / "pool"),
            "--rpc", f"http://127.0.0.1:{self.rpc_port}", "--rpc-user", "ratum",
            "--rpc-pass", "ratumtest",
            "--payout-address", POOL_ADDRESS,
            "--coinbase-tag", "RATUM",
            "--min-diff", "1", "--min-payout", str(MIN_PAYOUT), "--poll", "1",
            *extra_args,
        ]
        env = dict(os.environ, RUST_LOG=os.environ.get("RUST_LOG", "debug"))
        self.pool = self.spawn(argv, self.pool_log_path, env=env)
        # The public key is printed before the listener binds, so the key alone does not
        # mean the pool started. A port already in use ends the process right after it
        # prints the key.
        if not self.wait_for_log(self.pool_log_path, "listening on"):
            fail(f"the pool never listened on 127.0.0.1:{self.pool_port}; see {self.pool_log_path}")
        m = re.search(r"pool_pubkey: ([0-9a-f]+)", self.pool_log())
        if not m:
            fail(f"the pool never printed its public key; see {self.pool_log_path}")
        self.pubkey = m.group(1)

    @property
    def pool_log_path(self) -> Path:
        return self.work / "pool.log"

    def pool_log(self) -> str:
        return self.pool_log_path.read_text(errors="replace")

    def acceptances(self) -> list[Acceptance]:
        return [
            Acceptance(
                m["peer"], int(m["difficulty"]), m["hash"], int(m["height"]),
                int(m["split"]), int(m["pool"]), m["user"],
            )
            for m in ACCEPTED.finditer(self.pool_log())
        ]

    def start_gateway(
        self,
        name: str,
        stratum_port: int,
        api_port: int,
        pool_address: str,
        tag: str,
        protocol_v3: bool = True,
        vardiff_target: int = 4,
    ) -> None:
        """A gateway pointed at the pool, paying `pool_address` and tagging its coinbases
        with `tag` (empty for none). Its configuration and log are gateway-<name>.json and
        .log in the work directory."""
        config = {
            "bitcoind": {
                "rpcuser": "ratum",
                "rpcpassword": "ratumtest",
                "rpcurl": f"http://127.0.0.1:{self.rpc_port}",
                "notify_fallback": True,
            },
            "stratum": {
                "listen_port": stratum_port,
                "vardiff_min": 1,
                "vardiff_target_shares_min": vardiff_target,
            },
            "mining": {
                "pool_address": pool_address,
                "coinbase_tag_primary": "RATUM",
                "coinbase_tag_secondary": tag,
            },
            "api": {"admin_password": "", "listen_port": api_port, "modify_conf": False},
            "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 1},
            "datum": {
                "pool_host": "127.0.0.1",
                "pool_port": self.pool_port,
                "pool_pubkey": self.pubkey,
                "pool_pass_workers": True,
                "pool_pass_full_users": True,
                "pooled_mining_only": True,
                "protocol_v3": protocol_v3,
            },
        }
        path = self.work / f"gateway-{name}.json"
        path.write_text(json.dumps(config, indent=2) + "\n")
        log = self.work / f"gateway-{name}.log"
        self.spawn([str(self.gateway_bin), "-c", str(path)], log)
        self.wait_for_log(log, "Stratum V1 Server Init complete")
        if "DATUM Server MOTD" not in log.read_text(errors="replace"):
            fail(f"gateway {name} never completed the handshake; see {log}")

    def start_miner(self, user: str, name: str, port: int, cpus: str | None = None) -> None:
        argv = [str(ROOT / "target/release/sia-test-miner"), f"127.0.0.1:{port}", user]
        self.miners.append(self.spawn(argv, self.work / f"miner-{name}.log", cpus=cpus))

    def stop_and_dump_ledger(self) -> list[Share]:
        """Stops the miners, then the pool, so no share is credited after the last block on
        the chain and the pool releases the ledger's lock (a redb database), then dumps the
        ledger as text, oldest share first."""
        for p in self.miners:
            p.terminate()
        time.sleep(2)
        self.pool.terminate()
        self.pool.wait(timeout=10)
        argv = [
            str(ROOT / "target/release/ratum-prime"),
            "--dump-ledger", "--ledger", str(self.work / "pool" / "regtest.redb"),
        ]
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"could not dump the ledger: {r.stderr.strip()}")
        self.ledger_path.write_text(r.stdout)
        return [Share.parse(line) for line in r.stdout.splitlines() if line.split()]

    def block(self, height: int) -> tuple[str, dict]:
        block_hash = self.cli("getblockhash", str(height))
        return block_hash, self.cli_json("getblock", block_hash, "2")

    @staticmethod
    def coinbase_outputs(block: dict, addresses) -> dict[str, int]:
        """The coinbase outputs paying the given addresses, in sats by address."""
        paid = {}
        for out in block["tx"][0]["vout"]:
            address = out["scriptPubKey"].get("address")
            if address in addresses:
                paid[address] = paid.get(address, 0) + sats(out["value"])
        return paid

    @staticmethod
    def coinbase_value(block: dict) -> int:
        return sum(sats(out["value"]) for out in block["tx"][0]["vout"])

    def acceptance_of(self, block_hash: str) -> Acceptance:
        for a in self.acceptances():
            if a.block_hash == block_hash:
                return a
        fail(f"the pool has no acceptance line for block {block_hash}")

    @staticmethod
    def ledger_index_of(ledger: list[Share], block_hash: str) -> int:
        for i, s in enumerate(ledger):
            if s.block_hash == block_hash:
                return i
        fail(f"no ledger line records the share that solved {block_hash}")

    def print_ledger(self, ledger: list[Share]) -> None:
        print("ledger:")
        print(self.ledger_path.read_text(), end="")


def cpu_spans(parts: int) -> list[str]:
    """`parts` CPU spans that divide the machine, for pinning miners."""
    cores = os.cpu_count() or 1
    bounds = [cores * i // parts for i in range(parts + 1)]
    return [f"{lo}-{max(lo, hi - 1)}" for lo, hi in zip(bounds, bounds[1:])]


def full_stack(stack: Stack, a: argparse.Namespace) -> None:
    """Mines the first post-activation block through one gateway and one miner: the gateway
    accepts what the pool dictates, and a share the pool verifies is a block the node
    accepts. With --protocol-version 3 (the default, as in the gateway) the gateway sends
    the DRS hello and version 3 config and mines under the pool's anti-block-withholding
    assignment, which the pool submits blocks for."""
    stack.require_tools()
    stack.build_release()
    stack.start_node()
    stack.mine_through_activation()
    target = ACTIVATION_HEIGHT + a.blocks

    step(f"starting ratum-prime on port {stack.pool_port}")
    stack.start_pool(*a.prime_args.split())

    stratum_port, api_port = free_port(23300, 90), free_port(7100, 90)
    step(f"starting the gateway on stratum port {stratum_port}")
    stack.start_gateway(
        "A", stratum_port, api_port, a.gateway_pool_address, "e2e",
        protocol_v3=a.protocol_version == 3,
    )

    step(f"mining with sia-test-miner until height {target} (up to {a.timeout}s)")
    stack.start_miner(f"{MINER_ADDRESS}.rig1", "rig1", stratum_port)
    if not stack.wait_until(
        lambda: stack.height() >= target, a.timeout,
        lambda: f"height {stack.height()} of {target}",
    ):
        fail(f"no block at height {target} within {a.timeout}s; see {stack.work}")

    step("checking the last pooled block")
    block_hash = stack.cli("getblockhash", str(target))
    header = stack.cli("getblockheader", block_hash, "false")
    if len(header) != 328:
        fail(f"the header is {len(header)} hex characters, not 328 (164 bytes)")
    log = stack.pool_log()
    if f"BLOCK at height {target}" not in log:
        fail(f"the pool did not record a block at height {target}")
    if block_hash not in log:
        fail("the block on the chain is not one the pool verified")
    accepted = len(stack.acceptances())
    if accepted == 0:
        fail("the pool accepted no shares")

    step(
        f"passed: height {target} is {block_hash}: a 164-byte header mined through the stack "
        f"({a.blocks} pooled block(s))"
    )
    print(f"shares accepted: {accepted}")
    stack.print_ledger(stack.stop_and_dump_ledger())


def multi_miner(stack: Stack, a: argparse.Namespace) -> None:
    """Three miners, each with its own payout address, behind two gateways, and the
    accounting that appears only then: shares are attributed per identity, the coinbaser
    outputs match the pro-rata split of the share window, and what the pool recorded for a
    block is what its coinbase pays on chain.

    Two gateways rather than one because the pool keeps its jobs, its tip and its tip grace
    (TIP_GRACE_SECS) per connection. One gateway exercises one instance of that state. Two
    produce the case that only a real deployment has: a block found behind one gateway
    replaces the tip for the other's session, so work that was current when it was issued
    goes stale through no act of the miner doing it."""
    stack.require_tools("taskset")
    stack.build_release()
    stack.start_node()
    miners = [ALICE, BOB, CAROL]
    for address in miners + [GATEWAY_ADDRESS, POOL_ADDRESS]:
        if stack.cli_json("validateaddress", address).get("isvalid") is not True:
            fail(f"{address} is not an address this node accepts")
    stack.mine_through_activation()

    step(f"starting ratum-prime on port {stack.pool_port}, window floor {WINDOW_FLOOR}")
    stack.start_pool("--window-floor", str(WINDOW_FLOOR))

    ports = {"A": free_port(23300, 90), "B": free_port(23400, 90)}
    for name, api_base in (("A", 7100), ("B", 7200)):
        step(f"starting gateway {name} on stratum port {ports[name]}")
        stack.start_gateway(name, ports[name], free_port(api_base, 90), GATEWAY_ADDRESS, name)
    sessions = stack.pool_log().count("hello ok:")
    if sessions < 2:
        fail(f"the pool completed {sessions} handshake(s), not 2; see {stack.pool_log_path}")

    # alice behind one gateway and bob with carol behind the other splits the machine evenly
    # between the two sessions, so each gateway finds roughly half the blocks and each one
    # regularly invalidates the work the other has outstanding.
    step("starting miners: alice on gateway A, bob and carol on gateway B")
    alice_cpus, bob_cpus, carol_cpus = cpu_spans(2)[0], *cpu_spans(3)[1:]
    stack.start_miner(f"{ALICE}.rig", "alice", ports["A"], alice_cpus)
    stack.start_miner(f"{BOB}.rig", "bob", ports["B"], bob_cpus)
    stack.start_miner(f"{CAROL}.rig", "carol", ports["B"], carol_cpus)

    # A share is 2^32 BLAKE2b hashes (difficulty 1 is the protocol's floor), so each one
    # costs a CPU miner tens of seconds. Wait for the target, and for every miner to hold at
    # least one share, so that the split being checked is a split between three miners
    # rather than however many had found one.
    step(f"accumulating {a.shares} shares (up to {a.timeout}s)")

    def enough() -> bool:
        acc = stack.acceptances()
        return len(acc) >= a.shares and all(any(x.identity == m for x in acc) for m in miners)

    if not stack.wait_until(
        enough, a.timeout,
        lambda: f"{len(stack.acceptances())}/{a.shares} shares accepted at height {stack.height()}",
    ):
        fail(f"fewer than {a.shares} shares from every miner in {a.timeout}s; see {stack.pool_log_path}")

    ledger = stack.stop_and_dump_ledger()

    step("shares recorded per miner")
    for identity in sorted({s.identity for s in ledger}):
        mine = [s for s in ledger if s.identity == identity]
        print(f"  {identity:45} {len(mine):3d} shares {sum(s.difficulty for s in mine):6d} work")
    for m in miners:
        if not any(s.identity == m for s in ledger):
            fail(f"{m} submitted no share the pool credited")

    step("every accepted share was credited to the miner that submitted it")
    acc = stack.acceptances()
    if len(acc) != len(ledger):
        fail(f"the pool accepted {len(acc)} shares but wrote {len(ledger)} ledger lines")
    # Every acceptance names the user that submitted the share, its difficulty and the hash
    # it produced. The ledger line for that hash must carry the same difficulty and the
    # identity part of that user.
    accepted = {(x.block_hash, x.difficulty, x.identity) for x in acc}
    credited = {(s.block_hash, s.difficulty, s.identity) for s in ledger}
    if accepted != credited:
        fail(
            "the shares the pool accepted are not the shares it credited: "
            f"accepted only {accepted - credited}, credited only {credited - accepted}"
        )
    print(f"  {len(acc)} shares accepted, each credited to its submitter at its difficulty")

    step("both gateways delivered shares the pool credited")
    contributing = len({x.peer for x in acc})
    if contributing < 2:
        fail(f"credited shares came from {contributing} session(s); the second gateway contributed none")
    print(f"  {contributing} sessions contributed credited shares")

    step("each block pays out what the pool recorded for it")
    checked = proportional = 0
    # The node mined heights 1 to ACTIVATION_HEIGHT itself, so the blocks the pool found,
    # and the only ones it holds an acceptance line for, start one above that.
    for height in range(ACTIVATION_HEIGHT + 1, stack.height() + 1):
        block_hash, block = stack.block(height)
        recorded = stack.acceptance_of(block_hash)
        paid = stack.coinbase_outputs(block, miners)
        if sum(paid.values()) != recorded.split:
            fail(f"height {height}: the pool recorded split={recorded.split} but the coinbase pays {sum(paid.values())}")
        # The split itself, against the ledger as it stood when the template was built:
        # the shares before this block's own, allowing for a template built one share
        # earlier.
        k = stack.ledger_index_of(ledger, block_hash)
        matched = match_split(ledger, k, stack.coinbase_value(block), MIN_PAYOUT, paid)
        checked += 1
        if matched:
            proportional += 1
            print(f"  height {height:<3} {recorded.split} sats to {len(paid)} miner(s), pro rata over {matched[0]} shares")
        else:
            print(f"  height {height:<3} {recorded.split} sats to {len(paid)} miner(s), NOT the split of any recent window")
    if proportional != checked:
        fail(f"{checked - proportional} of {checked} coinbases did not match the ledger split")

    step(f"passed: {checked} blocks, each crediting its miner and paying the window pro rata")
    stack.print_ledger(ledger)


def public_gateway_fee(stack: Stack, a: argparse.Namespace) -> None:
    """Two gateways: a public one whose secondary coinbase tag the pool was given, and one
    with no tag, as a miner runs beside its own node. The pool charges the tagged gateway's
    shares the public gateway fee and reassigns the charged work to the miner on the untagged
    gateway: every pooled coinbase pays the split this module's copy of the pool's arithmetic
    computes from the ledger, the pool's address receives only the remainder that arithmetic
    leaves, at least one coinbase pays the public gateway's miner less than its work alone
    earns, and at least one pays the own-gateway miner more."""
    # 5000 basis points: half of alice's work is charged, so the fee and the subsidy are
    # large enough to show in the few shares a CPU miner produces. The whole fee is
    # reassigned: the pool keeps none, so a coinbase with own-gateway work in the window
    # leaves the pool address no remainder at all.
    fee_bps, subsidy_bps, public_tag = 5000, 10000, "public"
    stack.require_tools("taskset")
    stack.build_release()
    stack.start_node()
    stack.mine_through_activation()

    step(f"starting ratum-prime on port {stack.pool_port}, fee {fee_bps} bps on shares tagged {public_tag}, subsidy {subsidy_bps} bps")
    stack.start_pool(
        "--window-floor", str(WINDOW_FLOOR),
        "--public-gateway-fee-bps", str(fee_bps),
        "--public-gateway-fee-subsidy-bps", str(subsidy_bps),
        "--public-gateway-tag", public_tag,
    )
    if "public gateway fee:" not in stack.pool_log():
        fail(f"the pool did not report the public gateway fee at startup; see {stack.pool_log_path}")

    # Gateway A is the public one: it tags its coinbases. Gateway B is what a miner runs
    # beside its own node: the secondary tag left at its default, which is empty. Every
    # share is difficulty 1: the pool's floor is 1 and the vardiff target is set so far
    # above what a CPU miner reaches that the gateway never raises it.
    ports = {"A": free_port(23300, 90), "B": free_port(23400, 90)}
    step(f"starting gateway A on stratum port {ports['A']}, tag {public_tag}")
    stack.start_gateway("A", ports["A"], free_port(7100, 90), GATEWAY_ADDRESS, public_tag)
    step(f"starting gateway B on stratum port {ports['B']}, no tag")
    stack.start_gateway("B", ports["B"], free_port(7200, 90), GATEWAY_ADDRESS, "")

    step("starting miners: alice on gateway A, bob on gateway B")
    alice_cpus, bob_cpus = cpu_spans(2)
    stack.start_miner(f"{ALICE}.rig", "alice", ports["A"], alice_cpus)
    stack.start_miner(f"{BOB}.rig", "bob", ports["B"], bob_cpus)

    step(f"accumulating {a.alice_shares} shares from alice and {a.bob_shares} from bob (up to {a.timeout}s)")
    counts = {"alice": 0, "bob": 0, "enough_at": None}

    def enough() -> bool:
        acc = stack.acceptances()
        counts["alice"] = sum(x.identity == ALICE for x in acc)
        counts["bob"] = sum(x.identity == BOB for x in acc)
        if counts["alice"] < a.alice_shares or counts["bob"] < a.bob_shares:
            return False
        # A coinbase pays bob the subsidy only if its template was built after a share of
        # alice's and a share of bob's were credited. On regtest nearly every share is a
        # block, and a template can be one share behind the ledger, so once the counts are
        # met wait for two more accepted shares before stopping the miners.
        if counts["enough_at"] is None:
            counts["enough_at"] = len(acc) + 2
        return len(acc) >= counts["enough_at"]

    reached = stack.wait_until(
        enough, a.timeout,
        lambda: f"alice {counts['alice']}/{a.alice_shares}, bob {counts['bob']}/{a.bob_shares} at height {stack.height()}",
    )
    print(f"  alice {counts['alice']}, bob {counts['bob']}")
    if not reached:
        fail(f"alice {counts['alice']} and bob {counts['bob']} shares in {a.timeout}s, wanted {a.alice_shares} and {a.bob_shares}")

    ledger = stack.stop_and_dump_ledger()

    step("work credited per identity and tag")
    for key in sorted({(s.identity, s.tag) for s in ledger}):
        mine = [s for s in ledger if (s.identity, s.tag) == key]
        label = f"{key[0]} {key[1] or '(no tag)'}"
        print(f"  {label:55} {len(mine):3d} shares {sum(s.difficulty for s in mine):6d} work")
    if any(s.identity == ALICE and s.tag != public_tag for s in ledger):
        fail(f"a share of alice's does not carry the tag {public_tag} gateway A was started with")
    if any(s.identity == BOB and s.tag == public_tag for s in ledger):
        fail("a share of bob's carries the public tag; gateway B was started with none")

    step("each pooled coinbase pays the split with the fee and leaves the pool the remainder")
    checked = subsidy_only = charged = subsidized = 0
    for height in range(ACTIVATION_HEIGHT + 1, stack.height() + 1):
        block_hash, block = stack.block(height)
        recorded = stack.acceptance_of(block_hash)
        if recorded.split == 0:
            # Subsidy-only work: served between a tip change and the next coinbaser split,
            # its coinbase pays the pool alone and the pool records what it owes (README,
            # Owed blocks).
            subsidy_only += 1
            continue
        paid = stack.coinbase_outputs(block, [ALICE, BOB, POOL_ADDRESS])
        k = stack.ledger_index_of(ledger, block_hash)
        matched = match_split(
            ledger, k, stack.coinbase_value(block), MIN_PAYOUT, paid,
            fee=(fee_bps, subsidy_bps, public_tag), pool=POOL_ADDRESS,
        )
        if not matched:
            fail(f"height {height} pays {paid}, the split of no recent window with the fee")
        prefix, out, plain = matched
        checked += 1
        charged += out.get(ALICE, 0) < plain.get(ALICE, 0)
        subsidized += out.get(BOB, 0) > plain.get(BOB, 0)
        print(
            f"  height {height:<3} over {prefix} shares: alice {out.get(ALICE, 0)} sats "
            f"({plain.get(ALICE, 0)} without the fee), bob {out.get(BOB, 0)} sats "
            f"({plain.get(BOB, 0)} without it)"
        )
    if checked < 1:
        fail(f"no pooled coinbase to check ({subsidy_only} subsidy-only blocks)")
    if charged < 1:
        fail("no coinbase paid alice less than her work earns; the public gateway fee was not charged")
    if subsidized < 1:
        fail("no coinbase paid bob more than his own work earns; the fee work was not reassigned")

    step(
        f"passed: {checked} pooled coinbases match the split with the fee, {charged} charged "
        f"alice, {subsidized} paid bob the fee work ({subsidy_only} subsidy-only)"
    )
    stack.print_ledger(ledger)


def main() -> int:
    home = Path.home() / "src/bitcoin/build/bin"
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true", help="keep the work directory and its logs")
    ap.add_argument("--bitcoind", default=os.environ.get("BITCOIND", home / "bitcoind"))
    ap.add_argument("--bitcoin-cli", default=os.environ.get("BITCOIN_CLI", home / "bitcoin-cli"))
    ap.add_argument("--gateway", default=os.environ.get("DATUM_GATEWAY") or None,
                    help="another gateway build to run instead of this workspace's")
    runs = ap.add_subparsers(dest="run", required=True)

    fs = runs.add_parser("full-stack", help="the activation block through one gateway and one miner")
    fs.add_argument("--timeout", type=float, default=900, help="seconds to wait for the block")
    fs.add_argument("--blocks", type=int, default=1, help="pooled blocks to mine past the activation")
    fs.add_argument("--protocol-version", type=int, choices=(1, 3), default=3)
    fs.add_argument("--gateway-pool-address", default=MINER_ADDRESS,
                    help="the gateway's mining.pool_address; the C gateway decodes bc1/tb1 only")
    fs.add_argument("--prime-args", default="",
                    help='extra ratum-prime flags, split on whitespace ("--abw-reveal-after 20" '
                    "reveals each retired ABW slot 20 s after the rotation, so a short run "
                    "exercises the gateway's reveal audit)")
    fs.set_defaults(scenario=full_stack)

    mm = runs.add_parser("multi-miner", help="three miners behind two gateways: credit and payout split")
    mm.add_argument("--shares", type=int, default=6, help="shares to accumulate before checking")
    mm.add_argument("--timeout", type=float, default=5400, help="seconds to wait for them")
    mm.set_defaults(scenario=multi_miner)

    pf = runs.add_parser("public-gateway-fee", help="a tagged gateway's shares charged, the fee paid to the other's miner")
    pf.add_argument("--alice-shares", type=int, default=6, help="shares from the miner on the public gateway")
    pf.add_argument("--bob-shares", type=int, default=2, help="shares from the miner on the own gateway")
    pf.add_argument("--timeout", type=float, default=5400, help="seconds to wait for them")
    pf.set_defaults(scenario=public_gateway_fee)

    a = ap.parse_args()
    stack = Stack(a.run, a)
    try:
        a.scenario(stack, a)
        return 0
    except Failed as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    finally:
        stack.cleanup()


if __name__ == "__main__":
    sys.exit(main())
