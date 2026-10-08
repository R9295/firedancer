# Run the cluster with network control

Create a ten-validator cluster once. The generator refuses to overwrite an
existing directory, gives every validator the same genesis stake (10% each),
uses disjoint ports, and assigns disjoint shared CPU sets across the host NUMA
nodes:

```bash
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh create
C=/home/fuzz/cluster contrib/test/run_fd_cluster.sh fini   # Retire the old 3-node host setup
```

Then launch it from the repository root:

```bash
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh net
```

This incrementally builds Firedancer and the Rust controller, prepares the host,
sets up a private network, and launches the cluster. If a rebuild changes the
huge-page footprint, the launcher recreates only the stale mounts before it
reserves pages. No PID copying or `nsenter`. Ctrl-C stops both and removes the
network rules and control socket. Requires Rust, `iproute2`, `nftables`, kernel
NFQUEUE support, and `sudo` access for host setup.

In another terminal:

```bash
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh netctl status
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh netctl heal
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh netctl stop
```

For automatic TypeSafe partition injection, keep `net` running and use another terminal:

```bash
export TYPESAFE_API_KEY='your-key'
C=/home/fuzz/cluster-10 contrib/test/run_fd_cluster.sh netctl typesafe
```

There is one choice per configured validator. A choice isolates that validator
from every other validator in both directions for Gossip, Repair, Shred, and
Votor. Traffic between the other validators and all transaction traffic remain
available. One partition is active at most; each selection replaces the last
and prints `FAULT applied`. With the generated ten-node cluster, each choice
isolates exactly 10% of genesis stake. Ctrl-C or `netctl heal` stops injection
and clears the partition; manual faults are disabled until then. API errors retain
the current partition and retry on the next interval; slow calls skip missed ticks.
If the API worker is killed with SIGKILL, use `netctl heal` to clear its fault.
The host-side Rust worker uses TypeSafe's [Choice API](https://docs.typesafe.ai/primitives/choice),
default model `jev-latest` (`TYPESAFE_MODEL` overrides it). Only fault history and
packet counts go to the API, not configs, keys, payloads, or logs. API calls incur usage.

`apply RULE, RULE, ...` replaces every link rule at once. It heals, then sets
the comma-separated `block`, `allow`, `delay`, `duplicate` and `loss` rules (each written
as its own command would be), as one policy change. It changes nothing if any
rule is invalid, and `apply` alone heals. Like `block`, it drops held packets on
links it blocks. A command line can be up to 64 KiB long.

Delay accepts 0–5000 milliseconds; `duplicate ... 0` disables copies.
`loss FROM TO PCT` drops PCT percent (0–100) of new packets on the directed link
at random, decided when a packet arrives; `status` counts them as `lost`. Delay and
duplication combine, but a blocked link drops everything until `allow` or `heal`.
Changes affect new packets. `block` also drops already-held packets; `heal`
releases held originals once, without extra copies. The delay buffer is capped
at 4096 packets, half the kernel queue: exhaustion aborts the test rather than growing memory or silently
adding loss. Copies are limited to the validator's 2048-byte network frame size.
`status` includes duplicate, delayed, and pending packet counters.

By default, the launcher finds every `node-*.toml` in `C`, uses root target 256,
and waits 180 seconds.
Override with `net --root-slot N --timeout SECONDS`.

For another node list (1–128 nodes; IDs follow config order):

```bash
FD_CLUSTER_CONFIGS=/path/node-0.toml:/path/node-1.toml \
  contrib/test/run_fd_cluster.sh net
```

Only configured loopback UDP port pairs are intercepted; TCP and the host
firewall are untouched. Configs must use `net.provider = "socket"`, interface
`lo`, address `127.0.0.1`, and unique explicit UDP ports. QUIC stays encrypted.
Manual block, delay, and duplicate commands remain directed. TypeSafe partitions
are atomic policy replacements. Start with short partitions: the low-memory
cluster has bounded history.
The controller uses an 8192-packet NFQUEUE and a 32 MiB receive buffer. A rare
receive overrun is counted in `status` and warned without killing the cluster;
it means the kernel dropped packets in addition to the selected fault. After SIGKILL, remaining
test processes and a stale control socket may need manual cleanup.

The control socket defaults to `/run/fd-netctl/control.sock`; override it with
`FD_NETCTL_SOCKET` on both `net` and `netctl`. Manual/persistent `serve` mode is
still available via `contrib/test/fd-netctl/target/release/fd-netctl --help`.

## Random fault fuzzing

`fuzz_fd_cluster.sh` runs the cluster again and again under random faults,
until a run fails or a deadline passes:

```bash
C=/home/fuzz/cluster-10 contrib/test/fuzz_fd_cluster.sh
```

Each iteration boots the cluster from genesis with `run_fd_cluster.sh net`.
When every validator has launched, the iteration starts
`inject_fd_cluster_faults.sh`, then waits for every validator to root `ROOT`
(default 128) within `TIMEOUT` seconds (default 300). The loop stops at the
first failure, or after `DEADLINE_MIN` minutes (default 110). `touch
$OUT/STOP` stops it after the current iteration. `OUT` defaults to `$C/fuzz`:

- `summary.log` has one line per iteration, with its fault count and seed.
- `iter-N/faults.log` lists every applied fault with a timestamp.
- A failed iteration keeps `run.log` and writes `failure.txt` with the first
  error lines. The `Log at` line of `run.log` names the validators' log file.
  `contrib/test/show_fd_cluster_trace.py` shows each slot's consensus
  traces from that file (see `src/app/firedancer-dev/tests/README.md`).
- If the highest root stops for `STALL_S` seconds (default 8), or a validator
  trails it by more than `LAG_SLOTS` (default 64), every validator's metrics
  go to `iter-N/metrics-K/`. Such an iteration also keeps its `run.log`.

The exit code is 0 for the deadline or `STOP`, 1 for a cluster failure, and 2
for a harness problem.

Every injector step applies one to three stacked faults with a single `apply`,
so they start and end at once. It holds them for 0.5–3 seconds, then heals
the network for 0–3 seconds. Faults include isolating one validator,
splitting off a group, an even split, a bridge (two groups that reach each
other only through one validator), and delayed or duplicated links. The header
of `inject_fd_cluster_faults.sh` lists the shares and settings: `STACK_MAX`,
`STACK_PCT`, `ONLY`, `HOLD_MIN_MS`, `HOLD_MAX_MS`, `GAP_MIN_MS`, `GAP_MAX_MS`
and `DELAY_MAX_MS`. Pass
`SEED` from a `summary.log` line to replay the same choices; timing still
varies. `INJECTOR=rr` runs `rotate_fd_cluster_partitions.sh` instead, which
isolates validator 0, 1, 2, ... in turn, one per `INTERVAL` seconds.

To add a validator that equivocates, create the cluster with
`FD_CLUSTER_EQUIVOCATOR=K` (see `src/app/firedancer-dev/tests/README.md`).

Tests:

```bash
cargo test --locked --manifest-path contrib/test/fd-netctl/Cargo.toml
```

The opt-in `netns` tests need namespace privileges. Run the printed test executable
with `sudo`, or `unshare --user --map-root-user --net`, followed by `--ignored`.
