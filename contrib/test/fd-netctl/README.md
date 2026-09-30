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

Delay accepts 0–5000 milliseconds; `duplicate ... 0` disables copies. Delay and
duplication combine, but a blocked link drops everything until `allow` or `heal`.
Changes affect new packets. `block` also drops already-held packets; `heal`
releases held originals once, without extra copies. The delay buffer is capped
at 512 packets: exhaustion aborts the test rather than growing memory or silently
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

Tests:

```bash
cargo test --locked --manifest-path contrib/test/fd-netctl/Cargo.toml
```

The opt-in `netns` tests need namespace privileges. Run the printed test executable
with `sudo`, or `unshare --user --map-root-user --net`, followed by `--ignored`.
