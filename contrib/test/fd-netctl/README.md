# Run the cluster with network control

From the repository root:

```bash
contrib/test/run_fd_cluster.sh net
```

This builds the Rust controller, prompts for sudo, sets up a private network,
and launches the cluster. No PID copying or `nsenter`. Ctrl-C stops both and
removes the network rules and control socket. Uses the existing built/prepared
cluster; host huge-page/CPU setup is still `contrib/test/run_fd_cluster.sh init`.
Requires Rust, `iproute2`, `nftables`, and kernel NFQUEUE support.

In another terminal:

```bash
contrib/test/run_fd_cluster.sh netctl block 0 2  # Drop 0 -> 2
contrib/test/run_fd_cluster.sh netctl block 2 0  # Drop 2 -> 0
contrib/test/run_fd_cluster.sh netctl delay 0 2 100     # Add 100ms to 0 -> 2
contrib/test/run_fd_cluster.sh netctl duplicate 0 2 1   # One extra copy on 0 -> 2
contrib/test/run_fd_cluster.sh netctl status
contrib/test/run_fd_cluster.sh netctl heal       # Reset drops, delay, duplication
contrib/test/run_fd_cluster.sh netctl stop       # Stop the whole run
```

For automatic TypeSafe drop injection, keep `net` running and use another terminal:

```bash
export TYPESAFE_API_KEY='your-key'
contrib/test/run_fd_cluster.sh netctl typesafe   # Pick immediately, then every 1s
```

Exactly three nodes: six directed links × Repair/Shred/Votor/All = 24 choices,
with one active drop at most. Each selection replaces the last and prints
`FAULT applied`. Ports come from the destination node's config: both Repair
ports, Shred's port, both Votor ports, or all of Gossip, Repair, Shred, and Votor.
The All choice does not drop transaction traffic. Gossip remains available for
the three protocol-specific choices. Ctrl-C or `netctl heal` stops injection
and clears the fault; manual faults are disabled until then. API errors retain
the current fault and retry on the next interval; slow calls skip missed ticks.
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

Defaults: the three configs in `../cluster`, root target 256, timeout 180 seconds.
Override with `net --root-slot N --timeout SECONDS`.

For another node list (1–128 nodes; IDs follow config order):

```bash
FD_CLUSTER_CONFIGS=/path/node-0.toml:/path/node-1.toml \
  contrib/test/run_fd_cluster.sh net
```

Only configured loopback UDP port pairs are intercepted; TCP and the host
firewall are untouched. Configs must use `net.provider = "socket"`, interface
`lo`, address `127.0.0.1`, and unique explicit UDP ports. QUIC stays encrypted.
Commands are directed and individual, not an atomic partition transaction.
Start with short partitions: the low-memory cluster has bounded history.
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
