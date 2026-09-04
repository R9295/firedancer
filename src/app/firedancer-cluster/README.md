# Multi-process Firedancer cluster (Alpenglow)

`firedancer-cluster` runs multiple full Firedancer validators on one Linux VM.
Each validator is a separate process, and all of that validator's tiles run as
threads. The launcher always executes:

```text
firedancer-dev --config CONFIG --alpenglow --no-clone dev --no-watch --no-configure
```

This is a development and fuzzing tool, not a production deployment mode.

The accompanying development startup mode lets every validator load the same
trusted local `genesis.bin` while followers still use node 0 as a gossip
entrypoint. Set `development.bootstrap = true` in every node config to use it.
The genesis and IP-echo tiles then ignore gossip entrypoints, while the gossip
tiles retain them for peer discovery.

This mode proves the multi-process cluster and is suitable for transport fault
injection. It deliberately bypasses follower snapshot restore; see

## Quick start: three validators

The paths below use `/cluster` as an example. `node-0.toml` is not generated
by the launcher or checked into the repository: it contains host-specific
paths, ports, identities, and CPU assignments. Create one normal Firedancer
config per validator as described below.

### 1. Build Firedancer and the launcher

From the repository root:

```sh
make -j firedancer-dev firedancer-cluster
```

The resulting programs are `build/firedancer-dev` and
`build/firedancer-cluster`.

### 2. Create the identities and shared Alpenglow genesis

Use an Alpenglow-capable Agave checkout. Its tools must expose both of these
development options:

```sh
solana-genesis --help | grep -- --alpenglow
solana-keygen --help | grep bls_pubkey
```

Create a writable cluster directory plus identity, vote, stake, and faucet
keypairs:

```sh
sudo install -d -o "$(id -un)" -g "$(id -gn)" /cluster
mkdir -p /cluster/keys /cluster/ledger /cluster/logs \
  /cluster/node-0 /cluster/node-1 /cluster/node-2

solana-keygen new --no-bip39-passphrase --silent --force \
  --outfile /cluster/keys/faucet.json

for i in 0 1 2; do
  solana-keygen new --no-bip39-passphrase --silent --force \
    --outfile "/cluster/keys/identity-$i.json"
  solana-keygen new --no-bip39-passphrase --silent --force \
    --outfile "/cluster/keys/vote-$i.json"
  solana-keygen new --no-bip39-passphrase --silent --force \
    --outfile "/cluster/keys/stake-$i.json"
done

BLS_0=$(solana-keygen bls_pubkey /cluster/keys/identity-0.json)
BLS_1=$(solana-keygen bls_pubkey /cluster/keys/identity-1.json)
BLS_2=$(solana-keygen bls_pubkey /cluster/keys/identity-2.json)
```

There is no separate BLS secret file. Firedancer deterministically derives
the matching BLS secret from each identity keypair when it starts.

Create one genesis containing all three validators:

```sh
solana-genesis \
  --alpenglow \
  --cluster-type development \
  --ledger /cluster/ledger \
  --slots-per-epoch 256 \
  --faucet-pubkey /cluster/keys/faucet.json \
  --faucet-lamports 500000000000000000 \
  --bootstrap-validator \
    /cluster/keys/identity-0.json \
    /cluster/keys/vote-0.json \
    /cluster/keys/stake-0.json \
  --bootstrap-validator-bls-pubkey "$BLS_0" \
  --bootstrap-validator \
    /cluster/keys/identity-1.json \
    /cluster/keys/vote-1.json \
    /cluster/keys/stake-1.json \
  --bootstrap-validator-bls-pubkey "$BLS_1" \
  --bootstrap-validator \
    /cluster/keys/identity-2.json \
    /cluster/keys/vote-2.json \
    /cluster/keys/stake-2.json \
  --bootstrap-validator-bls-pubkey "$BLS_2"
```

`--alpenglow` is required: it activates Alpenglow at genesis and embeds the
development genesis certificate. Record the command's `Genesis hash:` value.
Every validator must use that exact hash and the resulting
`/cluster/ledger/genesis.bin`.

Each `--bootstrap-validator-bls-pubkey` corresponds to the immediately
preceding `--bootstrap-validator`; keep the two repeated argument lists in the
same order.

### 3. Create `node-0.toml`, `node-1.toml`, and `node-2.toml`

Start with this node 0 override. Replace `<non-root-user>`, `<GENESIS_HASH>`,
and `<NODE_0_CPU_LIST>`:

```toml
name = "fd-cluster-0"
user = "<non-root-user>"
telemetry = false

[paths]
    base = "/cluster/node-0"
    identity_key = "/cluster/keys/identity-0.json"
    vote_account = "/cluster/keys/vote-0.json"
    genesis = "/cluster/ledger/genesis.bin"

[log]
    path = "/cluster/node-0/firedancer.log"

[gossip]
    entrypoints = []
    host = "127.0.0.1"
    port = 8001

[snapshots]
    genesis_download = false

[consensus]
    expected_genesis_hash = "<GENESIS_HASH>"
    wait_for_vote_to_start_leader = false

[accounts]
    max_accounts = 65536
    cache_size_gib = 3

[runtime]
    max_live_slots = 64
    max_fork_width = 4

[layout]
    affinity = "<NODE_0_CPU_LIST>"
    net_tile_count = 1
    quic_tile_count = 1
    resolv_tile_count = 1
    verify_tile_count = 1
    gossvf_tile_count = 1
    execle_tile_count = 1
    execrp_tile_count = 1
    snapdc_tile_count = 1
    snapzp_tile_count = 1
    snapsv_tile_count = 1
    snapsv_io_worker_count = 1
    shred_tile_count = 1
    sign_tile_count = 2
    enable_block_production = true
    enable_snapshot_production = false

[hugetlbfs]
    mount_path = "/mnt/.fd-cluster-0"
    max_page_size = "huge"

[net]
    provider = "socket"
    interface = "lo"
    bind_address = "127.0.0.1"

[tiles.quic]
    regular_transaction_listen_port = 9001
    quic_transaction_listen_port = 9007

[tiles.shred]
    shred_listen_port = 8003
    shred_cache_size_mib = 64
    additional_shred_destinations_leader = [
        "127.0.0.1:8103",
        "127.0.0.1:8203",
    ]

[tiles.repair]
    repair_client_listen_port = 8701
    slot_max = 128

[tiles.rotor]
    slot_max = 128

[tiles.rserve]
    repair_serve_listen_port = 8702
    shred_storage_limit_gib = 1

[tiles.txsend]
    txsend_src_port = 9006

[tiles.metric]
    prometheus_listen_port = 7999

[tiles.gui]
    enabled = false

[tiles.rpc]
    enabled = true
    rpc_listen_address = "127.0.0.1"
    rpc_listen_port = 8899
    max_http_connections = 32
    max_websocket_connections = 8
    send_buffer_size_mb = 8
    delay_startup = false

[development]
    alpenglow = true
    bootstrap = true

[development.votor]
    quic_client_listen_port = 8005
    quic_server_listen_port = 8004

[development.gossip]
    allow_private_address = true

[development.genesis]
    validate_genesis_hash = false

[development.accdb]
    partition_size_gib = 1
```

Copy it to `node-1.toml` and `node-2.toml`, then apply this matrix. All other
values, especially `paths.genesis` and `consensus.expected_genesis_hash`, stay
the same.

| Setting | node 0 | node 1 | node 2 |
|---|---:|---:|---:|
| `name` | `fd-cluster-0` | `fd-cluster-1` | `fd-cluster-2` |
| `paths.base` | `/cluster/node-0` | `/cluster/node-1` | `/cluster/node-2` |
| identity/vote suffix | `0` | `1` | `2` |
| `log.path` | `/cluster/node-0/firedancer.log` | `/cluster/node-1/firedancer.log` | `/cluster/node-2/firedancer.log` |
| `hugetlbfs.mount_path` | `/mnt/.fd-cluster-0` | `/mnt/.fd-cluster-1` | `/mnt/.fd-cluster-2` |
| `gossip.entrypoints` | `[]` | `["127.0.0.1:8001"]` | `["127.0.0.1:8001"]` |
| gossip port | `8001` | `8101` | `8201` |
| shred port | `8003` | `8103` | `8203` |
| Votor server/client | `8004` / `8005` | `8104` / `8105` | `8204` / `8205` |
| repair client/server | `8701` / `8702` | `8801` / `8802` | `8901` / `8903` |
| TPU UDP/QUIC | `9001` / `9007` | `9101` / `9107` | `9201` / `9207` |
| txsend source | `9006` | `9106` | `9206` |
| metrics | `7999` | `8099` | `8199` |
| RPC | `8899` | `8999` | `9099` |
| leader shred destinations | `8103, 8203` | `8003, 8203` | `8003, 8103` |

The TPU QUIC port must always equal the regular TPU port plus six. Any other
enabled listener, including a snapshot HTTP server, also needs a unique port.
The explicit leader shred destinations make delivery deterministic in this
small loopback cluster.

The small accounts, slot, fork, and cache values above are a smoke-test
profile. The prior three-node test required about 85 GiB of 2 MiB huge pages;
measure the exact total for the current configs with `mem`. Raise
`runtime.max_live_slots` and the associated pools for longer fuzz campaigns.
A 64-slot pool can fill if a whole validator is suspended while the rest of
the cluster keeps advancing.

### 4. Assign CPUs and prepare the host

Do not leave `layout.affinity = "auto"` in every config. Each process would
independently choose the same CPUs. Assign disjoint logical CPUs to the
validators, and keep both SMT siblings with the same validator when possible.

For reference, the successful 96-logical-CPU test used this machine-specific
split, leaving CPUs 0 and 48 for the host:

```text
node 0: 1-15,49-63  (includes spare CPUs for snapshot-production tiles)
node 1: 16-28,64-76
node 2: 29-41,77-89
```

Inspect every topology before reserving memory:

```sh
for cfg in /cluster/node-{0,1,2}.toml; do
  build/firedancer-dev --config "$cfg" --alpenglow mem --sort
done
```

The launcher passes `--no-configure`, so standard Firedancer host setup is a
hard prerequisite. Initialize any missing global stages once using node 0's
config. Do not replace the shared keys or genesis with the configure command's
generated development versions.

Then initialize the cluster-specific huge-page mount and CPU partition for
each node:

```sh
for cfg in /cluster/node-{0,1,2}.toml; do
  sudo build/firedancer-dev --config "$cfg" --alpenglow \
    configure init hugetlbfs cpuset
done
```

The distinct `hugetlbfs.mount_path` values are intentional: they let each
configure invocation reserve its validator's pages. Total huge pages must
cover the sum of all validators. A shared mount is possible, but configuring
one `min_size` mount only reserves one topology's requirement.

### 5. Launch the cluster

```sh
sudo build/firedancer-cluster \
  --log-dir /cluster/logs \
  --validators 3 \
  --config-pattern '/cluster/node-{index}.toml'
```

Or list the configs explicitly:

```sh
sudo build/firedancer-cluster \
  --log-dir /cluster/logs \
  /cluster/node-0.toml \
  /cluster/node-1.toml \
  /cluster/node-2.toml
```

All options must appear before positional config paths. A pattern must
contain exactly one literal `{index}`. The supported validator count is 1 to
256. The launcher finds an adjacent `firedancer-dev` automatically; use
`--firedancer PATH` to override it.

With `--log-dir`, both stdout and stderr from validator `N` go to
`validator-N.stderr.log`. Files are truncated on each launch:

```sh
sudo tail -F /cluster/logs/validator-*.stderr.log
```

### 6. Assert that every validator finalized at least eight blocks

The launcher supervises processes; it does not implement a readiness or block
finality assertion. In Bash, with `curl` and `jq` installed, run this
separately:

```sh
set -eu

for port in 8899 8999 9099; do
  deadline=$((SECONDS + 180))
  while :; do
    height=$(
      curl -fsS -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getBlockHeight","params":[{"commitment":"finalized"}]}' \
        "http://127.0.0.1:$port" 2>/dev/null |
        jq -er '.result // empty' 2>/dev/null
    ) || height=

    case "$height" in
      ''|*[!0-9]*) ;;
      *)
        if [ "$height" -ge 8 ]; then
          echo "RPC $port finalized block height $height"
          break
        fi
        ;;
    esac

    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "RPC $port did not finalize eight blocks within 180 seconds" >&2
      exit 1
    fi
    sleep 1
  done
done
```

The command succeeds only after all three RPC endpoints report a finalized
height of at least eight.

## Supervision and shutdown

Each validator gets its own process group. `SIGINT`, `SIGTERM`, and `SIGHUP`
sent to the launcher are forwarded to every group. If any validator exits,
the launcher terminates all siblings, waits five seconds, then sends
`SIGKILL`. Linux `PR_SET_PDEATHSIG` prevents validators from surviving an
abruptly killed launcher. Any child exit makes the launcher exit nonzero;
Ctrl-C normally results in status 130.

After stopping the launcher, optional per-node host cleanup is:

```sh
for cfg in /cluster/node-{0,1,2}.toml; do
  sudo build/firedancer-dev --config "$cfg" --alpenglow \
    configure fini cpuset hugetlbfs
done
```
