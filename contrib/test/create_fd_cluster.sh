#!/usr/bin/env bash
# Create an equal-stake local Alpenglow cluster without overwriting an existing one.
set -euo pipefail

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

FD=${FD:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}
FD=$(cd -- "$FD" && pwd)
C=${C:-$(dirname -- "$FD")/cluster-10}
node_count=${FD_CLUSTER_NODES:-10}
keygen=${SOLANA_KEYGEN:-$(command -v solana-keygen || true)}
genesis=${SOLANA_GENESIS:-$FD/agave/target/release/solana-genesis}

[[ $C == /* && $C != / ]] || fail 'C must be an absolute, non-root path.'
[[ $C != *$'\n'* && $C != *'"'* && $C != *'\'* ]] \
  || fail 'C must not contain a newline, quote, or backslash.'
[[ $node_count =~ ^[0-9]+$ ]] && (( node_count>=2 && node_count<=128 )) \
  || fail 'FD_CLUSTER_NODES must be in 2..128.'
[[ -n $keygen && -x $keygen ]] || fail 'solana-keygen is required (or set SOLANA_KEYGEN).'
[[ -x $genesis ]] || fail "Missing $genesis; build solana-genesis or set SOLANA_GENESIS."
[[ ! -e $C ]] || fail "$C already exists; choose a new C so existing keys and ledger are not overwritten."

expand_cpu_list() {
  local list=$1 range first last cpu
  local -a ranges
  IFS=, read -r -a ranges <<<"$list"
  for range in "${ranges[@]}"; do
    if [[ $range == *-* ]]; then
      first=${range%-*}
      last=${range#*-}
    else
      first=$range
      last=$range
    fi
    [[ $first =~ ^[0-9]+$ && $last =~ ^[0-9]+$ && $first -le $last ]] \
      || fail "Invalid CPU list from sysfs: $list"
    for ((cpu=first; cpu<=last; cpu++)); do printf '%s\n' "$cpu"; done
  done
}

# A validator has 24 affinity entries in this reduced test topology.  Shared
# entries let those tiles use a smaller CPU set, but unlike plain `f24` they
# also give workspace placement a NUMA home.  Give every validator disjoint
# whole physical cores and distribute validators round-robin across NUMA.
plan_affinities() {
  local -a numa_paths cpus validators
  local -A core_owner
  local numa_count slot node_path cpu_list cpu package core key owner
  local node_numa_id core_count validator_count i tile affinity

  shopt -s nullglob
  numa_paths=(/sys/devices/system/node/node[0-9]*)
  shopt -u nullglob
  (( ${#numa_paths[@]} )) || fail 'No NUMA CPU topology found in sysfs.'
  numa_count=${#numa_paths[@]}

  for ((i=0; i<node_count; i++)); do
    node_cpu_lists[i]=''
    node_numa[i]=''
  done

  for ((slot=0; slot<numa_count; slot++)); do
    validators=()
    for ((i=slot; i<node_count; i+=numa_count)); do validators+=("$i"); done
    (( ${#validators[@]} )) || continue
    validator_count=${#validators[@]}
    node_path=${numa_paths[slot]}
    node_numa_id=${node_path##*node}
    cpu_list=$(<"$node_path/cpulist")
    mapfile -t cpus < <(expand_cpu_list "$cpu_list")
    (( ${#cpus[@]} )) || fail "NUMA $node_numa_id has no CPUs."

    core_owner=()
    core_count=0
    for cpu in "${cpus[@]}"; do
      if [[ -r /sys/devices/system/cpu/cpu$cpu/online ]] \
          && [[ $(</sys/devices/system/cpu/cpu$cpu/online) != 1 ]]; then
        continue
      fi
      package=$(</sys/devices/system/cpu/cpu$cpu/topology/physical_package_id)
      core=$(</sys/devices/system/cpu/cpu$cpu/topology/core_id)
      key=$package:$core
      if [[ ! -v core_owner[$key] ]]; then
        # Keep one complete physical core on each used NUMA node for the host.
        if (( core_count==0 )); then
          owner=-1
        else
          owner=${validators[(core_count-1)%validator_count]}
        fi
        core_owner[$key]=$owner
        ((core_count+=1))
      fi
      owner=${core_owner[$key]}
      if (( owner>=0 )); then
        node_cpu_lists[owner]+="${node_cpu_lists[owner]:+ }$cpu"
        node_numa[owner]=$node_numa_id
      fi
    done
    (( core_count-1>=validator_count )) \
      || fail "NUMA $node_numa_id needs at least $((validator_count+1)) physical cores for $validator_count validators and the host."
  done

  for ((i=0; i<node_count; i++)); do
    read -r -a cpus <<<"${node_cpu_lists[i]}"
    (( ${#cpus[@]} )) || fail "No CPU was assigned to validator $i."
    affinity=
    for ((tile=0; tile<24; tile++)); do
      cpu=${cpus[tile%${#cpus[@]}]}
      affinity+="${affinity:+,}s$cpu"
    done
    affinities[i]=$affinity
  done
}

declare -a affinities node_cpu_lists node_numa
plan_affinities

user=$(id -un)
[[ $user =~ ^[A-Za-z0-9_.-]+$ ]] || fail 'The current user name is not valid in a Firedancer config.'
install -d "$C/keys" "$C/ledger" "$C/logs"
for ((i=0; i<node_count; i++)); do install -d "$C/node-$i"; done

printf 'Creating keys for %s equal-stake validators...\n' "$node_count"
"$keygen" new --no-bip39-passphrase --silent --force --outfile "$C/keys/faucet.json"
genesis_args=()
for ((i=0; i<node_count; i++)); do
  "$keygen" new --no-bip39-passphrase --silent --force --outfile "$C/keys/identity-$i.json"
  "$keygen" new --no-bip39-passphrase --silent --force --outfile "$C/keys/vote-$i.json"
  "$keygen" new --no-bip39-passphrase --silent --force --outfile "$C/keys/stake-$i.json"
  bls=$("$keygen" bls_pubkey "$C/keys/identity-$i.json")
  genesis_args+=(
    --bootstrap-validator
    "$C/keys/identity-$i.json"
    "$C/keys/vote-$i.json"
    "$C/keys/stake-$i.json"
    --bootstrap-validator-bls-pubkey "$bls"
  )
done

printf 'Creating the shared Alpenglow genesis...\n'
if ! genesis_output=$("$genesis" \
  --alpenglow \
  --cluster-type development \
  --ledger "$C/ledger" \
  --slots-per-epoch 256 \
  --faucet-pubkey "$C/keys/faucet.json" \
  --faucet-lamports 500000000000000000 \
  --bootstrap-validator-lamports 500000000000 \
  --bootstrap-validator-stake-lamports 1000000000 \
  "${genesis_args[@]}" 2>&1); then
  printf '%s\n' "$genesis_output" >&2
  fail 'solana-genesis failed.'
fi
printf '%s\n' "$genesis_output"
genesis_hash=$(awk '/Genesis hash:/ { for (i=1; i<=NF; i++) if ($i=="hash:") { print $(i+1); exit } }' <<<"$genesis_output")
[[ -n $genesis_hash ]] || fail 'Could not read the genesis hash.'

for ((i=0; i<node_count; i++)); do
  base=$((10000 + 100*i))
  if (( i==0 )); then
    entrypoints='[]'
  else
    entrypoints='["127.0.0.1:10001"]'
  fi
  config=$C/node-$i.toml
  {
    printf '%s\n' \
      "name = \"fd-cluster-$i\"" \
      "user = \"$user\"" \
      'telemetry = false' \
      '' \
      '[paths]' \
      "    base = \"$C/node-$i\"" \
      "    identity_key = \"$C/keys/identity-$i.json\"" \
      "    vote_account = \"$C/keys/vote-$i.json\"" \
      "    genesis = \"$C/ledger/genesis.bin\"" \
      '' \
      '[log]' \
      "    path = \"$C/node-$i/firedancer.log\"" \
      '' \
      '[gossip]' \
      "    entrypoints = $entrypoints" \
      '    host = "127.0.0.1"' \
      "    port = $((base+1))" \
      '' \
      '[snapshots]' \
      '    genesis_download = false' \
      '' \
      '[consensus]' \
      "    expected_genesis_hash = \"$genesis_hash\"" \
      '    wait_for_vote_to_start_leader = false' \
      '' \
      '[accounts]' \
      '    max_accounts = 65536' \
      '    cache_size_gib = 3' \
      '' \
      '[runtime]' \
      '    max_live_slots = 64' \
      '    max_fork_width = 4' \
      '    program_cache_size_mib = 256' \
      '' \
      '[layout]' \
      "    affinity = \"${affinities[i]}\"" \
      '    net_tile_count = 1' \
      '    quic_tile_count = 1' \
      '    resolv_tile_count = 1' \
      '    verify_tile_count = 1' \
      '    gossvf_tile_count = 1' \
      '    execle_tile_count = 1' \
      '    execrp_tile_count = 1' \
      '    snapdc_tile_count = 1' \
      '    snapzp_tile_count = 1' \
      '    snapsv_tile_count = 1' \
      '    snapsv_io_worker_count = 1' \
      '    shred_tile_count = 1' \
      '    sign_tile_count = 2' \
      '    enable_block_production = true' \
      '    enable_snapshot_production = false' \
      '' \
      '[hugetlbfs]' \
      "    mount_path = \"/mnt/.fd-cluster-$i\"" \
      '    max_page_size = "huge"' \
      '' \
      '[net]' \
      '    provider = "socket"' \
      '    interface = "lo"' \
      '    bind_address = "127.0.0.1"' \
      '    ingress_buffer_size = 1024' \
      '' \
      '[tiles.gossip]' \
      '    max_entries = 8192' \
      '' \
      '[tiles.quic]' \
      '    max_concurrent_connections = 512' \
      '    max_concurrent_handshakes = 64' \
      '    txn_reassembly_count = 1024' \
      "    regular_transaction_listen_port = $((base+11))" \
      "    quic_transaction_listen_port = $((base+17))" \
      '' \
      '[tiles.verify]' \
      '    signature_cache_size = 65534' \
      '    receive_buffer_size = 1024' \
      '' \
      '[tiles.dedup]' \
      '    signature_cache_size = 65534' \
      '' \
      '[tiles.pack]' \
      '    max_pending_transactions = 4096' \
      '' \
      '[tiles.replay]' \
      '    max_transaction_lookahead_buffer_size = 4096' \
      '' \
      '[tiles.shred]' \
      '    max_pending_shred_sets = 1024' \
      "    shred_listen_port = $((base+3))" \
      '    shred_cache_size_mib = 64' \
      '    additional_shred_destinations_leader = ['
    for ((j=0; j<node_count; j++)); do
      if (( j!=i )); then printf '        "127.0.0.1:%s",\n' "$((10000 + 100*j + 3))"; fi
    done
    printf '%s\n' \
      '    ]' \
      '' \
      '[tiles.repair]' \
      "    repair_client_listen_port = $((base+71))" \
      '    slot_max = 128' \
      '' \
      '[tiles.rotor]' \
      '    slot_max = 128' \
      '' \
      '[tiles.rserve]' \
      "    repair_serve_listen_port = $((base+72))" \
      '    shred_storage_limit_gib = 1' \
      '' \
      '[tiles.txsend]' \
      "    txsend_src_port = $((base+16))" \
      '' \
      '[tiles.metric]' \
      "    prometheus_listen_port = $((base+99))" \
      '' \
      '[tiles.gui]' \
      '    enabled = false' \
      '' \
      '[tiles.rpc]' \
      '    enabled = false' \
      '' \
      '[development]' \
      '    alpenglow = true' \
      '    bootstrap = true' \
      '' \
      '[development.runtime]' \
      '    max_stake_accounts = 4096' \
      '    max_stake_accounts_fallback = 65536' \
      '    max_vote_accounts = 64' \
      '' \
      '[development.votor]' \
      "    quic_client_listen_port = $((base+5))" \
      "    quic_server_listen_port = $((base+4))" \
      '' \
      '[development.gossip]' \
      '    allow_private_address = true' \
      '' \
      '[development.genesis]' \
      '    validate_genesis_hash = false' \
      '' \
      '[development.accdb]' \
      '    partition_size_gib = 1'
  } >"$config"
done

stake_percent=$(awk -v n="$node_count" 'BEGIN { printf "%.2f", 100/n }')
printf 'Created %s validators at %s with equal stake (%s%% each).\n' \
  "$node_count" "$C" "$stake_percent"
for ((i=0; i<node_count; i++)); do
  printf '  node %s: NUMA %s, shared CPUs [%s]\n' "$i" "${node_numa[i]}" "${node_cpu_lists[i]}"
done
printf 'Next: C=%q %q init\n' "$C" "$FD/contrib/test/run_fd_cluster.sh"
