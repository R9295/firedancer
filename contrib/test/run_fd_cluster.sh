#!/usr/bin/env bash
# Build and test an existing local Alpenglow cluster.
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: run_fd_cluster.sh [COMMAND] [OPTIONS]' \
    '' \
    'Commands:' \
    '  create   Create equal-stake keys, genesis, and node configs (default: 10)' \
    '  test     Build, configure the host, and run the test (default)' \
    '  build    Build firedancer-dev and test_firedancer_cluster' \
    '  init     Configure sysctl, huge pages, CPUs, and snapshot directories' \
    '  run      Run the test using an already prepared host' \
    '  net      Build, prepare the host, and run with the Rust network controller' \
    '  netctl   Send a controller command: status | block N M | allow N M | heal | stop' \
    '           delay N M MS | duplicate N M 0|1 (one extra copy)' \
    '           typesafe [SECONDS] (automatic single-node partition; default: 1s)' \
    '  mem      Show the memory reservation for each node' \
    '  logs     Follow all default node log files' \
    '  fini     Remove CPU partitions, huge-page mounts, and the HugePages pool' \
    '' \
    'Options:' \
    '  --root-slot N   Slot every node must root (default: 8; net: 256)' \
    '  --timeout N     Timeout in seconds (default: 180)' \
    '  --jobs N        Parallel build jobs (default: 8)' \
    '  -h, --help      Show this help' \
    '' \
    'Environment: FD (repository), C (cluster directory),' \
    '  FD_CLUSTER_ROOT_SLOT, FD_CLUSTER_TIMEOUT_S, FD_CLUSTER_BUILD_JOBS,' \
    '  FD_CLUSTER_NODES (create only; default: 10).' \
    '  FD_CLUSTER_CONFIGS: colon-separated absolute node config paths (1..128).' \
    '  FD_NETCTL_SOCKET: control socket (default: /run/fd-netctl/control.sock).' \
    'C defaults to the cluster directory alongside the repository.' \
    'By default, uses every C/node-*.toml in version order.' \
    'Run as your normal user; privileged commands request sudo as needed.' \
    'The test stops its validators when it finishes. Use fini for host cleanup.'
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

action=test
action_set=0
root_slot_set=${FD_CLUSTER_ROOT_SLOT+x}
control_args=(status)
root_slot=${FD_CLUSTER_ROOT_SLOT:-8}
timeout_s=${FD_CLUSTER_TIMEOUT_S:-180}
jobs=${FD_CLUSTER_BUILD_JOBS:-8}
while (( $# )); do
  case "$1" in
    netctl)
      (( !action_set )) || fail 'Specify only one command.'
      action=netctl
      shift
      if (( $# )); then control_args=("$@"); fi
      break
      ;;
    create|test|build|init|run|net|mem|logs|fini)
      (( !action_set )) || fail 'Specify only one command.'
      action=$1
      action_set=1
      shift
      ;;
    --root-slot|--timeout|--jobs)
      (( $#>=2 )) || fail "Missing value for $1."
      case "$1" in
        --root-slot) root_slot=$2; root_slot_set=1 ;;
        --timeout)   timeout_s=$2 ;;
        --jobs)      jobs=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1 (see --help)." ;;
  esac
done
if [[ $action == net && -z $root_slot_set ]]; then root_slot=256; fi
[[ $root_slot =~ ^[1-9][0-9]*$ ]] || fail 'Root slot must be a positive integer.'
[[ $timeout_s =~ ^[1-9][0-9]*$ ]] || fail 'Timeout must be a positive integer.'
[[ $jobs =~ ^[1-9][0-9]*$ ]] || fail 'Build jobs must be a positive integer.'

FD=${FD:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}
FD=$(cd -- "$FD" && pwd)
C=${C:-$(dirname -- "$FD")/cluster}
netctl_bin=$FD/contrib/test/fd-netctl/target/release/fd-netctl
netctl_socket=${FD_NETCTL_SOCKET:-/run/fd-netctl/control.sock}

if [[ $action == create ]]; then
  FD="$FD" C="$C" "$FD/contrib/test/create_fd_cluster.sh"
  exit 0
fi

as_root() {
  if (( EUID==0 )); then "$@"; else sudo -- "$@"; fi
}

# Preserve user ownership of build outputs even if invoked through sudo.
as_builder() {
  if (( EUID==0 )) && [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    sudo -u "$SUDO_USER" -- "$@"
  else
    "$@"
  fi
}

build() {
  as_builder make -C "$FD" -j"$jobs" firedancer-dev test_firedancer_cluster
}

locate_binaries() {
  local build_dir
  # Ask make for the active compiler/version/flavor instead of selecting
  # a possibly stale build/firedancer-dev or hardcoding a GCC version.
  build_dir=$(as_builder make -s --no-print-directory -C "$FD" \
    --eval='.PHONY: cluster-build-dir' \
    --eval='cluster-build-dir:;@printf "%s\n" "$(abspath $(OBJDIR))"' \
    cluster-build-dir)
  dev=$build_dir/bin/firedancer-dev
  test_bin=$build_dir/integration-test/test_firedancer_cluster
  [[ -x $dev ]] || fail "Missing $dev; run this script with build first."
  if [[ $action == run || $action == test || $action == net ]]; then
    [[ -x $test_bin ]] || fail "Missing $test_bin; run this script with build first."
  fi
}

init() {
  command -v python3 >/dev/null || fail 'python3 is required to plan the cluster huge-page pools.'
  printf 'Preparing the host for %s nodes.\n' "${#configs[@]}"
  as_root "$dev" --config "${configs[0]}" --alpenglow configure init sysctl

  # A rebuild can change a node's required min_size.  Release only stale
  # mounts before planning the pool so their old reservations are counted as
  # reusable capacity instead of as a new-cluster shortfall.  Valid mounts
  # remain reserved and are omitted from the new demand below.
  local stale_configs=()
  local cfg
  for cfg in "${configs[@]}"; do
    if ! as_root "$dev" --config "$cfg" --alpenglow configure check hugetlbfs >/dev/null 2>&1; then
      stale_configs+=("$cfg")
    fi
  done
  if (( ${#stale_configs[@]} )); then
    printf 'Refreshing huge-page mounts for %s nodes.\n' "${#stale_configs[@]}"
    local i
    for ((i=${#stale_configs[@]}-1; i>=0; i--)); do
      as_root "$dev" --config "${stale_configs[i]}" --alpenglow configure fini hugetlbfs
    done
    as_root python3 "$FD/contrib/test/reserve_fd_cluster_pages.py" --dev "$dev" "${stale_configs[@]}"
  fi
  for cfg in "${configs[@]}"; do
    # Startup opens the snapshot directory even when bootstrapping from genesis.
    as_root "$dev" --config "$cfg" --alpenglow configure init hugetlbfs cpuset snapshots
  done
}

run() {
  local config_spec
  config_spec=$(IFS=:; printf '%s' "${configs[*]}")
  printf 'Waiting for all %s nodes to root slot %s (timeout: %ss).\n' "${#configs[@]}" "$root_slot" "$timeout_s"
  # env must be inside sudo so its environment filtering cannot drop the
  # test settings and silently turn this into the test's skip path.
  as_root env "FD_CLUSTER_CONFIGS=$config_spec" \
    "FD_CLUSTER_ROOT_SLOT=$root_slot" "FD_CLUSTER_TIMEOUT_S=$timeout_s" "$test_bin"
}

net() {
  local config_spec
  config_spec=$(IFS=:; printf '%s' "${configs[*]}")
  as_builder cargo build --locked --release \
    --manifest-path "$FD/contrib/test/fd-netctl/Cargo.toml" \
    --target-dir "$FD/contrib/test/fd-netctl/target"
  printf 'Control links from another terminal: %s netctl (block/allow/delay/duplicate/heal/status/stop)\n' "$FD/contrib/test/run_fd_cluster.sh"
  printf 'Waiting for all %s nodes to root slot %s (timeout: %ss).\n' "${#configs[@]}" "$root_slot" "$timeout_s"
  as_root env "FD_CLUSTER_CONFIGS=$config_spec" \
    "FD_CLUSTER_ROOT_SLOT=$root_slot" "FD_CLUSTER_TIMEOUT_S=$timeout_s" \
    "$netctl_bin" run "$netctl_socket" "${configs[@]}" -- "$test_bin"
}

fini() {
  local status=0
  # Try every node even if one cleanup fails; retain a failing exit code.
  for ((i=${#configs[@]}-1; i>=0; i--)); do
    as_root "$dev" --config "${configs[i]}" --alpenglow configure fini cpuset hugetlbfs || status=1
  done
  # fdctl unmounts hugetlbfs but leaves its host-wide 2 MiB page pool reserved.
  as_root sysctl -w vm.nr_hugepages=0 || status=1
  return "$status"
}

if [[ $action == build ]]; then build; exit 0; fi
if [[ $action == netctl ]]; then
  [[ -x $netctl_bin ]] || fail 'Controller not built; launch with net first.'
  if [[ ${control_args[0]} == typesafe && $EUID != 0 ]]; then
    # Keep the key out of argv and out of the validator process environment.
    sudo --preserve-env=TYPESAFE_API_KEY,TYPESAFE_MODEL -- \
      "$netctl_bin" ctl "$netctl_socket" "${control_args[@]}"
  else
    as_root "$netctl_bin" ctl "$netctl_socket" "${control_args[@]}"
  fi
  exit 0
fi
if [[ ${FD_CLUSTER_CONFIGS+x} ]]; then
  [[ -n $FD_CLUSTER_CONFIGS && $FD_CLUSTER_CONFIGS != :* && $FD_CLUSTER_CONFIGS != *: && $FD_CLUSTER_CONFIGS != *::* && $FD_CLUSTER_CONFIGS != *$'\n'* ]] \
    || fail 'FD_CLUSTER_CONFIGS must contain nonempty colon-separated config paths.'
  IFS=: read -r -a configs <<< "$FD_CLUSTER_CONFIGS"
else
  [[ -d $C ]] || fail "Cluster directory not found: $C"
  C=$(cd -- "$C" && pwd)
  [[ $C != *:* ]] || fail 'Cluster directory must not contain a colon.'
  shopt -s nullglob
  configs=("$C"/node-*.toml)
  shopt -u nullglob
  (( ${#configs[@]} )) || fail "No node-*.toml configs found in $C."
  mapfile -t configs < <(printf '%s\n' "${configs[@]}" | sort -V)
fi
(( ${#configs[@]}>=1 && ${#configs[@]}<=128 )) || fail 'Provide between 1 and 128 node configs.'
for cfg in "${configs[@]}"; do
  [[ $cfg == /* ]] || fail "Node configuration path must be absolute: $cfg"
  [[ -r $cfg ]] || fail "Node configuration not readable: $cfg"
done

if [[ $action == logs ]]; then
  logs=()
  for ((i=0; i<${#configs[@]}; i++)); do logs+=("$C/node-$i/firedancer.log"); done
  exec tail -n 50 -F "${logs[@]}"
fi

if [[ $action == test || $action == net ]]; then build; fi
locate_binaries
case "$action" in
  test) init; run ;;
  init) init ;;
  run)  run ;;
  net)  init; net ;;
  fini) fini ;;
  mem)
    for cfg in "${configs[@]}"; do
      printf '\nMemory reservation for %s:\n' "$cfg"
      "$dev" --config "$cfg" --alpenglow mem --sort
    done
    ;;
esac
