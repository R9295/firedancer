#!/usr/bin/env bash
# Build and test an existing local three-validator Alpenglow cluster.
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: run_fd_cluster.sh [COMMAND] [OPTIONS]' \
    '' \
    'Commands:' \
    '  test     Build, configure the host, and run the test (default)' \
    '  build    Build firedancer-dev and test_firedancer_cluster' \
    '  init     Configure sysctl, huge pages, CPUs, and snapshot directories' \
    '  run      Run the test using an already prepared host' \
    '  mem      Show the memory reservation for each node' \
    '  logs     Follow the three default node log files' \
    '  fini     Remove the cluster CPU partitions and huge-page mounts' \
    '' \
    'Options:' \
    '  --root-slot N   Slot every node must root (default: 8)' \
    '  --timeout N     Timeout in seconds (default: 180)' \
    '  --jobs N        Parallel build jobs (default: 8)' \
    '  -h, --help      Show this help' \
    '' \
    'Environment: FD (repository), C (cluster directory),' \
    '  FD_CLUSTER_ROOT_SLOT, FD_CLUSTER_TIMEOUT_S, FD_CLUSTER_BUILD_JOBS.' \
    'C defaults to the cluster directory alongside the repository.' \
    'Existing node-0.toml, node-1.toml, node-2.toml, keys, and genesis are required.' \
    'Run as your normal user; privileged commands request sudo as needed.' \
    'The test stops its validators when it finishes. Use fini for host cleanup.'
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

action=test
action_set=0
root_slot=${FD_CLUSTER_ROOT_SLOT:-8}
timeout_s=${FD_CLUSTER_TIMEOUT_S:-180}
jobs=${FD_CLUSTER_BUILD_JOBS:-8}
while (( $# )); do
  case "$1" in
    test|build|init|run|mem|logs|fini)
      (( !action_set )) || fail 'Specify only one command.'
      action=$1
      action_set=1
      shift
      ;;
    --root-slot|--timeout|--jobs)
      (( $#>=2 )) || fail "Missing value for $1."
      case "$1" in
        --root-slot) root_slot=$2 ;;
        --timeout)   timeout_s=$2 ;;
        --jobs)      jobs=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1 (see --help)." ;;
  esac
done
[[ $root_slot =~ ^[1-9][0-9]*$ ]] || fail 'Root slot must be a positive integer.'
[[ $timeout_s =~ ^[1-9][0-9]*$ ]] || fail 'Timeout must be a positive integer.'
[[ $jobs =~ ^[1-9][0-9]*$ ]] || fail 'Build jobs must be a positive integer.'

FD=${FD:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}
FD=$(cd -- "$FD" && pwd)
C=${C:-$(dirname -- "$FD")/cluster}

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
  if [[ $action == run || $action == test ]]; then
    [[ -x $test_bin ]] || fail "Missing $test_bin; run this script with build first."
  fi
}

init() {
  command -v python3 >/dev/null || fail 'python3 is required to plan the cluster huge-page pools.'
  printf 'Preparing the host for three nodes (about 34 GiB of huge pages).\n'
  as_root "$dev" --config "${configs[0]}" --alpenglow configure init sysctl
  as_root python3 "$FD/contrib/test/reserve_fd_cluster_pages.py" --dev "$dev" "${configs[@]}"
  for cfg in "${configs[@]}"; do
    # Startup opens the snapshot directory even when bootstrapping from genesis.
    as_root "$dev" --config "$cfg" --alpenglow configure init hugetlbfs cpuset snapshots
  done
}

run() {
  local config_spec
  config_spec=$(IFS=:; printf '%s' "${configs[*]}")
  printf 'Waiting for all three nodes to root slot %s (timeout: %ss).\n' "$root_slot" "$timeout_s"
  # env must be inside sudo so its environment filtering cannot drop the
  # test settings and silently turn this into the test's skip path.
  as_root env "FD_CLUSTER_CONFIGS=$config_spec" \
    "FD_CLUSTER_ROOT_SLOT=$root_slot" "FD_CLUSTER_TIMEOUT_S=$timeout_s" "$test_bin"
}

fini() {
  local status=0
  # Try every node even if one cleanup fails; retain a failing exit code.
  for ((i=${#configs[@]}-1; i>=0; i--)); do
    as_root "$dev" --config "${configs[i]}" --alpenglow configure fini cpuset hugetlbfs || status=1
  done
  return "$status"
}

if [[ $action == build ]]; then build; exit 0; fi
[[ -d $C ]] || fail "Cluster directory not found: $C"
C=$(cd -- "$C" && pwd)
if [[ $action == logs ]]; then
  exec tail -n 50 -F "$C/node-0/firedancer.log" "$C/node-1/firedancer.log" "$C/node-2/firedancer.log"
fi
[[ $C != *:* ]] || fail 'Cluster directory must not contain a colon.'
configs=("$C/node-0.toml" "$C/node-1.toml" "$C/node-2.toml")
for cfg in "${configs[@]}"; do
  [[ -r $cfg ]] || fail "Node configuration not readable: $cfg"
done

if [[ $action == test ]]; then build; fi
locate_binaries
case "$action" in
  test) init; run ;;
  init) init ;;
  run)  run ;;
  fini) fini ;;
  mem)
    for cfg in "${configs[@]}"; do
      printf '\nMemory reservation for %s:\n' "$cfg"
      "$dev" --config "$cfg" --alpenglow mem --sort
    done
    ;;
esac
