#!/usr/bin/env bash
# Round-robin single-node partitions through the controller's TypeSafe
# protocol, without the API: isolate node 0, 1, ..., N-1, 0, ... one per
# INTERVAL seconds, the schedule TypeSafe chose in every run so far.
# Exits when the controller goes away.
set -uo pipefail

SOCK=${FD_NETCTL_SOCKET:-/run/fd-netctl/control.sock}
NETCTL=${NETCTL:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/fd-netctl/target/release/fd-netctl}
INTERVAL=${1:-1}

ctl() { sudo "$NETCTL" ctl "$SOCK" "$@"; }

start=$(ctl typesafe-start) || exit 1
instance=$(jq -r .instance <<<"${start#OK }")
session=$(jq -r .session <<<"${start#OK }")
nodes=$(jq -r .node_count <<<"${start#OK }")
echo "round-robin: $nodes single-node partitions, interval=${INTERVAL}s"

i=0
while :; do
  state=$(ctl typesafe-state 2>/dev/null) || exit 0
  [[ $(jq -r .session <<<"${state#OK }") == "$session" ]] || exit 0
  gen=$(jq -r .generation <<<"${state#OK }")
  ctl typesafe-partition "$instance" "$session" "$gen" "partition_node_$(( i%nodes ))" || exit 0
  i=$(( i+1 ))
  sleep "$INTERVAL"
done
