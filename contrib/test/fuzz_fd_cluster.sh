#!/usr/bin/env bash
# Run the netctl cluster under random fault injection, iteration after
# iteration, until a run fails or DEADLINE_MIN passes.
#
# Each iteration boots the cluster from genesis, starts the fault
# injector once every validator has launched, and waits for every
# validator to root ROOT.  A stall or lag snapshots every node's metrics
# while the run goes on.  A pass keeps only the fault schedule; a
# failure keeps every log and snapshot, writes failure.txt and ends the
# loop.  touch $OUT/STOP ends it after the current iteration.
#
# Exit: 0 deadline or STOP, 1 cluster failure, 2 harness problem.
set -uo pipefail

FD=${FD:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}
C=${C:-$(dirname -- "$FD")/cluster}
OUT=${OUT:-$C/fuzz}
ROOT=${ROOT:-128}
TIMEOUT=${TIMEOUT:-300}
INTERVAL=${INTERVAL:-1} # rr only: seconds per partition
DEADLINE_MIN=${DEADLINE_MIN:-110}
INJECTOR=${INJECTOR:-random} # random: inject_fd_cluster_faults.sh, seeded per iteration; rr: rotate_fd_cluster_partitions.sh

runner=$FD/contrib/test/run_fd_cluster.sh
summary=$OUT/summary.log
nodes=$( ls "$C"/node-*.toml | wc -l )
mkdir -p "$OUT"

STALL_S=${STALL_S:-8}      # seconds without root progress that count as a stall
LAG_SLOTS=${LAG_SLOTS:-64} # a node this far behind the highest root lags

# watch_stall polls every node's root from inside the cluster's network
# namespace and snapshots all their metrics once the highest root stops
# advancing for STALL_S seconds, or a node stays more than LAG_SLOTS
# behind it that long: the state a failure needs explained, captured
# before an abort ends the run.  At most 3 snapshots, each after a fresh
# STALL_S window.
watch_stall() {
  local dir=$1 snaps=0 pid n r max min last_max=-1 stall_t=$SECONDS lag_t=-1 reason
  while kill -0 "$run_pid" 2>/dev/null && (( snaps<3 )); do
    sleep 2
    pid=$( pgrep -f '^[^ ]*fd-netctl run' | head -1 )
    [[ -n $pid ]] || continue
    max=-1 min=-1
    for (( n=0; n<nodes; n++ )); do
      r=$( sudo nsenter -t "$pid" -n curl -s --max-time 1 "http://127.0.0.1:$(( 10000+100*n+99 ))/metrics" 2>/dev/null \
           | awk '/^replay_root_slot[{ ]/ { print $NF; exit }' )
      [[ $r =~ ^[0-9]+$ ]] || continue
      (( max<0 || r>max )) && max=$r
      (( min<0 || r<min )) && min=$r
    done
    if (( max<=0 )); then stall_t=$SECONDS; continue; fi # still booting
    if (( max!=last_max )); then last_max=$max; stall_t=$SECONDS; fi
    if (( max-min>LAG_SLOTS )); then (( lag_t>=0 )) || lag_t=$SECONDS; else lag_t=-1; fi
    reason=
    (( SECONDS-stall_t>=STALL_S )) && reason="highest root stuck at $max for $(( SECONDS-stall_t ))s"
    (( lag_t>=0 && SECONDS-lag_t>=STALL_S )) && reason="${reason:+$reason; }a root at $min trails $max"
    [[ -n $reason ]] || continue
    mkdir -p "$dir/metrics-$snaps"
    printf '%s %s\n' "$(date +%T)" "$reason" >"$dir/metrics-$snaps/reason"
    for (( n=0; n<nodes; n++ )); do
      sudo nsenter -t "$pid" -n curl -s --max-time 2 "http://127.0.0.1:$(( 10000+100*n+99 ))/metrics" >"$dir/metrics-$snaps/node-$n.prom" 2>/dev/null
    done
    log "iter $iter: metrics-$snaps saved ($reason)"
    snaps=$(( snaps+1 ))
    stall_t=$SECONDS
    lag_t=-1
  done
}
deadline=$(( $(date +%s) + 60*DEADLINE_MIN ))
iter=$( { ls -d "$OUT"/iter-* 2>/dev/null || true; } | sed 's/.*iter-//' | sort -n | tail -1 )
iter=${iter:-0}

log() { printf '%s %s\n' "$(date +%T)" "$*" | tee -a "$summary"; }

# start_injector starts the fault injector for this iteration.  A
# restart reuses the iteration's seed, so it replays the same choices.
start_injector() {
  if [[ $INJECTOR == random ]]; then
    NODES=$nodes SEED=$seed "$FD/contrib/test/inject_fd_cluster_faults.sh" >>"$dir/faults.log" 2>&1 &
  else
    "$FD/contrib/test/rotate_fd_cluster_partitions.sh" "$INTERVAL" >>"$dir/faults.log" 2>&1 &
  fi
  ts_pid=$!
}

harness=0
run_pid=
stop_run() {
  # Ask the controller to stop so it removes its rules and socket.
  if [[ -n $run_pid ]] && kill -0 "$run_pid" 2>/dev/null; then
    C=$C "$runner" netctl stop >/dev/null 2>&1 || true
    wait "$run_pid" 2>/dev/null
  fi
}
trap 'stop_run; log "loop interrupted"; exit 2' INT TERM

while :; do
  if [[ -e $OUT/STOP ]]; then log "stop requested after $iter iterations"; exit 0; fi
  if (( $(date +%s) >= deadline )); then log "deadline reached after $iter iterations, no failure"; exit 0; fi

  iter=$(( iter+1 ))
  dir=$OUT/iter-$iter
  mkdir -p "$dir"
  start=$(date +%s)
  seed=${SEED:-$RANDOM} # SEED fixes every iteration's schedule, to reproduce a failure

  C=$C "$runner" net --root-slot "$ROOT" --timeout "$TIMEOUT" --jobs 16 >"$dir/run.log" 2>&1 &
  run_pid=$!
  # Inject once every validator has launched: the controller is ready
  # well before the cluster, and faults before then hit nothing.
  while kill -0 "$run_pid" 2>/dev/null && (( $( sed 's/\x1b\[[0-9;]*m//g' "$dir/run.log" | grep -cE 'validator fd-cluster-[0-9]+ pid' ) < nodes )); do sleep 0.2; done

  ts_pid=
  watch_pid=
  if kill -0 "$run_pid" 2>/dev/null; then
    start_injector
    watch_stall "$dir" &
    watch_pid=$!
  fi

  # An injector that stops while the cluster runs means faults stopped
  # too.  A control request can fail while the controller is busy (the
  # validator boot burst), so heal and restart it a few times before
  # giving up on the iteration; rr's dead session also needs the heal.
  ts_died=0
  ts_restarts=0
  while kill -0 "$run_pid" 2>/dev/null; do
    if [[ -n $ts_pid ]] && ! kill -0 "$ts_pid" 2>/dev/null; then
      kill -0 "$run_pid" 2>/dev/null || break # the run ended first
      if (( ts_restarts>=3 )); then ts_died=1; break; fi
      ts_restarts=$(( ts_restarts+1 ))
      log "iter $iter: injector exited ($( tail -n1 "$dir/faults.log" | cut -c1-80 )); heal and restart $ts_restarts"
      C=$C "$runner" netctl heal >>"$dir/faults.log" 2>&1 || true
      start_injector
    fi
    sleep 1
  done
  if (( ts_died )); then
    stop_run
    [[ -n $watch_pid ]] && { kill "$watch_pid" 2>/dev/null; wait "$watch_pid" 2>/dev/null; }
    harness=$(( harness+1 ))
    log "iter $iter HARNESS: the fault injector kept exiting (see $dir/faults.log)"
    if (( harness>=3 )); then log "stopping after $harness consecutive harness failures"; exit 2; fi
    continue
  fi
  harness=0
  wait "$run_pid"; rc=$?
  run_pid=
  [[ -n $watch_pid ]] && { kill "$watch_pid" 2>/dev/null; wait "$watch_pid" 2>/dev/null; }

  # The injector exits once the controller's socket is gone.
  for _ in $(seq 20); do [[ -z $ts_pid ]] || ! kill -0 "$ts_pid" 2>/dev/null && break; sleep 0.5; done
  [[ -n $ts_pid ]] && kill -0 "$ts_pid" 2>/dev/null && kill "$ts_pid" 2>/dev/null || true

  dur=$(( $(date +%s)-start ))
  faults=$( grep -c 'FAULT applied' "$dir/faults.log" 2>/dev/null || true )
  clean=$( sed 's/\x1b\[[0-9;]*m//g' "$dir/run.log" )

  if (( rc==0 )) && grep -q ': pass' <<<"$clean"; then
    if compgen -G "$dir/metrics-*" >/dev/null; then
      # It recovered from a stall or lag; keep what the snapshots caught.
      log "iter $iter PASS ${dur}s faults=${faults:-0} seed=$seed (stalled; kept logs and metrics)"
    else
      log "iter $iter PASS ${dur}s faults=${faults:-0} seed=$seed"
      rm -f "$dir/run.log" # boots from genesis every time, so only the schedule matters
    fi
    continue
  fi

  if ! grep -q 'Network ready' <<<"$clean"; then
    log "iter $iter HARNESS: rc=$rc before the cluster started (see $dir/run.log)"
    exit 2
  fi

  # The fault controller gives up when its own limits are hit (delay
  # buffer, copy size): a harness problem, not a cluster failure.
  if grep -q 'test invalid' <<<"$clean"; then
    harness=$(( harness+1 ))
    log "iter $iter HARNESS: $( grep -m1 'test invalid' <<<"$clean" | cut -c1-120 )"
    if (( harness>=3 )); then log "stopping after $harness consecutive harness failures"; exit 2; fi
    continue
  fi

  grep -E 'INVARIANT|exited before|did not root|failed with|CRIT|FAIL:|Segmentation|Aborted' <<<"$clean" \
    | grep -v 'configure' | head -40 >"$dir/failure.txt"
  log "iter $iter FAIL rc=$rc ${dur}s faults=${faults:-0} seed=$seed: $(head -n1 "$dir/failure.txt" | cut -c1-160)"
  exit 1
done
