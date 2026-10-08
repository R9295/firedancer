#!/usr/bin/env bash
# Random faults through the netctl controller, with no external service.
# Every step picks a stack of random faults and applies it with one
# controller apply command, which replaces the previous faults all at
# once.  It holds the faults for HOLD_MIN_MS..HOLD_MAX_MS (default
# 500..3000), then heals the network for GAP_MIN_MS..GAP_MAX_MS (default
# 0..3000) so the cluster can recover.  The first fault comes from these
# shares:
#
#   isolate    one node from all others, both directions        20%
#   split      a group of 2..NODES/2-1 nodes from the rest       12%
#   halves     an even split; no side can finalize while held     5%
#   bridge     groups X and Y cannot reach each other, but both   13%
#              reach one bridge node Z (partial connectivity)
#   oneway     a group of 1..NODES/2 nodes cannot send to the     12%
#              rest, or cannot receive from it; the other
#              direction works
#   loss       random packet loss of 1..LOSS_MAX_PCT percent on   10%
#              every link, or of up to 3x that (at most 90) on
#              all links of one node, in both directions
#   delay      1..3 random directed links, 10..DELAY_MAX_MS      10%
#   duplicate  NODES random directed links                        8%
#   heal       nothing, so the cluster can recover               10%
#
# In a bridge, X and Y each have 1..NODES-2 nodes and Z keeps every
# link.  Only Z receives every vote and shred, so X and Y can progress
# only on what Z relays and serves to them.
#
# Unless the first fault is heal, the step stacks up to STACK_MAX
# (default 3) faults: after each one, another follows with probability
# STACK_PCT percent (default 40), from the same shares without heal.
# The faults apply together: stacked partitions join their cuts, so two
# of them can leave three or more groups, and a delay or duplicate can
# sit on top of a partition.  A step has at most one delay fault, so
# the delay buffer below does not fill.  STACK_MAX=1 turns stacking off.
#
# Steps come in bursts of BURST_MIN..BURST_MAX (default 3..8).  After
# each burst the network is healed and stays healthy for
# QUIET_MIN_MS..QUIET_MAX_MS (default 10000..20000), so a stall or skip
# inside a quiet period cannot be blamed on a fault.  QUIET_MAX_MS=0
# turns quiet periods off.
#
# Faults are link rules, so they cover all cluster traffic between the
# chosen nodes.  The controller holds delayed packets in a 4096-packet
# buffer and declares the test invalid when it fills, so delays stay
# short and few.  SEED fixes the sequence of choices (not the timing),
# so a failing schedule can be rerun.  ONLY=KIND (one of the names
# above) makes every fault that kind; add STACK_MAX=1 for one fault per
# step.  Exits when the controller goes away.
set -uo pipefail

SOCK=${FD_NETCTL_SOCKET:-/run/fd-netctl/control.sock}
NETCTL=${NETCTL:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/fd-netctl/target/release/fd-netctl}
NODES=${NODES:?set NODES to the cluster size}
HOLD_MIN_MS=${HOLD_MIN_MS:-500}
HOLD_MAX_MS=${HOLD_MAX_MS:-3000}
GAP_MIN_MS=${GAP_MIN_MS:-0}
GAP_MAX_MS=${GAP_MAX_MS:-3000}
DELAY_MAX_MS=${DELAY_MAX_MS:-100}
LOSS_MAX_PCT=${LOSS_MAX_PCT:-20}
ONLY=${ONLY:-}
STACK_MAX=${STACK_MAX:-3}
STACK_PCT=${STACK_PCT:-40}
BURST_MIN=${BURST_MIN:-3}
BURST_MAX=${BURST_MAX:-8}
QUIET_MIN_MS=${QUIET_MIN_MS:-10000}
QUIET_MAX_MS=${QUIET_MAX_MS:-20000}
[[ $BURST_MIN =~ ^[1-9][0-9]*$ && $BURST_MAX =~ ^[0-9]+$ ]] && (( BURST_MIN<=BURST_MAX )) \
  || { echo 'BURST_MIN must be at least 1 and at most BURST_MAX' >&2; exit 2; }
[[ $QUIET_MIN_MS =~ ^[0-9]+$ && $QUIET_MAX_MS =~ ^[0-9]+$ ]] && (( QUIET_MIN_MS<=QUIET_MAX_MS )) \
  || { echo 'QUIET_MIN_MS must be at most QUIET_MAX_MS' >&2; exit 2; }
[[ $STACK_MAX =~ ^[1-9][0-9]*$ && $STACK_PCT =~ ^[0-9]+$ ]] && (( STACK_PCT<=100 )) \
  || { echo 'STACK_MAX must be at least 1 and STACK_PCT in 0..100' >&2; exit 2; }
[[ $LOSS_MAX_PCT =~ ^[0-9]+$ ]] && (( LOSS_MAX_PCT>=1 && LOSS_MAX_PCT<=30 )) \
  || { echo 'LOSS_MAX_PCT must be in 1..30' >&2; exit 2; }
SEED=${SEED:-$(( $(od -An -N4 -tu4 /dev/urandom) % 32768 ))}
RANDOM=$SEED

# The first roll of each fault's share of 0..99; a roll below the next
# fault's first roll picks it.
# The shares changed when oneway and loss were added, so a SEED from
# before then picks a different schedule.
declare -A first_roll=( [isolate]=0 [split]=20 [halves]=32 [bridge]=37 [oneway]=50 [loss]=62 [delay]=72 [duplicate]=82 [heal]=90 )
[[ -z $ONLY || -v first_roll[$ONLY] ]] || { echo "ONLY must be one of: ${!first_roll[*]}" >&2; exit 2; }

# ctl sends one controller command.
ctl() { sudo "$NETCTL" ctl "$SOCK" "$1" >/dev/null; }

# msleep sleeps for $1 milliseconds.
msleep() { sleep "$(( $1/1000 )).$(printf '%03d' $(( $1%1000 )))"; }

# shuffle leaves a random permutation of 0..NODES-1 in perm.  It reads
# RANDOM directly: a $( ) subshell would not advance the seeded stream.
shuffle() {
  local i j t
  perm=()
  for (( i=0; i<NODES; i++ )); do perm+=( "$i" ); done
  for (( i=NODES-1; i>0; i-- )); do
    j=$(( RANDOM % (i+1) )); t=${perm[i]}; perm[i]=${perm[j]}; perm[j]=$t
  done
}

# cut LO MID appends commands that block every link between
# perm[LO..MID) and perm[MID..NODES) to cmds.  Nodes before LO keep all
# their links.
cut() {
  local lo=$1 mid=$2 a b
  for (( a=lo; a<mid; a++ )); do
    for (( b=mid; b<NODES; b++ )); do
      cmds+=( "block ${perm[a]} ${perm[b]}" "block ${perm[b]} ${perm[a]}" )
    done
  done
}

# oneway_cut K appends commands that block every link from perm[0..K)
# to perm[K..NODES), and leaves the reverse direction open.
oneway_cut() {
  local a b
  for (( a=0; a<$1; a++ )); do
    for (( b=$1; b<NODES; b++ )); do cmds+=( "block ${perm[a]} ${perm[b]}" ); done
  done
}

# links leaves $1 random distinct-endpoint directed links in pairs.
links() {
  local i a b
  pairs=()
  for (( i=0; i<$1; i++ )); do
    a=$(( RANDOM % NODES )); b=$(( (a + 1 + RANDOM % (NODES-1)) % NODES ))
    pairs+=( "$a $b" )
  done
}

# fault ROLL appends the controller commands of the fault that ROLL
# picks to cmds, and its description to descs.
fault() {
  local roll=$1 k x p a b pct
  if   (( roll<first_roll[split] )); then
    shuffle; cut 0 1; descs+=( "isolate [${perm[0]}]" )
  elif (( roll<first_roll[halves] && NODES>=6 )); then
    shuffle; k=$(( 2 + RANDOM % (NODES/2 - 2) )); cut 0 "$k"; descs+=( "split [${perm[*]:0:k}]" )
  elif (( roll<first_roll[bridge] )); then
    shuffle; cut 0 $(( NODES/2 )); descs+=( "halves [${perm[*]:0:NODES/2}]" )
  elif (( roll<first_roll[oneway] && NODES>=3 )); then
    # perm[0] is the bridge Z, then X has x nodes and Y the rest.
    shuffle; x=$(( 1 + RANDOM % (NODES-2) )); cut 1 $(( 1+x ))
    descs+=( "bridge [${perm[0]}] between [${perm[*]:1:x}] and [${perm[*]:1+x}]" )
  elif (( roll<first_roll[loss] )); then
    # Reversing perm makes the group the receiving side instead.
    shuffle; k=$(( 1 + RANDOM % (NODES/2) ))
    if (( RANDOM % 2 )); then
      oneway_cut "$k"; descs+=( "oneway [${perm[*]:0:k}] cannot send" )
    else
      local group=( "${perm[@]:0:k}" ) rest=( "${perm[@]:k}" )
      perm=( "${rest[@]}" "${group[@]}" ); oneway_cut $(( NODES-k ))
      descs+=( "oneway [${group[*]}] cannot receive" )
    fi
  elif (( roll<first_roll[delay] )); then
    if (( RANDOM % 2 )); then
      pct=$(( 1 + RANDOM % LOSS_MAX_PCT ))
      for (( a=0; a<NODES; a++ )); do
        for (( b=0; b<NODES; b++ )); do (( a==b )) || cmds+=( "loss $a $b $pct" ); done
      done
      descs+=( "loss ${pct}% all links" )
    else
      x=$(( RANDOM % NODES )); pct=$(( 1 + RANDOM % (3*LOSS_MAX_PCT) ))
      for (( a=0; a<NODES; a++ )); do
        (( a==x )) || cmds+=( "loss $x $a $pct" "loss $a $x $pct" )
      done
      descs+=( "loss ${pct}% [$x]" )
    fi
  elif (( roll<first_roll[duplicate] )); then
    links $(( 1 + RANDOM % 3 )); for p in "${pairs[@]}"; do cmds+=( "delay $p $(( 10 + RANDOM % (DELAY_MAX_MS - 9) ))" ); done
    descs+=( "delay ${#pairs[@]} links" )
  elif (( roll<first_roll[heal] )); then
    links "$NODES"; for p in "${pairs[@]}"; do cmds+=( "duplicate $p 1" ); done
    descs+=( "duplicate ${#pairs[@]} links" )
  else
    descs+=( "heal" )
  fi
}

# is_delay ROLL is true when ROLL picks the delay fault.
is_delay() { (( $1>=first_roll[delay] && $1<first_roll[duplicate] )); }

echo "random faults: nodes=$NODES seed=$SEED hold=${HOLD_MIN_MS}..${HOLD_MAX_MS}ms gap=${GAP_MIN_MS}..${GAP_MAX_MS}ms burst=${BURST_MIN}..${BURST_MAX} quiet=${QUIET_MIN_MS}..${QUIET_MAX_MS}ms"
step=0
burst=$(( BURST_MIN + RANDOM % (BURST_MAX - BURST_MIN + 1) ))
while :; do
  if (( QUIET_MAX_MS && burst==0 )); then
    quiet=$(( QUIET_MIN_MS + RANDOM % (QUIET_MAX_MS - QUIET_MIN_MS + 1) ))
    ctl heal || exit 0
    echo "$(date +%T.%3N) QUIET healthy for ${quiet}ms"
    msleep "$quiet"
    burst=$(( BURST_MIN + RANDOM % (BURST_MAX - BURST_MIN + 1) ))
  fi
  burst=$(( burst-1 ))
  roll=$(( RANDOM % 100 ))
  [[ -z $ONLY ]] || roll=${first_roll[$ONLY]}
  hold=$(( HOLD_MIN_MS + RANDOM % (HOLD_MAX_MS - HOLD_MIN_MS + 1) ))
  gap=$(( GAP_MIN_MS + RANDOM % (GAP_MAX_MS - GAP_MIN_MS + 1) ))
  cmds=()
  descs=()
  fault "$roll"
  # Stack more faults onto any step but a heal.  A stacked roll that
  # picks a second delay adds nothing.
  if (( roll<first_roll[heal] )); then
    delayed=0; is_delay "$roll" && delayed=1
    stack=1
    while (( stack<STACK_MAX && RANDOM % 100 < STACK_PCT )); do
      stack=$(( stack+1 ))
      roll=$(( RANDOM % first_roll[heal] ))
      [[ -z $ONLY ]] || roll=${first_roll[$ONLY]}
      if is_delay "$roll"; then (( delayed )) && continue; delayed=1; fi
      fault "$roll"
    done
  fi
  # One apply swaps the previous faults for these, with no partial state.
  rules=
  for c in "${cmds[@]}"; do rules+="${rules:+, }$c"; done
  ctl "apply $rules" || exit 0
  step=$(( step+1 ))
  desc=${descs[0]}
  for (( i=1; i<${#descs[@]}; i++ )); do desc+=" + ${descs[i]}"; done
  echo "$(date +%T.%3N) FAULT applied: $desc hold=${hold}ms gap=${gap}ms step=$step"
  msleep "$hold"
  if (( gap )); then ctl heal || exit 0; msleep "$gap"; fi
done
