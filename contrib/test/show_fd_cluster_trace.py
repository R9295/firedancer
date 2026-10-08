#!/usr/bin/env python3
"""Merge the consensus traces of a local test cluster into slot timelines.

Every validator logs "TRACE <tile> <event> key=value ..." lines at INFO
level, see src/disco/fd_trace.h.  The cluster test writes all nodes into
one log file and tags each line with fN, which is node N-1.

  show_fd_cluster_trace.py LOG... --slot 109       summary and timeline of slot 109
  show_fd_cluster_trace.py LOG... --slot 100-120   summary of each slot in the range
  show_fd_cluster_trace.py LOG... --counts         events per tile and node
  show_fd_cluster_trace.py LOG... --check          what to look at first in the run

In the output, nN is node N and a sender rank is shown as the node that
holds it.  The block ids of a slot are named a, b, c... in the order the
cluster first saw them, and 0 is the zero block id (a turbine version
before it completes).  When the leader equivocated, each FEC set root of
a version is marked A or B for the leader's two versions, and ? for
neither.
"""
import argparse
import collections
import re
import signal
import sys

LINE_RE = re.compile(r'^\w+\s+(\S+ \S+) GMT\S*\s+\S+\s+\S*?:f(\d+)\s.*?: TRACE (\w+) (\w+) ?(.*)$')
ZERO_ID = '1' * 32         # base58 of the zero block id
SLOTS_PER_WINDOW = 4       # AG_SLOTS_PER_WINDOW
FEC_SHRED_CNT = 32         # FD_FEC_SHRED_CNT: FEC set k starts at shred index 32*k

Event = collections.namedtuple('Event', 'ts node tile event kv')


def parse(paths):
    events = []
    for path in paths:
        with open(path, errors='replace') as f:
            for line in f:
                if ' TRACE ' not in line:
                    continue
                m = LINE_RE.match(line.rstrip('\n'))
                if not m:
                    continue
                ts, tag, tile, event, rest = m.groups()
                kv = dict(p.split('=', 1) for p in rest.split() if '=' in p)
                events.append(Event(ts, int(tag) - 1, tile, event, kv))
    events.sort(key=lambda e: e.ts)
    return events


def node_name(node):
    return f'n{node}' if node >= 0 else 'main'


def node_key(name):
    m = re.match(r'n(\d+)', name)
    return int(m.group(1)) if m else -1


def slot_of(e):
    s = e.kv.get('slot', '-')
    return int(s) if s.lstrip('-').isdigit() and s != '-' else None


class Names:
    """Names block ids per slot and sender ranks per epoch."""

    def __init__(self, events):
        self.blocks = collections.defaultdict(dict)  # slot -> {block id: letter}
        self.id_node = {}                             # identity -> node
        self.rank_id = {}                             # (epoch start, rank) -> identity
        self.starts = set()
        for e in events:
            if e.tile == 'votor' and e.event == 'epoch':
                self.id_node[e.kv['id']] = e.node
            elif e.tile == 'votor' and e.event == 'epoch_rank':
                start = int(e.kv['start'])
                self.rank_id[(start, int(e.kv['rank']))] = e.kv['id']
                self.starts.add(start)
            slot = slot_of(e)
            if slot is not None and 'block' in e.kv:
                self.block(slot, e.kv['block'])
            if e.kv.get('parent_slot', '-').isdigit() and 'parent' in e.kv:
                self.block(int(e.kv['parent_slot']), e.kv['parent'])

    def block(self, slot, block_id):
        if block_id in ('-', ZERO_ID):
            return '-' if block_id == '-' else '0'
        names = self.blocks[slot]
        if block_id not in names:
            i = len(names)
            names[block_id] = chr(ord('a') + i) if i < 26 else f'v{i}'
        return names[block_id]

    def rank(self, slot, rank):
        if rank in ('-', '-1'):
            return '-'
        start = max((s for s in self.starts if slot is None or s <= slot), default=None)
        node = self.id_node.get(self.rank_id.get((start, int(rank))))
        return node_name(node) if node is not None else f'r{rank}'


def show_event(names, e):
    slot = slot_of(e)
    parts = []
    for k, v in e.kv.items():
        if k == 'slot':
            continue
        if k == 'block' and slot is not None:
            v = names.block(slot, v)
        elif k == 'parent' and e.kv.get('parent_slot', '-').isdigit():
            v = names.block(int(e.kv['parent_slot']), v)
        elif k == 'from' and e.tile == 'votor':
            v = names.rank(slot, v)
        parts.append(f'{k}={v}')
    return f'{e.ts[11:26]} {node_name(e.node):>4} {e.tile:6} {e.event:15} {" ".join(parts)}'


def equivocation(events, slot):
    """Returns the leader's version A and B roots by FEC set index, and the
    nodes version B went to, if the leader equivocated in slot."""
    a, b, b_nodes = {}, {}, None
    for e in events:
        if slot_of(e) != slot or e.tile != 'shred':
            continue
        if e.event == 'eqvoc_slot':
            ports = e.kv.get('b_ports', '-')
            # Node N's shred port is 10003+100*N in a created test cluster.
            b_nodes = sorted((int(p) - 10003) // 100 for p in ports.split(',')) if ports != '-' else []
        elif e.event == 'leader_fec':
            version = {'A': a, 'B': b}.get(e.kv.get('version'))
            if version is not None:
                version[int(e.kv['fec'])] = e.kv['root']
    return a, b, b_nodes


def summary(events, names, slot, nodes):
    ev = [e for e in events if slot_of(e) == slot]
    if not ev:
        print(f'slot {slot}: no events')
        return
    leader = next((e for e in ev if e.tile == 'replay' and e.event == 'leader_start'), None)
    if leader:
        head = f'slot {slot}: leader {node_name(leader.node)}, parent {leader.kv["parent_slot"]}' \
               f' {names.block(int(leader.kv["parent_slot"]), leader.kv["parent"])}'
    else:
        window = next((e for e in events if e.tile == 'votor' and e.event == 'leader_window'
                       and 0 <= slot - int(e.kv['slot']) < SLOTS_PER_WINDOW), None)
        head = f'slot {slot}: leader {node_name(window.node) if window else "?"} (did not start)'
    a, b, b_nodes = equivocation(events, slot)
    if b_nodes is not None:
        head += f'; equivocated, version B to {",".join(node_name(n) for n in b_nodes) or "nobody"}'
    print(head)
    ids = names.blocks.get(slot, {})
    if ids:
        print('  ids: ' + ' '.join(f'{v}={k[:8]}' for k, v in ids.items()))
    chained = next((e for e in ev if e.tile == 'shred' and e.event == 'leader_slot' and 'chained_root' in e.kv), None)
    if chained:
        # The leader chains its first FEC set to the last FEC set root of the parent version it built on.
        parent_slot, root = int(chained.kv['parent_slot']), chained.kv['chained_root']
        on = sorted({names.block(parent_slot, e.kv['block']) for e in events
                     if e.tile == 'rotor' and e.event == 'block_complete' and slot_of(e) == parent_slot
                     and e.kv['roots'].split(',')[-1] == root})
        print(f'  leader chained to {parent_slot} root {root}' + (f' (block {",".join(on)})' if on else ''))

    # Versions: FEC roots and who completed, replayed, voted for and certified each one.
    roots = {}
    done = collections.defaultdict(set)
    replayed = collections.defaultdict(set)
    voted = collections.defaultdict(set)
    certs = collections.defaultdict(set)
    for e in ev:
        blk = names.block(slot, e.kv.get('block', '-'))
        if e.tile == 'rotor' and e.event == 'block_complete':
            roots[blk] = e.kv['roots'].split(',')
            flag = '' if e.kv['turbine'] == '1' else '(votor)'
            if e.kv['abandoned'] == '1':
                flag += '(abandoned)'
            done[blk].add(node_name(e.node) + flag)
        elif e.tile == 'replay' and e.event == 'block_done':
            replayed[blk].add(node_name(e.node))
        elif e.tile == 'votor' and e.event == 'vote_tx' and e.kv['kind'] in ('notar', 'notar_fallback'):
            voted[blk].add(node_name(e.node) + ('' if e.kv['kind'] == 'notar' else '(fallback)'))
        elif e.tile == 'votor' and e.event in ('cert_new', 'cert_rx', 'cert_footer') \
                and e.kv['result'] in ('created', 'accepted') and blk != '-':
            certs[blk].add(e.kv['kind'])
    for blk in sorted(set(roots) | set(replayed) | set(voted) | set(certs)):
        r = roots.get(blk, [])
        mix = ''
        if a and r:
            mix = ' ' + ''.join('A' if a.get(FEC_SHRED_CNT * i) == x else 'B' if b.get(FEC_SHRED_CNT * i) == x else '?'
                                for i, x in enumerate(r))
        print(f'  block {blk}: roots {",".join(r) or "?"}{mix}')
        for what, d in (('complete', done), ('replayed', replayed), ('notar vote', voted)):
            if d.get(blk):
                print(f'    {what:10} {" ".join(sorted(d[blk], key=node_key))}')
        if certs.get(blk):
            print(f'    certs      {" ".join(sorted(certs[blk]))}')

    # Each node's slot-wide votes, certs, finalization and anything unusual.
    print('  per node:')
    unusual = {('rotor', 'fec_reject'), ('rotor', 'abandon'), ('rotor', 'prune'), ('rotor', 'votor_block'),
               ('rotor', 'repair_parent'), ('rotor', 'repair_root'), ('rotor', 'redeliver_walk'),
               ('shred', 'eqvoc_rx'), ('votor', 'notar_pending'), ('votor', 'repair_req'),
               ('votor', 'safe_to_notar'), ('votor', 'safe_to_skip'), ('votor', 'standstill'),
               ('replay', 'fec_drop'), ('replay', 'block_dead'), ('replay', 'block_abandoned'), ('replay', 'evict'),
               ('replay', 'drain_enter'), ('replay', 'drain_exit'), ('replay', 'leader_drop'),
               ('replay', 'finalized_ahead'), ('votor', 'leader_missed')}
    by_node = collections.defaultdict(list)
    for e in ev:
        by_node[e.node].append(e)
    for node in sorted(by_node):
        if nodes and node not in nodes:
            continue
        ne = by_node[node]
        votes = [f'{x.kv["kind"]}' + (f' {names.block(slot, x.kv["block"])}' if x.kv['block'] != '-' else '')
                 for x in ne if x.tile == 'votor' and x.event == 'vote_tx']
        kinds = sorted({f'{x.kv["kind"]}' + (f' {names.block(slot, x.kv["block"])}' if x.kv['block'] != '-' else '')
                        for x in ne if x.tile == 'votor' and x.event in ('cert_new', 'cert_rx', 'cert_footer')
                        and x.kv['result'] in ('created', 'accepted')})
        fin = [names.block(slot, x.kv['block']) + (' (implicit)' if x.kv.get('implicit') == '1' else '')
               for x in ne if x.tile == 'votor' and x.event == 'finalized']
        skipped = any(x.tile == 'votor' and x.event == 'skipped' for x in ne)
        root = [names.block(slot, x.kv['block']) for x in ne if x.tile == 'replay' and x.event == 'root']
        line = f'    {node_name(node):>4}: votes [{", ".join(votes)}] certs [{", ".join(kinds)}]'
        if fin:
            line += f' finalized {fin[0]}'
        if skipped:
            line += ' skipped'
        if root:
            line += f' rooted {root[0]}'
        print(line)
        # Repeats of an event (votor asks again for a block on every vote for it) print once, with a count.
        seen = collections.OrderedDict()
        for x in ne:
            if (x.tile, x.event) in unusual:
                key = show_event(names, x)[16:]
                if key in seen:
                    seen[key][1] += 1
                else:
                    seen[key] = [x.ts[11:26], 1]
        for key, (ts, n) in seen.items():
            print(f'          {ts} {key}' + (f'  (x{n})' if n > 1 else ''))


def secs(ts):
    h, m, s = ts[11:].split(':')
    return int(h) * 3600 + int(m) * 60 + float(s)


WARN_RE = re.compile(r'^(WARNING|ERR|CRIT|ALERT|EMERG)\s+(\S+ \S+) GMT\S*\s+\S+\s+\S*?:f(\d+)\s.*?(\S+\(\d+\))\[[^\]]*\]: (.*)$')


def warnings(paths):
    """Groups the WARNING and worse lines of the logs by source line."""
    groups = {}
    for path in paths:
        with open(path, errors='replace') as f:
            for line in f:
                if not line.startswith(('WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG')):
                    continue
                m = WARN_RE.match(line.rstrip('\n'))
                if not m:
                    continue
                level, ts, tag, where, msg = m.groups()
                g = groups.setdefault((level, where), {'n': 0, 'nodes': set(), 'first': ts, 'msg': msg})
                g['n'] += 1
                g['nodes'].add(int(tag) - 1)
    return groups


def nodes_str(nodes):
    return ','.join(node_name(n) for n in sorted(nodes))


def slots_str(slots, cap=12):
    slots = sorted(slots)
    return ','.join(map(str, slots[:cap])) + (f',... ({len(slots)})' if len(slots) > cap else '')


def check(paths, events, names):
    """Prints what to look at first in a run: lines starting with ! break
    a protocol rule, the rest are liveness, equivocation, unusual events
    and warnings to explain."""
    problems = []
    end = secs(events[-1].ts) if events else 0.0
    nodes = sorted({e.node for e in events if e.node >= 0})
    print(f'run: {len(events)} trace lines, nodes {nodes_str(nodes)}'
          + (f', {events[0].ts[11:19]} to {events[-1].ts[11:19]}' if events else ''))

    # Outcomes of each slot at each node.
    fin = collections.defaultdict(lambda: collections.defaultdict(set))   # slot -> block -> nodes
    skipped = collections.defaultdict(set)                                # slot -> nodes
    rooted = collections.defaultdict(lambda: collections.defaultdict(set))
    roots = collections.defaultdict(list)                                 # node -> [(time, slot)]
    votes = collections.defaultdict(set)                                  # (node, slot) -> {(kind, block)}
    for e in events:
        slot = slot_of(e)
        if e.tile == 'votor' and e.event == 'finalized':
            fin[slot][names.block(slot, e.kv['block'])].add(e.node)
        elif e.tile == 'votor' and e.event == 'skipped':
            skipped[slot].add(e.node)
        elif e.tile == 'replay' and e.event == 'root':
            rooted[slot][names.block(slot, e.kv['block'])].add(e.node)
            roots[e.node].append((secs(e.ts), slot))
        elif e.tile == 'votor' and e.event == 'vote_tx':
            votes[(e.node, slot)].add((e.kv['kind'], names.block(slot, e.kv['block'])))
            if e.kv['result'] not in ('accepted', 'duplicate'):
                problems.append(f'! {node_name(e.node)} own {e.kv["kind"]} vote in slot {slot} added as {e.kv["result"]}')
        elif e.tile == 'votor' and e.event == 'vote_rx' and e.kv['result'] in ('slashable', 'bad_sig'):
            problems.append(f'! {node_name(e.node)} got a {e.kv["result"]} {e.kv["kind"]} vote in slot {slot} from {names.rank(slot, e.kv["from"])}')
        elif e.tile == 'votor' and e.event == 'cert_rx' and e.kv['result'] == 'failed_verify':
            problems.append(f'! {node_name(e.node)} got a {e.kv["kind"]} cert for slot {slot} that failed verification')

    # Safety: one outcome per slot across the cluster.
    for slot in sorted(set(fin) | set(skipped) | set(rooted)):
        f = fin.get(slot, {})
        if len(f) > 1:
            problems.append(f'! slot {slot} finalized as ' + ' and '.join(f'{b} by {nodes_str(n)}' for b, n in f.items()))
        if f and skipped.get(slot):
            problems.append(f'! slot {slot} finalized by {nodes_str(set().union(*f.values()))} but skipped by {nodes_str(skipped[slot])}')
        r = rooted.get(slot, {})
        if len(r) > 1:
            problems.append(f'! slot {slot} rooted as ' + ' and '.join(f'{b} by {nodes_str(n)}' for b, n in r.items()))
        for b, n in r.items():
            if f and b not in f:
                problems.append(f'! slot {slot} rooted as {b} by {nodes_str(n)} but finalized as {",".join(f)}')
        if slot in skipped and r:
            problems.append(f'! slot {slot} rooted by {nodes_str(set().union(*r.values()))} but skipped by {nodes_str(skipped[slot])}')

    # A node votes notar for at most one block, never both notar and skip,
    # and casts no final vote together with a skip or fallback vote.
    for (node, slot), vs in sorted(votes.items()):
        kinds = {k for k, _ in vs}
        notar = {b for k, b in vs if k == 'notar'}
        if len(notar) > 1:
            problems.append(f'! {node_name(node)} voted notar for blocks {",".join(sorted(notar))} in slot {slot}')
        if 'notar' in kinds and 'skip' in kinds:
            problems.append(f'! {node_name(node)} voted both notar and skip in slot {slot}')
        if 'final' in kinds and kinds & {'skip', 'skip_fallback', 'notar_fallback'}:
            problems.append(f'! {node_name(node)} voted final and {",".join(sorted(kinds & {"skip", "skip_fallback", "notar_fallback"}))} in slot {slot}')

    print('protocol violations:' if problems else 'protocol violations: none found')
    for p in problems[:40]:
        print(f'  {p}')
    if len(problems) > 40:
        print(f'  ... {len(problems) - 40} more')

    # Liveness: where each node's root ended, and its longest wait for the next root.
    finalized = {node: {s for s, f in fin.items() if any(node in n for n in f.values())} for node in nodes}
    print('roots (last root, highest finalized, longest wait for a root and the root it waited after):')
    top = max((r[-1][1] for r in roots.values()), default=0)
    for node in nodes:
        r = roots.get(node, [])
        hi = max(finalized[node], default=None)
        if not r:
            print(f'  {node_name(node):>4}: never rooted, highest finalized {hi}')
            continue
        waits = [(b[0] - a[0], a[1]) for a, b in zip(r, r[1:])] + [(end - r[-1][0], r[-1][1])]
        wait, after = max(waits)
        lag = f'  LAGS {top - r[-1][1]} slots' if top - r[-1][1] > 8 else ''
        print(f'  {node_name(node):>4}: root {r[-1][1]}, finalized {hi}, longest wait {wait:.1f}s after root {after}{lag}')

    # Slots a node never finalized or skipped although it finalized later ones.
    gaps = {}
    for node in nodes:
        done = finalized[node] | {s for s, n in skipped.items() if node in n}
        if finalized[node]:
            gaps[node] = [s for s in range(min(done), max(finalized[node]) + 1) if s not in done]
    if any(gaps.values()):
        print('slots without an outcome at a node (neither finalized nor skipped, below its highest finalized slot):')
        for node, g in sorted(gaps.items()):
            if g:
                print(f'  {node_name(node):>4}: {slots_str(g)}')

    # Equivocated slots: the leader's two versions, every version nodes built, and the outcome.
    eq_slots = sorted({slot_of(e) for e in events if e.tile == 'shred' and e.event == 'eqvoc_slot'})
    if eq_slots:
        print('equivocated slots (version roots marked A, B or ? for neither):')
    for slot in eq_slots:
        a, b, b_nodes = equivocation(events, slot)
        built = collections.defaultdict(set)
        replayed = collections.defaultdict(set)
        voted = collections.defaultdict(set)
        marks = {}
        for e in events:
            if slot_of(e) != slot:
                continue
            blk = names.block(slot, e.kv.get('block', '-'))
            if e.tile == 'rotor' and e.event == 'block_complete':
                r = e.kv['roots'].split(',')
                marks[blk] = ''.join('A' if a.get(FEC_SHRED_CNT * i) == x else 'B' if b.get(FEC_SHRED_CNT * i) == x else '?'
                                     for i, x in enumerate(r))
                built[blk].add(e.node)
            elif e.tile == 'replay' and e.event == 'block_done':
                replayed[blk].add(e.node)
            elif e.tile == 'votor' and e.event == 'vote_tx' and e.kv['kind'] in ('notar', 'notar_fallback'):
                voted[blk].add(e.node)
        outcome = ('finalized ' + ','.join(fin[slot])) if fin.get(slot) else 'skipped' if skipped.get(slot) else 'no outcome'
        print(f'  slot {slot}: B to {nodes_str(b_nodes or [])}; {outcome}')
        for blk in sorted(set(marks) | set(replayed) | set(voted)):
            m = marks.get(blk, '?')
            mixed = ' MIXED' if len(set(m)) > 1 or '?' in m else ''
            print(f'    {blk} {m}{mixed}: built {nodes_str(built[blk]) or "-"}; replayed {nodes_str(replayed[blk]) or "-"}; notar votes {nodes_str(voted[blk]) or "-"}')
            if mixed and blk in fin.get(slot, {}):
                print(f'    ! a mixed version of slot {slot} was finalized')

    # Unusual events, by kind and reason.
    keyed = {('rotor', 'fec_reject'): None, ('rotor', 'abandon'): 'why', ('rotor', 'redeliver_stop'): 'parent_found',
             ('rotor', 'missing_fec'): None, ('rotor', 'root_held'): None, ('shred', 'eqvoc_rx'): 'src',
             ('votor', 'notar_pending'): 'why', ('votor', 'standstill'): None, ('votor', 'leader_missed'): None,
             ('votor', 'safe_to_notar'): None, ('votor', 'safe_to_skip'): None,
             ('replay', 'fec_drop'): 'why', ('replay', 'fec_skip'): 'why', ('replay', 'block_dead'): 'dead_reason',
             ('replay', 'block_abandoned'): 'abandoned_reason', ('replay', 'evict'): None, ('replay', 'drain_enter'): None,
             ('replay', 'leader_drop'): None, ('replay', 'finalized_ahead'): None, ('replay', 'leader_grant'): 'now'}
    tally = collections.defaultdict(lambda: [0, set(), set()])
    for e in events:
        if (e.tile, e.event) not in keyed:
            continue
        if e.tile == 'replay' and e.event == 'leader_grant' and e.kv.get('now') == 'started':
            continue
        k = keyed[(e.tile, e.event)]
        t = tally[(e.tile, e.event, f'{k}={e.kv.get(k)}' if k else '')]
        t[0] += 1
        t[1].add(e.node)
        if slot_of(e) is not None:
            t[2].add(slot_of(e))
    for e in events:  # a version that was built for repair but never completed before it was pruned
        if e.tile == 'rotor' and e.event == 'prune' and e.kv['turbine'] == '0' and e.kv['complete'] == '0':
            slot = slot_of(e)
            if names.block(slot, e.kv['block']) in fin.get(slot, {}):
                t = tally[('rotor', 'prune', 'finalized version never completed')]
                t[0] += 1
                t[1].add(e.node)
                t[2].add(slot)
    if tally:
        print('unusual events (count, kind, nodes, slots):')
        for (tile, event, k), (n, ns, ss) in sorted(tally.items(), key=lambda x: -x[1][0]):
            print(f'  {n:6} {tile} {event} {k}  nodes {nodes_str(ns)}  slots {slots_str(ss)}')

    groups = warnings(paths)
    if groups:
        order = {'EMERG': 0, 'ALERT': 1, 'CRIT': 2, 'ERR': 3, 'WARNING': 4}
        print('warnings and errors by source line:')
        for (level, where), g in sorted(groups.items(), key=lambda x: (order[x[0][0]], -x[1]['n']))[:30]:
            print(f'  {level:7} {g["n"]:6} {where} nodes {nodes_str(g["nodes"])} first {g["first"][11:19]}: {g["msg"][:150]}')


def counts(events):
    by_event = collections.Counter((e.tile, e.event) for e in events)
    by_node = collections.Counter(e.node for e in events)
    span = 0.0
    if events:
        span = max(secs(events[-1].ts) - secs(events[0].ts), 1e-9)
    print(f'{len(events)} trace lines over {span:.1f} s')
    for (tile, event), n in by_event.most_common():
        print(f'  {n:8} {n / span:9.1f}/s  {tile} {event}')
    print('per node:')
    for node, n in sorted(by_node.items()):
        print(f'  {node_name(node):>4} {n:8} {n / span:9.1f}/s')


def main():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped into head
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('logs', nargs='+', help='log files with TRACE lines')
    ap.add_argument('--slot', help='a slot, or FIRST-LAST')
    ap.add_argument('--node', type=int, action='append', default=[], help='only this node in per-node lines and the timeline (repeatable)')
    ap.add_argument('--timeline', action='store_true', help='also print the timeline of each slot (default for one slot)')
    ap.add_argument('--counts', action='store_true', help='print event counts per tile and node')
    ap.add_argument('--check', action='store_true', help='print protocol violations, liveness, equivocation, unusual events and warnings of the run')
    args = ap.parse_args()

    events = parse(args.logs)
    names = Names(events)
    if args.check:
        check(args.logs, events, names)
        return
    if not events:
        sys.exit('no TRACE lines found')
    if args.counts or not args.slot:
        counts(events)
    if not args.slot:
        return
    first, _, last = args.slot.partition('-')
    first = int(first)
    last = int(last) if last else first
    for slot in range(first, last + 1):
        summary(events, names, slot, set(args.node))
        if args.timeline or first == last:
            print('  timeline:')
            for e in events:
                if slot_of(e) == slot and (not args.node or e.node in args.node):
                    print(f'    {show_event(names, e)}')
        print()


if __name__ == '__main__':
    main()
