#!/usr/bin/env python3
"""Provision the combined NUMA-local huge-page demand of a test cluster."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

# The same recovery the hugetlbfs configure stage runs on ENOMEM: free
# memory is often too fragmented to form huge pages until the page
# cache is dropped and memory is compacted.
COMPACT_STEPS = (("/proc/sys/vm/compact_memory", 1),
                 ("/proc/sys/vm/drop_caches", 3),
                 ("/proc/sys/vm/compact_memory", 1))


def compact():
    for path, value in COMPACT_STEPS:
        Path(path).write_text(f"{value}\n")
        time.sleep(0.5)


def requirements(summaries):
    pages = {}
    for summary in summaries:
        for node in summary["numa_nodes"]:
            for size, field in ((2048, "huge_pages"), (1048576, "gigantic_pages")):
                count = node[field]
                if not isinstance(node["node"], int) or node["node"] < 0:
                    raise ValueError("Invalid NUMA node in memory report")
                if not isinstance(count, int) or count < 0:
                    raise ValueError("Invalid page count in memory report")
                if count:
                    key = (node["node"], size)
                    pages[key] = pages.get(key, 0) + count
    return pages


def pool_target(total, free, required):
    if min(total, free, required) < 0 or free > total:
        raise ValueError("Invalid huge-page pool counters")
    # Keep pages already allocated to files/users and add only the gap.
    # A fully configured cluster skips this preflight, so its existing
    # workspace files do not cause another allocation on each test run.
    target = total + max(0, required - free)
    if target > 0xFFFFFFFF:
        raise ValueError("Huge-page pool would exceed UINT_MAX pages")
    return target


def prepare(dev, configs):
    def command(config, *args):
        return [dev, "--config", config, "--alpenglow", *args]

    if all(subprocess.run(command(config, "configure", "check", "hugetlbfs"),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
           for config in configs):
        print("Cluster huge-page mounts are already configured.", flush=True)
        return

    summaries = []
    for config in configs:
        report = subprocess.check_output(command(config, "mem", "--json"), text=True)
        summaries.append(json.loads(report)["summary"])
    pages = requirements(summaries)
    mib = sum(size * count for (_, size), count in pages.items()) / 1024
    print(f"Combined cluster requirement: {mib / 1024:.2f} GiB of huge pages.", flush=True)

    for (node, size), count in sorted(pages.items()):
        pool = Path(f"/sys/devices/system/node/node{node}/hugepages/hugepages-{size}kB")
        total = int((pool / "nr_hugepages").read_text())
        free = int((pool / "free_hugepages").read_text())
        target = pool_target(total, free, count)
        if target == total:
            continue
        print(f"NUMA {node}: increasing {size} KiB page pool from {total} to {target}", flush=True)
        for attempt in range(2):
            (pool / "nr_hugepages").write_text(f"{target}\n")
            free = int((pool / "free_hugepages").read_text())
            if free >= count:
                break
            if attempt:
                raise RuntimeError(
                    f"NUMA {node}: need {count} free {size} KiB pages, got {free}. "
                    "Insufficient contiguous memory; reserve huge pages at boot or retry after reboot."
                )
            print(f"NUMA {node}: only {free} free {size} KiB pages; compacting memory before trying again.", flush=True)
            compact()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev", required=True, help="Path to firedancer-dev")
    parser.add_argument("configs", nargs="+", help="Node TOML configurations")
    args = parser.parse_args()
    try:
        prepare(args.dev, args.configs)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Huge-page preparation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
