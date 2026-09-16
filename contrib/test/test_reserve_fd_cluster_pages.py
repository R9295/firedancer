import json
import subprocess
import unittest
from unittest.mock import patch

import reserve_fd_cluster_pages as reserve


class ReservationTest(unittest.TestCase):
    def setUp(self):
        self.configs = ["node-0.toml", "node-1.toml", "node-2.toml"]
        self.reports = [
            {"summary": {"numa_nodes": [
                {"node": n, "huge_pages": 98 if n == 0 else 5655 if n == i + 1 else 0,
                 "gigantic_pages": 0}
                for n in range(4)
            ]}}
            for i in range(3)
        ]
        self.files = {}
        for node, count in enumerate((242, 5667, 5667, 156)):
            base = f"/sys/devices/system/node/node{node}/hugepages/hugepages-2048kB"
            self.files[f"{base}/nr_hugepages"] = count
            self.files[f"{base}/free_hugepages"] = count
        self.writes = []

    def read(self, path):
        return str(self.files[str(path)])

    def write(self, path, value):
        path = str(path)
        value = int(value)
        free_path = path.replace("nr_hugepages", "free_hugepages")
        self.files[free_path] += value - self.files[path]
        self.files[path] = value
        self.writes.append((path, value))

    def test_shared_numa_node_is_summed_before_mounting(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
             patch.object(subprocess, "check_output", side_effect=map(json.dumps, self.reports)), \
             patch.object(reserve.Path, "read_text", autospec=True, side_effect=self.read), \
             patch.object(reserve.Path, "write_text", autospec=True, side_effect=self.write):
            reserve.prepare("/build/firedancer-dev", self.configs)
        self.assertEqual(self.writes, [
            ("/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages", 294),
            ("/sys/devices/system/node/node3/hugepages/hugepages-2048kB/nr_hugepages", 5655),
        ])

    def test_configured_cluster_does_not_allocate_again(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(subprocess, "check_output") as report, \
             patch.object(reserve.Path, "write_text") as write:
            reserve.prepare("/build/firedancer-dev", self.configs)
        report.assert_not_called()
        write.assert_not_called()

    def test_cannot_satisfy_pool(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
             patch.object(subprocess, "check_output", side_effect=map(json.dumps, self.reports)), \
             patch.object(reserve.Path, "read_text", autospec=True, side_effect=self.read), \
             patch.object(reserve.Path, "write_text"):
            with self.assertRaisesRegex(RuntimeError, "NUMA 0: need 294"):
                reserve.prepare("/build/firedancer-dev", self.configs)

    def test_allocated_pages_are_preserved(self):
        self.assertEqual(reserve.pool_target(200, 20, 100), 280)
        self.assertEqual(reserve.pool_target(200, 150, 100), 200)
        self.assertEqual(reserve.pool_target(0, 0, 100), 100)
        with self.assertRaises(ValueError):
            reserve.pool_target(0xFFFFFFFF, 0, 1)

    def test_page_sizes_remain_separate(self):
        summary = {"numa_nodes": [{"node": 1, "huge_pages": 10, "gigantic_pages": 3}]}
        self.assertEqual(reserve.requirements([summary, summary]), {(1, 2048): 20, (1, 1048576): 6})

    def test_failed_report_does_not_allocate(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
             patch.object(subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "mem")), \
             patch.object(reserve.Path, "write_text") as write:
            with self.assertRaises(subprocess.CalledProcessError):
                reserve.prepare("/build/firedancer-dev", self.configs)
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
