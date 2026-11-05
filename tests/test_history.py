"""本地配置历史（history.py）的测试：存得快照、按时间倒序、能裁剪、坏数据不崩。"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "vendor")):
    if path not in sys.path:
        sys.path.insert(0, path)

from wgmanager.history import History  # noqa: E402

CONF = """[Interface]
PrivateKey = serverPrivateKeyFake=
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
PublicKey = peerOne=
AllowedIPs = 10.8.0.2/32
"""

HOST_A = "111.38.183.123"
HOST_B = "10.0.0.9"


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wgm-hist-")
        self.h = History(self.dir, keep=5)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_record_and_read(self):
        entry = self.h.record(HOST_A, CONF, "新增密钥", "张三 / 10.8.0.2", peers=1)
        self.assertIsNotNone(entry)
        self.assertEqual(self.h.count(), 1)
        self.assertEqual(self.h.read(entry["id"]), CONF)

    def test_entries_newest_first(self):
        first = self.h.record(HOST_A, CONF, "新增密钥", "a", peers=1)
        second = self.h.record(HOST_A, CONF, "删除密钥", "b", peers=1)
        items = self.h.entries(HOST_A)
        self.assertEqual([e["id"] for e in items], [second["id"], first["id"]])

    def test_filter_by_host(self):
        self.h.record(HOST_A, CONF, "新增密钥", "a")
        self.h.record(HOST_B, CONF, "删除密钥", "b")
        self.assertEqual(len(self.h.entries(HOST_A)), 1)
        self.assertEqual(len(self.h.entries(HOST_B)), 1)
        self.assertEqual(len(self.h.entries()), 2)
        self.assertEqual(self.h.entries(HOST_A)[0]["action"], "新增密钥")

    def test_empty_text_is_not_recorded(self):
        self.assertIsNone(self.h.record(HOST_A, "", "新增密钥", "x"))
        self.assertEqual(self.h.count(), 0)

    def test_missing_snapshot_file_returns_empty(self):
        entry = self.h.record(HOST_A, CONF, "新增密钥", "a")
        os.remove(os.path.join(self.h.root, entry["file"]))
        self.assertEqual(self.h.read(entry["id"]), "")

    def test_unknown_id(self):
        self.assertEqual(self.h.read("no-such-id"), "")
        self.assertIsNone(self.h.find("no-such-id"))

    def test_prune_keeps_only_recent(self):
        ids = []
        for i in range(8):
            e = self.h.record(HOST_A, CONF + f"# v{i}\n", "新增密钥", str(i))
            ids.append(e["id"])
        self.assertEqual(self.h.count(), 5)
        kept = [e["id"] for e in self.h.entries(HOST_A)]
        self.assertEqual(kept, list(reversed(ids[-5:])))
        # 被裁掉的文件也要真的删掉，不能只从索引里摘掉
        files = [f for f in os.listdir(self.h.root) if f.endswith(".conf")]
        self.assertEqual(len(files), 5)

    def test_persists_across_instances(self):
        entry = self.h.record(HOST_A, CONF, "新增密钥", "a")
        fresh = History(self.dir)
        self.assertEqual(fresh.read(entry["id"]), CONF)

    def test_corrupt_index_is_tolerated(self):
        os.makedirs(self.h.root, exist_ok=True)
        with open(os.path.join(self.h.root, "index.json"), "w", encoding="utf-8") as fh:
            fh.write("not json at all")
        fresh = History(self.dir)
        self.assertEqual(fresh.count(), 0)
        # 还能继续往里写
        self.assertIsNotNone(fresh.record(HOST_A, CONF, "新增密钥", "a"))

    def test_size_recorded(self):
        entry = self.h.record(HOST_A, CONF, "新增密钥", "a")
        self.assertEqual(entry["size"], len(CONF.encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
