"""操作审计日志的单元测试。"""
import json
import os
import tempfile
import unittest

from wgmanager.audit import ACTION_LABELS, AuditLog, export_csv


class AuditTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _log(self, **kw):
        return AuditLog(self.dir, **kw)


class TestRecord(AuditTestCase):
    def test_record_then_read(self):
        a = self._log()
        self.assertTrue(a.record("add", host="1.2.3.4:22/root", name="张三",
                                 pubkey="PUBKEY1", detail="地址 10.8.0.5"))
        rows = a.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "add")
        self.assertEqual(rows[0]["name"], "张三")
        self.assertEqual(rows[0]["host"], "1.2.3.4:22/root")
        self.assertEqual(rows[0]["result"], "ok")
        self.assertIn("ts", rows[0])
        self.assertIn("user", rows[0])

    def test_newest_first(self):
        a = self._log()
        for i in range(5):
            a.record("add", name=f"k{i}")
        names = [r["name"] for r in a.rows()]
        self.assertEqual(names, ["k4", "k3", "k2", "k1", "k0"])

    def test_limit(self):
        a = self._log()
        for i in range(10):
            a.record("add", name=f"k{i}")
        self.assertEqual(len(a.rows(limit=3)), 3)

    def test_backup_stored_as_basename(self):
        a = self._log()
        a.record("edit", backup="/etc/wireguard/wg0.conf.wgmgr.bak.20261105-101500")
        self.assertEqual(a.rows()[0]["backup"], "wg0.conf.wgmgr.bak.20261105-101500")


class TestScrub(AuditTestCase):
    def test_private_key_never_written(self):
        a = self._log()
        a.record("edit", name="x", detail="PrivateKey = aBcD1234secretmaterial=")
        row = a.rows()[0]
        self.assertNotIn("aBcD1234", row["detail"])
        self.assertIn("已隐去", row["detail"])

    def test_preshared_key_never_written(self):
        a = self._log()
        a.record("edit", detail="presharedkey 是 XyZ9876")
        self.assertNotIn("XyZ9876", a.rows()[0]["detail"])

    def test_normal_detail_untouched(self):
        a = self._log()
        a.record("add", detail="分配地址 10.8.0.5, fd08::5")
        self.assertEqual(a.rows()[0]["detail"], "分配地址 10.8.0.5, fd08::5")

    def test_detail_truncated(self):
        a = self._log()
        a.record("edit", detail="长" * 1000)
        self.assertLessEqual(len(a.rows()[0]["detail"]), 300)

    def test_whole_file_has_no_key_material(self):
        a = self._log()
        a.record("edit", detail="PrivateKey = SECRETSECRET")
        with open(a.path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("SECRETSECRET", raw)


class TestFilter(AuditTestCase):
    def setUp(self):
        super().setUp()
        self.a = self._log()
        self.a.record("add", host="A:22/root", name="张三", pubkey="PK1")
        self.a.record("delete", host="B:10022/jsd", name="李四", pubkey="PK2")
        self.a.record("edit", host="A:22/root", name="张三", pubkey="PK1",
                      detail="改名")

    def test_filter_by_host(self):
        rows = self.a.rows(host="A:22/root")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["host"] == "A:22/root" for r in rows))

    def test_filter_by_action(self):
        rows = self.a.rows(action="delete")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "李四")

    def test_search_keyword_matches_pubkey(self):
        rows = self.a.rows(keyword="PK2")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "李四")

    def test_search_is_case_insensitive(self):
        self.assertEqual(len(self.a.rows(keyword="pk1")), 2)

    def test_search_matches_detail(self):
        rows = self.a.rows(keyword="改名")
        self.assertEqual(len(rows), 1)

    def test_hosts_sorted_unique(self):
        self.assertEqual(self.a.hosts(), ["A:22/root", "B:10022/jsd"])

    def test_combined_filters(self):
        rows = self.a.rows(host="A:22/root", action="add")
        self.assertEqual(len(rows), 1)


class TestRotate(AuditTestCase):
    def test_rotation_keeps_old_records(self):
        # 每条记录约 190 字节，2000 字节切一份、留 5 份，30 条能全放下
        a = AuditLog(self.dir, max_bytes=2000, keep=5)
        for i in range(30):
            a.record("add", name=f"k{i:02d}", detail="x" * 40)
        names = {r["name"] for r in a.rows(limit=1000)}
        self.assertIn("k00", names)
        self.assertIn("k29", names)
        self.assertEqual(len(names), 30)

    def test_rotation_caps_file_count(self):
        a = AuditLog(self.dir, max_bytes=300, keep=3)
        for i in range(60):
            a.record("add", name=f"k{i}", detail="y" * 40)
        files = [f for f in os.listdir(self.dir) if f.startswith("audit.jsonl")]
        self.assertLessEqual(len(files), 3)


class TestRobustness(AuditTestCase):
    def test_broken_line_is_skipped(self):
        a = self._log()
        a.record("add", name="好记录")
        with open(a.path, "a", encoding="utf-8") as f:
            f.write("{这不是合法 JSON\n")
        a.record("add", name="又一条")
        names = [r["name"] for r in a.rows()]
        self.assertEqual(names, ["又一条", "好记录"])

    def test_empty_returns_empty(self):
        self.assertEqual(self._log().rows(), [])

    def test_count(self):
        a = self._log()
        for _ in range(4):
            a.record("add")
        self.assertEqual(a.count(), 4)

    def test_bad_directory_does_not_raise(self):
        a = AuditLog(os.path.join(self.dir, "不存在的子目录"))
        self.assertFalse(a.record("add", name="x"))


class TestExport(AuditTestCase):
    def test_export_csv(self):
        a = self._log()
        a.record("add", host="H:22/root", name="张三", pubkey="PK1",
                 detail="地址 10.8.0.5")
        a.record("delete", host="H:22/root", name="李四", pubkey="PK2")
        path = os.path.join(self.dir, "out.csv")
        n = export_csv(a.rows(), path)
        self.assertEqual(n, 2)
        with open(path, encoding="utf-8-sig") as f:
            raw = f.read()
        self.assertIn("时间,操作,服务器,密钥名,公钥,详情,结果,操作者", raw)
        self.assertIn("新增密钥", raw)
        self.assertIn("删除密钥", raw)

    def test_export_empty(self):
        path = os.path.join(self.dir, "empty.csv")
        self.assertEqual(export_csv([], path), 0)
        self.assertTrue(os.path.exists(path))

    def test_csv_has_bom_for_excel(self):
        a = self._log()
        a.record("add", name="中文名")
        path = os.path.join(self.dir, "bom.csv")
        export_csv(a.rows(), path)
        with open(path, "rb") as f:
            self.assertEqual(f.read(3), b"\xef\xbb\xbf")


class TestLabels(unittest.TestCase):
    def test_all_actions_have_labels(self):
        for act in ("add", "edit", "delete", "restore", "install", "expire"):
            self.assertIn(act, ACTION_LABELS)

    def test_labels_unique(self):
        values = list(ACTION_LABELS.values())
        self.assertEqual(len(values), len(set(values)))


if __name__ == "__main__":
    unittest.main()
