"""客户端配置保险箱（vault.py）的测试：存得进、取得出、坏数据不崩。"""
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

from wgmanager import secrets  # noqa: E402
from wgmanager.vault import Vault  # noqa: E402

SAMPLE = """[Interface]
PrivateKey = aBcD1234fakeKeyForTestingOnly=
Address = 10.8.0.5/32
DNS = 1.1.1.1

[Peer]
PublicKey = ServerPubKeyExample=
PresharedKey = PskExample1234=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 111.38.183.123:51820
"""

PUB_A = "ClientPubKeyAAaa="
PUB_B = "ClientPubKeyBBbb="


class VaultBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wgm-vault-")
        self.vault = Vault(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


@unittest.skipUnless(secrets.available(), "需要 Windows DPAPI")
class VaultRoundTrip(VaultBase):
    def test_put_then_get(self):
        self.assertTrue(self.vault.put(PUB_A, "张三-手机", SAMPLE, "张三-手机.conf"))
        entry = self.vault.get(PUB_A)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["conf"], SAMPLE)
        self.assertEqual(entry["name"], "张三-手机")
        self.assertEqual(entry["file"], "张三-手机.conf")

    def test_conf_is_not_stored_in_plaintext(self):
        self.vault.put(PUB_A, "n", SAMPLE, "")
        with open(os.path.join(self.dir, "clients.vault.json"), encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("PrivateKey", raw)
        self.assertNotIn("aBcD1234fakeKeyForTestingOnly", raw)
        self.assertIn("dpapi:", raw)

    def test_multiple_entries_are_independent(self):
        self.vault.put(PUB_A, "A", SAMPLE, "")
        self.vault.put(PUB_B, "B", SAMPLE.replace("10.8.0.5", "10.8.0.6"), "")
        self.assertEqual(self.vault.count(), 2)
        self.assertIn("10.8.0.6", self.vault.get(PUB_B)["conf"])
        self.assertIn("10.8.0.5", self.vault.get(PUB_A)["conf"])

    def test_overwrite_same_pubkey(self):
        self.vault.put(PUB_A, "旧名", SAMPLE, "")
        self.vault.put(PUB_A, "新名", SAMPLE + "\n# updated\n", "new.conf")
        self.assertEqual(self.vault.count(), 1)
        entry = self.vault.get(PUB_A)
        self.assertEqual(entry["name"], "新名")
        self.assertIn("# updated", entry["conf"])

    def test_rename_keeps_conf(self):
        self.vault.put(PUB_A, "旧名", SAMPLE, "")
        self.vault.rename(PUB_A, "新名", "新名.conf")
        entry = self.vault.get(PUB_A)
        self.assertEqual(entry["name"], "新名")
        self.assertEqual(entry["file"], "新名.conf")
        self.assertEqual(entry["conf"], SAMPLE)

    def test_drop_removes_entry(self):
        self.vault.put(PUB_A, "A", SAMPLE, "")
        self.vault.drop(PUB_A)
        self.assertFalse(self.vault.has(PUB_A))
        self.assertIsNone(self.vault.get(PUB_A))
        self.assertEqual(self.vault.count(), 0)

    def test_persists_across_instances(self):
        self.vault.put(PUB_A, "A", SAMPLE, "")
        other = Vault(self.dir)
        self.assertEqual(other.get(PUB_A)["conf"], SAMPLE)


class VaultEdgeCases(VaultBase):
    def test_get_unknown_pubkey(self):
        self.assertIsNone(self.vault.get("nope="))
        self.assertFalse(self.vault.has("nope="))

    def test_get_empty_pubkey(self):
        self.assertIsNone(self.vault.get(""))

    def test_put_without_conf(self):
        self.assertFalse(self.vault.put(PUB_A, "n", "", ""))

    def test_corrupt_file_is_tolerated(self):
        with open(os.path.join(self.dir, "clients.vault.json"), "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        fresh = Vault(self.dir)
        self.assertEqual(fresh.count(), 0)
        self.assertIsNone(fresh.get(PUB_A))

    def test_undecryptable_entry_returns_none(self):
        """换机器/换账号后密文解不开，要当成"没有"，而不是抛异常。"""
        import json

        path = os.path.join(self.dir, "clients.vault.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "entries": {
                PUB_A: {"name": "x", "file": "", "created": "",
                        "sealed": "dpapi:AAAAAAAAAAAAAAAAAAAA"}
            }}, fh)
        fresh = Vault(self.dir)
        self.assertIsNone(fresh.get(PUB_A))
        self.assertTrue(fresh.has(PUB_A))

    def test_plaintext_sealed_field_is_rejected(self):
        """老数据或人为写入的明文不该被当成密文解出来。"""
        import json

        path = os.path.join(self.dir, "clients.vault.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "entries": {
                PUB_A: {"name": "x", "sealed": "PrivateKey = plaintext"}
            }}, fh)
        self.assertIsNone(Vault(self.dir).get(PUB_A))


class VaultNoCrypto(unittest.TestCase):
    """DPAPI 不可用时必须拒绝保存，绝不退回明文。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wgm-vault-")
        self.vault = Vault(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_put_fails_when_encryption_unavailable(self):
        original = secrets.protect
        secrets.protect = lambda _t: ""
        try:
            self.assertFalse(self.vault.put(PUB_A, "n", SAMPLE, ""))
            self.assertFalse(os.path.isfile(os.path.join(self.dir, "clients.vault.json")))
        finally:
            secrets.protect = original


if __name__ == "__main__":
    unittest.main()
