"""口令加密（DPAPI）与连接配置档去重规则的测试。

这里只测纯逻辑，不开窗口：加密能不能往返、坏数据会不会崩、
同一个 IP 不同端口会不会被误当成同一条配置。
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "vendor")):
    if path not in sys.path:
        sys.path.insert(0, path)

from wgmanager import secrets  # noqa: E402


class SecretsRoundTrip(unittest.TestCase):
    """加解密往返。只在 DPAPI 可用的机器上跑（也就是 Windows）。"""

    @unittest.skipUnless(secrets.available(), "需要 Windows DPAPI")
    def test_roundtrip_common_inputs(self):
        for text in ("abc123", "P@ssw0rd!", "中文口令测试", "a" * 500, "  两头有空格  "):
            sealed = secrets.protect(text)
            self.assertTrue(sealed.startswith(secrets.PREFIX), f"没有加密前缀：{text!r}")
            self.assertEqual(secrets.unprotect(sealed), text)

    @unittest.skipUnless(secrets.available(), "需要 Windows DPAPI")
    def test_ciphertext_does_not_contain_plaintext(self):
        sealed = secrets.protect("hunter2")
        self.assertNotIn("hunter2", sealed)

    @unittest.skipUnless(secrets.available(), "需要 Windows DPAPI")
    def test_same_input_gives_different_ciphertext(self):
        """DPAPI 每次加密都掺随机盐，两次结果必然不同，但都能解回原文。"""
        first = secrets.protect("same-password")
        second = secrets.protect("same-password")
        self.assertNotEqual(first, second)
        self.assertEqual(secrets.unprotect(first), "same-password")
        self.assertEqual(secrets.unprotect(second), "same-password")


class SecretsEdgeCases(unittest.TestCase):
    """坏数据和边界值：一律安静地当成"没存过"，绝不抛异常打断连接流程。"""

    def test_empty_string(self):
        self.assertEqual(secrets.protect(""), "")
        self.assertEqual(secrets.unprotect(""), "")

    def test_plaintext_is_not_treated_as_ciphertext(self):
        # 老版本写进去的明文（如果存在）不能被当成密文解出乱码
        self.assertEqual(secrets.unprotect("hunter2"), "")

    def test_tampered_or_garbage_input(self):
        self.assertEqual(secrets.unprotect("dpapi:" + "A" * 40), "")
        self.assertEqual(secrets.unprotect("dpapi:!!!not-base64!!!"), "")

    def test_none_input(self):
        self.assertEqual(secrets.protect(None), "")
        self.assertEqual(secrets.unprotect(None), "")

    def test_is_sealed(self):
        self.assertFalse(secrets.is_sealed(""))
        self.assertFalse(secrets.is_sealed("plain-text"))
        self.assertFalse(secrets.is_sealed(None))
        self.assertFalse(secrets.is_sealed(123))
        self.assertTrue(secrets.is_sealed("dpapi:anything"))


class ProfileKey(unittest.TestCase):
    """一条配置的唯一标识：host + port + username。"""

    def setUp(self):
        from wgmanager.gui import _profile_key

        self.key = _profile_key

    def test_same_host_different_port_is_distinct(self):
        a = self.key({"host": "10.0.0.1", "port": 22, "username": "root"})
        b = self.key({"host": "10.0.0.1", "port": 10022, "username": "jsd"})
        self.assertNotEqual(a, b, "同 IP 不同端口/账号被当成同一条，会互相覆盖配置")

    def test_missing_port_defaults_to_22(self):
        self.assertEqual(
            self.key({"host": "h", "username": "u"}),
            self.key({"host": "h", "port": 22, "username": "u"}),
        )
        self.assertEqual(
            self.key({"host": "h", "port": "", "username": "u"}),
            self.key({"host": "h", "port": 22, "username": "u"}),
        )

    def test_broken_port_falls_back(self):
        self.assertEqual(
            self.key({"host": "h", "port": "abc", "username": "u"}),
            self.key({"host": "h", "port": 22, "username": "u"}),
        )

    def test_string_and_int_port_match(self):
        self.assertEqual(
            self.key({"host": "h", "port": "2222", "username": "u"}),
            self.key({"host": "h", "port": 2222, "username": "u"}),
        )

    def test_whitespace_is_trimmed(self):
        self.assertEqual(
            self.key({"host": "  h  ", "port": 22, "username": " u "}),
            self.key({"host": "h", "port": 22, "username": "u"}),
        )


if __name__ == "__main__":
    unittest.main()
