"""组网隧道模块的纯逻辑测试（不碰真隧道、不需要管理员）。

真正装/卸隧道要 UAC 和内核驱动，只能真机手工验；这里只锁住
"名字清洗、conf 校验、状态解析"这些容易改坏又最容易被忽略的部分。

运行： python -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "vendor")):
    if path not in sys.path:
        sys.path.insert(0, path)

from wgmanager import tunnel  # noqa: E402

GOOD_CONF = """[Interface]
PrivateKey = aGVsbG8td29ybGQta2V5LWZvci10ZXN0aW5nPT0=
Address = 10.18.0.15/24
DNS = 10.18.0.1

[Peer]
PublicKey = c2VydmVyLXB1YmxpYy1rZXktZm9yLXRlc3Rpbmc9PQ==
PresharedKey = cHNrLWZvci10ZXN0aW5nLXB1cnBvc2VzLW9ubHk9PQ==
AllowedIPs = 10.18.0.0/24
Endpoint = 8.134.138.130:51820
PersistentKeepalive = 25
"""


class TestNormalizeName(unittest.TestCase):
    def test_prefix_is_added(self):
        self.assertEqual(tunnel.normalize_name("18-rl"), "wgm-18-rl")

    def test_existing_prefix_kept(self):
        self.assertEqual(tunnel.normalize_name("wgm-office"), "wgm-office")

    def test_suffix_and_illegal_chars(self):
        # 中文名洗不出合法字符就退回默认名 —— Windows 服务名不能乱来
        self.assertEqual(tunnel.normalize_name("研发室 机器.conf"), "wgm-tunnel")
        self.assertEqual(tunnel.normalize_name("office 现场/1"), "wgm-office-1")
        self.assertTrue(tunnel.normalize_name("a/b\\c:d").startswith("wgm-"))

    def test_empty_falls_back(self):
        self.assertEqual(tunnel.normalize_name("   "), "wgm-tunnel")

    def test_length_capped(self):
        self.assertLessEqual(len(tunnel.normalize_name("x" * 200)), 60)


class TestUniqueName(unittest.TestCase):
    def test_avoids_taken(self):
        self.assertEqual(tunnel.unique_name("office", ["wgm-office"]),
                         "wgm-office-2")

    def test_free_name_untouched(self):
        self.assertEqual(tunnel.unique_name("office", ["wgm-18-rl"]),
                         "wgm-office")


class TestValidateConf(unittest.TestCase):
    def test_good_conf_passes(self):
        self.assertEqual(tunnel.validate_conf(GOOD_CONF), [])

    def test_empty(self):
        self.assertTrue(tunnel.validate_conf(""))

    def test_missing_private_key(self):
        text = GOOD_CONF.replace(
            "PrivateKey = aGVsbG8td29ybGQta2V5LWZvci10ZXN0aW5nPT0=\n", "")
        problems = tunnel.validate_conf(text)
        self.assertTrue(any("PrivateKey" in p for p in problems))

    def test_missing_endpoint(self):
        text = GOOD_CONF.replace("Endpoint = 8.134.138.130:51820\n", "")
        problems = tunnel.validate_conf(text)
        self.assertTrue(any("Endpoint" in p for p in problems))

    def test_comments_are_ignored(self):
        text = "# PrivateKey = fake 注释里的不算\n" + GOOD_CONF.replace(
            "PrivateKey = aGVsbG8td29ybGQta2V5LWZvci10ZXN0aW5nPT0=\n", "")
        problems = tunnel.validate_conf(text)
        self.assertTrue(any("PrivateKey" in p for p in problems))


class TestConfNotes(unittest.TestCase):
    def test_full_tunnel_warned(self):
        text = GOOD_CONF.replace("AllowedIPs = 10.18.0.0/24",
                                 "AllowedIPs = 0.0.0.0/0, ::/0")
        notes = tunnel.conf_notes(text)
        self.assertTrue(any("全隧道" in n for n in notes))

    def test_no_keepalive_warned(self):
        text = GOOD_CONF.replace("PersistentKeepalive = 25\n", "")
        notes = tunnel.conf_notes(text)
        self.assertTrue(any("Keepalive" in n for n in notes))

    def test_clean_conf_has_no_notes(self):
        self.assertEqual(tunnel.conf_notes(GOOD_CONF), [])


class TestStateHelpers(unittest.TestCase):
    def test_service_name(self):
        self.assertEqual(tunnel.service_name("wgm-x"), "WireGuardTunnel$wgm-x")

    def test_state_of_absent_tunnel_is_absent_or_unknown(self):
        # 不存在的隧道必须是 absent（不能是 running），否则连接前会误判
        self.assertIn(tunnel.service_state("wgm-definitely-not-a-tunnel-xyz"),
                      ("absent", "unknown", "stopped"))

    def test_tcp_ok_refuses_empty_host(self):
        self.assertFalse(tunnel.tcp_ok("", 22))

    def test_start_rejects_empty_conf(self):
        with self.assertRaises(tunnel.TunnelError):
            tunnel.start("wgm-x", "   ", wait=1, log=lambda _m: None)


class TestTunnelStore(unittest.TestCase):
    """隧道仓库：conf 必须加密落盘，名字撞了不能互相覆盖。"""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.store = tunnel.TunnelStore(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_then_get(self):
        name = self.store.put("office", GOOD_CONF)
        self.assertEqual(name, "wgm-office")
        self.assertEqual(self.store.get(name), GOOD_CONF)

    def test_conf_is_not_stored_in_plaintext(self):
        self.store.put("office", GOOD_CONF)
        path = os.path.join(self.dir, "tunnels.json")
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("PrivateKey", raw)
        self.assertNotIn("10.18.0.15", raw)
        self.assertIn("dpapi:", raw)

    def test_same_name_overwrites_not_duplicates(self):
        first = self.store.put("office", GOOD_CONF)
        second = self.store.put("office", GOOD_CONF.replace("10.18.0.15", "10.18.0.16"))
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.all()), 1)
        self.assertIn("10.18.0.16", self.store.get(first))

    def test_prefix_never_dropped(self):
        self.assertEqual(self.store.put("研发室", GOOD_CONF), "wgm-tunnel")

    def test_all_exposes_summary_fields(self):
        self.store.put("office", GOOD_CONF)
        items = self.store.all()
        self.assertEqual(items[0]["name"], "wgm-office")
        summary = tunnel.conf_summary(items[0]["conf"])
        self.assertEqual(summary["address"], "10.18.0.15/24")
        self.assertEqual(summary["endpoint"], "8.134.138.130:51820")

    def test_drop(self):
        name = self.store.put("office", GOOD_CONF)
        self.assertTrue(self.store.drop(name))
        self.assertEqual(self.store.names(), [])
        self.assertFalse(self.store.drop(name))

    def test_rename(self):
        old = self.store.put("office", GOOD_CONF)
        new = self.store.rename(old, "home")
        self.assertEqual(new, "wgm-home")
        self.assertEqual(self.store.names(), ["wgm-home"])
        self.assertEqual(self.store.get(new), GOOD_CONF)

    def test_persists_across_instances(self):
        name = self.store.put("office", GOOD_CONF)
        again = tunnel.TunnelStore(self.dir)
        self.assertEqual(again.get(name), GOOD_CONF)

    def test_get_missing_returns_empty(self):
        self.assertEqual(self.store.get("wgm-nope"), "")
        self.assertEqual(self.store.get(""), "")


class TestLiveStats(unittest.TestCase):
    """实时流量解析。这些函数只读、纯计算，出错时界面必须能安静降级。"""

    def test_parse_dump_full(self):
        text = ("privkey\tpubkey\t65209\toff\n"
                "PEERKEY\tPSKKEY\t8.134.138.130:51820\t10.18.0.0/24\t"
                "1700000000\t1234\t5678\t25\n")
        data = tunnel.parse_wg_dump(text)
        self.assertEqual(data["listen_port"], 65209)
        self.assertEqual(data["public_key"], "pubkey")
        peer = data["peers"][0]
        self.assertTrue(peer["preshared"])
        self.assertEqual(peer["endpoint"], "8.134.138.130:51820")
        self.assertEqual(peer["allowed"], "10.18.0.0/24")
        self.assertEqual(peer["handshake"], 1700000000)
        self.assertEqual((peer["rx"], peer["tx"]), (1234, 5678))

    def test_parse_dump_without_psk_and_without_handshake(self):
        text = ("priv\tpub\t1\toff\n"
                "P\t(none)\t1.2.3.4:1\t0.0.0.0/0\t0\t0\t0\t0\n")
        peer = tunnel.parse_wg_dump(text)["peers"][0]
        self.assertFalse(peer["preshared"])
        self.assertEqual(peer["handshake"], 0)  # 0 = 还没握手

    def test_parse_dump_garbage_returns_empty(self):
        for bad in ("", "   ", "abc", "only-one-field", None):
            self.assertEqual(tunnel.parse_wg_dump(bad), {})

    def test_parse_dump_skips_short_peer_lines(self):
        text = "priv\tpub\t51820\toff\nP\t(none)\t1.2.3.4:1\n"
        self.assertEqual(tunnel.parse_wg_dump(text)["peers"], [])

    def test_conf_detail(self):
        d = tunnel.conf_detail(GOOD_CONF)
        self.assertEqual(d["address"], "10.18.0.15/24")
        self.assertEqual(d["endpoint"], "8.134.138.130:51820")
        self.assertEqual(d["allowed"], "10.18.0.0/24")
        self.assertTrue(d["preshared"])

    def test_conf_detail_empty_is_blank_not_crash(self):
        d = tunnel.conf_detail("")
        self.assertEqual(d["address"], "")
        self.assertFalse(d["preshared"])

    def test_short_key_keeps_short_keys_intact(self):
        self.assertEqual(tunnel.short_key("abc"), "abc")
        long_key = "R1h7jOzB1eP2U8HwQx8999/5czNVxag5ur7Ce3yVHk="
        short = tunnel.short_key(long_key)
        self.assertTrue(short.startswith("R1h7jOzB"))
        self.assertTrue(short.endswith("3yVHk="))
        self.assertIn("…", short)
        self.assertLess(len(short), len(long_key))

    def test_if_counters_returns_dict_on_any_platform(self):
        # 非 Windows 返回空 dict，Windows 返回 {别名: (收, 发, 状态)}，
        # 两种都不许抛异常 —— 界面每秒调一次
        got = tunnel.if_counters()
        self.assertIsInstance(got, dict)
        for key, value in got.items():
            self.assertIsInstance(key, str)
            self.assertEqual(len(value), 3)

    def test_iface_counters_of_unknown_name_is_none(self):
        self.assertIsNone(tunnel.iface_counters(""))
        self.assertIsNone(tunnel.iface_counters("wgm-definitely-not-here"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
