"""密钥有效期：元数据读写 + 过期判定 + 批量清理。"""
import datetime as dt
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "vendor")):
    if path not in sys.path:
        sys.path.insert(0, path)

from wgmanager.backend import DemoBackend  # noqa: E402
from wgmanager.config import WGConfig  # noqa: E402
from wgmanager.probe import probe  # noqa: E402
from wgmanager.service import WGService  # noqa: E402
from wgmanager.util import expire_status, parse_expire_date  # noqa: E402

LOG = lambda _m: None  # noqa: E731
CONF_PATH = "/etc/wireguard/wg0.conf"
PK = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="


def build_service():
    backend = DemoBackend(log=LOG)
    target, dep = probe(backend, {"demo": True}, LOG)
    return backend, WGService(target, dep, LOG), dep


def today():
    return dt.date.today()


def days_from_now(n: int) -> str:
    return (today() + dt.timedelta(days=n)).strftime("%Y-%m-%d")


class TestParseDate(unittest.TestCase):
    def test_standard_format(self):
        self.assertEqual(parse_expire_date("2026-11-12"), dt.date(2026, 11, 12))

    def test_alternate_separators(self):
        self.assertEqual(parse_expire_date("2026/11/12"), dt.date(2026, 11, 12))
        self.assertEqual(parse_expire_date("2026.11.12"), dt.date(2026, 11, 12))
        self.assertEqual(parse_expire_date("20261112"), dt.date(2026, 11, 12))

    def test_empty_and_junk(self):
        for value in ("", None, "   ", "明年", "2026-13-40"):
            self.assertIsNone(parse_expire_date(value), f"{value!r} 应该解析失败")

    def test_ignores_trailing_time(self):
        self.assertEqual(parse_expire_date("2026-11-12 18:30"),
                         dt.date(2026, 11, 12))


class TestStatus(unittest.TestCase):
    base = dt.date(2026, 11, 5)

    def test_no_expire(self):
        self.assertEqual(expire_status("", self.base), ("", None))

    def test_expired(self):
        text, days = expire_status("2026-11-01", self.base)
        self.assertEqual(text, "已过期")
        self.assertEqual(days, -4)

    def test_today(self):
        self.assertEqual(expire_status("2026-11-05", self.base), ("今天到期", 0))

    def test_soon(self):
        self.assertEqual(expire_status("2026-11-07", self.base), ("2 天后", 2))
        self.assertEqual(expire_status("2026-11-08", self.base), ("3 天后", 3))

    def test_far(self):
        self.assertEqual(expire_status("2026-11-20", self.base),
                         ("还剩 15 天", 15))

    def test_expired_flag_matches_days(self):
        for offset in (-10, -1, 0, 1, 5):
            text, days = expire_status(days_from_now(offset))
            self.assertEqual(days, offset)
            self.assertEqual(text == "已过期", offset < 0)


class TestConfigMeta(unittest.TestCase):
    def test_parse_expire_comment(self):
        text = (f"# WGM_NAME: 访客\n# WGM_NOTE: 临时\n"
                f"# WGM_CREATED: 2026-11-05 10:00\n# WGM_EXPIRE: 2026-11-12\n"
                f"[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n")
        conf = WGConfig(text)
        peer = conf.peers()[0]
        self.assertEqual(peer.expire, "2026-11-12")

    def test_missing_expire_is_empty(self):
        text = f"# WGM_NAME: 老配置\n[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n"
        self.assertEqual(WGConfig(text).peers()[0].expire, "")

    def test_add_peer_writes_expire(self):
        conf = WGConfig("[Interface]\nAddress = 10.8.0.1/24\n")
        conf.add_peer(public_key=PK, allowed_ips="10.8.0.9/32",
                      name="访客", expire="2026-11-12")
        self.assertIn("# WGM_EXPIRE: 2026-11-12", conf.render())
        self.assertEqual(conf.peers()[0].expire, "2026-11-12")

    def test_add_peer_without_expire_omits_line(self):
        conf = WGConfig("[Interface]\nAddress = 10.8.0.1/24\n")
        conf.add_peer(public_key=PK, allowed_ips="10.8.0.9/32", name="永久")
        self.assertNotIn("WGM_EXPIRE", conf.render())

    def test_update_peer_sets_expire(self):
        text = f"# WGM_NAME: 访客\n[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n"
        conf = WGConfig(text)
        conf.update_peer(conf.peers()[0], expire="2026-12-01")
        self.assertIn("# WGM_EXPIRE: 2026-12-01", conf.render())
        self.assertEqual(conf.peers()[0].expire, "2026-12-01")

    def test_update_peer_clears_expire(self):
        text = (f"# WGM_NAME: 访客\n# WGM_EXPIRE: 2026-11-12\n"
                f"[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n")
        conf = WGConfig(text)
        conf.update_peer(conf.peers()[0], expire="")
        self.assertNotIn("WGM_EXPIRE", conf.render())

    def test_rename_keeps_expire(self):
        """改名只动注释块，不能把有效期弄丢。"""
        text = (f"# WGM_NAME: 旧名\n# WGM_EXPIRE: 2026-11-12\n"
                f"[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n")
        conf = WGConfig(text)
        conf.update_peer(conf.peers()[0], name="新名")
        peer = conf.peers()[0]
        self.assertEqual(peer.name, "新名")
        self.assertEqual(peer.expire, "2026-11-12")

    def test_note_change_keeps_expire(self):
        text = (f"# WGM_NAME: 甲\n# WGM_NOTE: 旧备注\n# WGM_EXPIRE: 2026-11-12\n"
                f"[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n")
        conf = WGConfig(text)
        conf.update_peer(conf.peers()[0], note="新备注")
        peer = conf.peers()[0]
        self.assertEqual(peer.note, "新备注")
        self.assertEqual(peer.expire, "2026-11-12")

    def test_address_change_keeps_expire(self):
        text = (f"# WGM_NAME: 甲\n# WGM_EXPIRE: 2026-11-12\n"
                f"[Peer]\nPublicKey = {PK}\nAllowedIPs = 10.8.0.9/32\n")
        conf = WGConfig(text)
        conf.update_peer(conf.peers()[0], allowed_ips="10.8.0.10/32")
        self.assertEqual(conf.peers()[0].expire, "2026-11-12")
        self.assertEqual(conf.peers()[0].allowed_ips, "10.8.0.10/32")

    def test_expire_roundtrip_through_render(self):
        conf = WGConfig("[Interface]\nAddress = 10.8.0.1/24\n")
        conf.add_peer(public_key=PK, allowed_ips="10.8.0.9/32",
                      name="访客", expire="2026-11-12")
        again = WGConfig(conf.render())
        self.assertEqual(again.peers()[0].expire, "2026-11-12")


class TestServiceExpire(unittest.TestCase):
    def test_add_peer_with_expire(self):
        _backend, svc, _dep = build_service()
        res = svc.add_peer(name="临时访客", expire=days_from_now(7))
        self.assertEqual(res.expire, days_from_now(7))
        conf = svc.refresh_conf()
        peer = next(p for p in conf.peers() if p.public_key == res.public_key)
        self.assertEqual(peer.expire, days_from_now(7))

    def test_add_peer_rejects_bad_date(self):
        _backend, svc, _dep = build_service()
        with self.assertRaises(ValueError):
            svc.add_peer(name="坏日期", expire="下周三")

    def test_list_peers_exposes_expire(self):
        _backend, svc, _dep = build_service()
        svc.add_peer(name="临时访客", expire=days_from_now(2))
        views = svc.list_peers()
        view = next(v for v in views if v.name == "临时访客")
        self.assertEqual(view.expire, days_from_now(2))
        self.assertEqual(view.expire_days, 2)
        self.assertFalse(view.expired)
        self.assertEqual(view.expire_text, "2 天后")

    def test_update_peer_sets_expire(self):
        _backend, svc, _dep = build_service()
        res = svc.add_peer(name="访客")
        svc.update_peer(res.public_key, expire=days_from_now(30))
        conf = svc.refresh_conf()
        peer = next(p for p in conf.peers() if p.public_key == res.public_key)
        self.assertEqual(peer.expire, days_from_now(30))

    def test_update_peer_marks_changed(self):
        _backend, svc, _dep = build_service()
        res = svc.add_peer(name="访客")
        updated = svc.update_peer(res.public_key, expire=days_from_now(10))
        self.assertIn("有效期", updated.changed)

    def test_update_with_same_expire_is_noop(self):
        _backend, svc, _dep = build_service()
        when = days_from_now(10)
        res = svc.add_peer(name="访客", expire=when)
        updated = svc.update_peer(res.public_key, expire=when)
        self.assertEqual(updated.changed, [])

    def test_expired_peers_detects_past_date(self):
        backend, svc, _dep = build_service()
        res = svc.add_peer(name="过期访客")
        # 直接把过期日期写进配置，模拟"放了一段时间没管"
        conf = svc.refresh_conf()
        peer = next(p for p in conf.peers() if p.public_key == res.public_key)
        conf.update_peer(peer, expire="2020-01-01")
        backend.fs[CONF_PATH] = conf.render()
        names = [p.display_name for p in svc.expired_peers()]
        self.assertEqual(names, ["过期访客"])

    def test_expired_peers_ignores_future_and_empty(self):
        _backend, svc, _dep = build_service()
        svc.add_peer(name="未来", expire=days_from_now(5))
        svc.add_peer(name="永久")
        self.assertEqual(svc.expired_peers(), [])

    def test_remove_expired_deletes_only_expired(self):
        backend, svc, _dep = build_service()
        keep = svc.add_peer(name="保留", expire=days_from_now(9))
        gone = svc.add_peer(name="该删")
        conf = svc.refresh_conf()
        peer = next(p for p in conf.peers() if p.public_key == gone.public_key)
        conf.update_peer(peer, expire="2020-01-01")
        backend.fs[CONF_PATH] = conf.render()

        removed = svc.remove_expired()
        self.assertEqual(removed, ["该删"])
        keys = {p.public_key for p in svc.refresh_conf().peers()}
        self.assertIn(keep.public_key, keys)
        self.assertNotIn(gone.public_key, keys)

    def test_remove_expired_when_none(self):
        _backend, svc, _dep = build_service()
        self.assertEqual(svc.remove_expired(), [])
        self.assertEqual(len(svc.refresh_conf().peers()), 3)


if __name__ == "__main__":
    unittest.main()
