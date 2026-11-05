"""核心逻辑测试：用内存模拟服务器跑通 探测 / 查看 / 新增 / 删除 / 回滚。

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

from wgmanager.backend import DemoBackend, _demo_key, _SERVER_PRIV  # noqa: E402
from wgmanager.config import WGConfig, stripped_for_syncconf  # noqa: E402
from wgmanager.probe import probe  # noqa: E402
from wgmanager.service import WGService  # noqa: E402
from wgmanager.util import allocate_addresses, is_wg_key, pub_from_priv  # noqa: E402

CONF_PATH = "/etc/wireguard/wg0.conf"
LOG = lambda _m: None  # noqa: E731


def build_service():
    backend = DemoBackend(log=LOG)
    target, dep = probe(backend, {"demo": True}, LOG)
    return backend, WGService(target, dep, LOG), dep


class TestConfig(unittest.TestCase):
    def test_parse_and_preserve(self):
        text = DemoBackend().fs[CONF_PATH]
        conf = WGConfig(text)
        peers = conf.peers()
        self.assertEqual(len(peers), 3)
        self.assertEqual(peers[0].raw_name, "zhangsan-laptop")
        self.assertEqual(peers[0].note, "研发部 / 长期有效")
        self.assertEqual(peers[0].allowed_ips, "10.8.0.2/32, fd08::2/128")
        self.assertIn("PostUp = iptables -A FORWARD -i %i -j ACCEPT", conf.render())
        self.assertIn("# 上面这些行在工具改写配置时会原样保留", conf.render())

    def test_foreign_name_comment(self):
        text = "### Client old-phone\n[Peer]\nPublicKey = " + _demo_key("old") + "\nAllowedIPs = 10.8.0.9/32\n"
        peer = WGConfig(text).peers()[0]
        self.assertEqual(peer.raw_name, "old-phone")

    def test_add_then_remove_roundtrip(self):
        original = DemoBackend().fs[CONF_PATH]
        conf = WGConfig(original)
        before = conf.render()
        conf.add_peer(public_key=_demo_key("new"), allowed_ips="10.8.0.7/32",
                      name="tmp", note="n", created="2026-11-05 09:00")
        self.assertEqual(len(conf.peers()), 4)
        conf.remove_peer(conf.peers()[-1])
        self.assertEqual(len(conf.peers()), 3)
        self.assertEqual(conf.render(), before)

    def test_strip(self):
        stripped = stripped_for_syncconf(DemoBackend().fs[CONF_PATH])
        self.assertIn("[Peer]", stripped)
        self.assertNotIn("Address", stripped)
        self.assertNotIn("PostUp", stripped)
        self.assertNotIn("WGM_NAME", stripped)

    def test_update_peer_keeps_other_lines(self):
        conf = WGConfig(DemoBackend().fs[CONF_PATH])
        peer = conf.peers()[2]
        conf.update_peer(peer, name="改名了", note="新备注", allowed_ips="10.8.0.44/32")
        out = conf.render()
        self.assertIn("# WGM_NAME: 改名了", out)
        self.assertIn("# WGM_NOTE: 新备注", out)
        self.assertIn("AllowedIPs = 10.8.0.44/32", out)
        self.assertIn("PostUp = iptables -A FORWARD -i %i -j ACCEPT", out)
        self.assertIn("# 上面这些行在工具改写配置时会原样保留", out)

        again = WGConfig(out)
        self.assertEqual(len(again.peers()), 3)
        self.assertEqual(again.peers()[0].raw_name, "zhangsan-laptop")
        self.assertEqual(again.peers()[2].raw_name, "改名了")
        self.assertEqual(again.peers()[2].note, "新备注")
        self.assertEqual(again.peers()[2].allowed_ips, "10.8.0.44/32")
        # 公钥不能被改动
        self.assertEqual(again.peers()[2].public_key, peer.public_key)

    def test_update_peer_adds_meta_to_unnamed(self):
        text = (
            "[Interface]\nAddress = 10.8.0.1/24\n\n"
            "[Peer]\nPublicKey = " + _demo_key("x") + "\nAllowedIPs = 10.8.0.9/32\n"
        )
        conf = WGConfig(text)
        self.assertEqual(conf.peers()[0].raw_name, "")
        conf.update_peer(conf.peers()[0], name="无名氏", note="补个备注")
        out = conf.render()
        self.assertIn("# WGM_NAME: 无名氏", out)
        self.assertTrue(out.startswith("[Interface]\nAddress = 10.8.0.1/24\n"))
        peer = WGConfig(out).peers()[0]
        self.assertEqual((peer.raw_name, peer.note), ("无名氏", "补个备注"))
        self.assertEqual(peer.allowed_ips, "10.8.0.9/32")

    def test_update_peer_only_note_keeps_name(self):
        conf = WGConfig(DemoBackend().fs[CONF_PATH])
        conf.update_peer(conf.peers()[0], note="只改备注")
        peer = WGConfig(conf.render()).peers()[0]
        self.assertEqual(peer.raw_name, "zhangsan-laptop")
        self.assertEqual(peer.note, "只改备注")


class TestUtil(unittest.TestCase):
    def test_allocate_ipv4_ipv6(self):
        result = allocate_addresses(
            ["10.8.0.1/24, fd08::1/64"],
            ["10.8.0.2/32, fd08::2/128", "10.8.0.3/32, fd08::3/128"],
        )
        self.assertEqual(result, ["10.8.0.4/32", "fd08::4/128"])

    def test_normalize_allowed_ips(self):
        from wgmanager.util import normalize_allowed_ips

        self.assertEqual(normalize_allowed_ips("10.8.0.9"), "10.8.0.9/32")
        self.assertEqual(normalize_allowed_ips("fd08::9"), "fd08::9/128")
        self.assertEqual(
            normalize_allowed_ips(" 10.8.0.9 , fd08::9/128 "), "10.8.0.9/32, fd08::9/128"
        )
        self.assertEqual(normalize_allowed_ips("10.8.0.0/24"), "10.8.0.0/24")
        for bad in ("", "abc", "10.8.0.1/33", "0.0.0.0/0", "::/0"):
            with self.assertRaises(ValueError):
                normalize_allowed_ips(bad)

    def test_patch_client_conf(self):
        from wgmanager.util import patch_client_conf

        text = (
            "# 注释保留\n[Interface]\nPrivateKey = abc\nAddress = 10.8.0.2/32\n"
            "DNS = 1.1.1.1\n\n[Peer]\nPublicKey = xyz\nAllowedIPs = 0.0.0.0/0\n"
        )
        out = patch_client_conf(text, ["10.8.0.30/32"])
        self.assertIn("Address = 10.8.0.30/32", out)
        self.assertNotIn("Address = 10.8.0.2/32", out)
        self.assertIn("PrivateKey = abc", out)
        self.assertIn("DNS = 1.1.1.1", out)
        self.assertIn("AllowedIPs = 0.0.0.0/0", out)  # 只改 Interface 里的 Address

    def test_local_pubkey(self):
        self.assertTrue(is_wg_key(pub_from_priv(_SERVER_PRIV)))


class TestProbe(unittest.TestCase):
    def test_probe(self):
        _backend, _svc, dep = build_service()
        self.assertEqual(dep.kind, "native")
        self.assertEqual(dep.iface, "wg0")
        self.assertEqual(dep.conf_path, CONF_PATH)
        self.assertEqual(dep.listen_port, 51820)
        self.assertEqual(len(dep.addresses), 2)
        self.assertTrue(dep.interface_up)
        self.assertTrue(dep.has_wg_quick)
        self.assertTrue(is_wg_key(dep.server_public_key))
        self.assertEqual(dep.server_public_key, pub_from_priv(_SERVER_PRIV))
        self.assertEqual(dep.dns, ["1.1.1.1", "8.8.8.8"])


class _NoSudoBackend:
    """模拟「不是 root、也没有免密 sudo、还没填 sudo 密码」的服务器。"""

    host = "1.2.3.4"
    sudo_mode = "none"
    is_root = False
    label = "fake"

    def run(self, cmd, root=False, stdin=None, timeout=25):
        from wgmanager.backend import CmdResult

        if root:
            return CmdResult(
                "",
                "需要 root 权限，但当前账号不是 root、也不能免密 sudo。"
                "请在连接区填写「sudo 密码」，或改用 root 账号登录。",
                1,
                cmd,
            )
        return CmdResult("", "", 0, cmd)

    def close(self):
        pass


class TestProbeErrors(unittest.TestCase):
    def test_permission_problem_reported_as_sudo_issue(self):
        """权限不足时不能再笼统地报「没有找到配置文件」。"""
        from wgmanager.probe import ProbeError, probe

        with self.assertRaises(ProbeError) as ctx:
            probe(_NoSudoBackend(), {}, LOG)
        msg = str(ctx.exception)
        self.assertIn("sudo 密码", msg)
        self.assertNotIn("没有找到 WireGuard 配置文件（已检查", msg)


class TestService(unittest.TestCase):
    def test_list(self):
        _b, svc, _d = build_service()
        views = svc.list_peers()
        self.assertEqual(len(views), 3)
        self.assertEqual(sum(1 for v in views if v.online), 1)
        self.assertEqual(views[0].address, "10.8.0.2, fd08::2")

    def test_add_peer(self):
        backend, svc, dep = build_service()
        result = svc.add_peer(name="zhaoliu-test", note="自动化测试", use_psk=True)
        self.assertEqual(result.name, "zhaoliu-test")
        self.assertEqual(result.addresses, ["10.8.0.5/32", "fd08::5/128"])
        self.assertTrue(is_wg_key(result.private_key))
        self.assertTrue(is_wg_key(result.public_key))
        self.assertIn("PrivateKey = " + result.private_key, result.client_conf)
        self.assertIn("PublicKey = " + dep.server_public_key, result.client_conf)
        self.assertIn("Endpoint = 203.0.113.10:51820", result.client_conf)
        self.assertIn("PresharedKey =", result.client_conf)

        conf_text = svc.target.fs[CONF_PATH]
        self.assertIn("# WGM_NAME: zhaoliu-test", conf_text)
        self.assertIn("PostUp = iptables -A FORWARD -i %i -j ACCEPT", conf_text)
        self.assertEqual(len(WGConfig(conf_text).peers()), 4)
        self.assertTrue(any(os.path.basename(k).startswith("wg0.conf.wgmgr.bak.") for k in svc.target.fs))
        views = svc.list_peers()
        self.assertEqual(len(views), 4)
        self.assertIn(result.public_key, svc.target.runtime)

    def test_remove_peer(self):
        _backend, svc, _dep = build_service()
        views = svc.list_peers()
        key = views[2].pubkey
        names = svc.remove_peers({key})
        self.assertEqual(len(names), 1)
        self.assertEqual(len(WGConfig(svc.target.fs[CONF_PATH]).peers()), 2)
        self.assertNotIn(key, svc.target.runtime)
        self.assertEqual(len(svc.list_peers()), 2)

    def test_duplicate_name_rejected(self):
        _backend, svc, _dep = build_service()
        with self.assertRaises(ValueError):
            svc.add_peer(name="zhangsan-laptop")

    def test_rollback_when_reload_broken(self):
        backend, svc, _dep = build_service()
        original = backend.fs[CONF_PATH]
        backend.broken_reload = True
        with self.assertRaises(RuntimeError):
            svc.add_peer(name="should-rollback")
        self.assertEqual(backend.fs[CONF_PATH], original)
        self.assertEqual(len(svc.list_peers()), 3)

    def test_manual_vpn_address(self):
        _backend, svc, _dep = build_service()
        result = svc.add_peer(name="manual-ip", vpn_addresses="10.8.0.99/32, fd08::99/128",
                              use_psk=False)
        self.assertEqual(result.addresses, ["10.8.0.99/32", "fd08::99/128"])
        self.assertNotIn("PresharedKey", result.client_conf)

    # ------------------------------------------------------------- 修改密钥
    def test_update_peer_rename(self):
        _backend, svc, _dep = build_service()
        key = svc.list_peers()[2].pubkey
        res = svc.update_peer(key, name="wangwu-ipad", note="行政部 / 王五")
        self.assertEqual(res.changed, ["名称", "备注"])
        self.assertEqual(res.name, "wangwu-ipad")
        self.assertFalse(res.address_changed)
        text = svc.target.fs[CONF_PATH]
        self.assertIn("# WGM_NAME: wangwu-ipad", text)
        self.assertIn("# WGM_NOTE: 行政部 / 王五", text)
        self.assertIn("PostUp = iptables", text)
        self.assertTrue(any(os.path.basename(k).startswith("wg0.conf.wgmgr.bak.") for k in svc.target.fs))
        views = svc.list_peers()
        self.assertIn("wangwu-ipad", [v.name for v in views])
        self.assertEqual(views[2].note, "行政部 / 王五")

    def test_update_peer_address(self):
        _backend, svc, _dep = build_service()
        key = svc.list_peers()[0].pubkey
        res = svc.update_peer(key, allowed_ips="10.8.0.20/32, fd08::20/128")
        self.assertTrue(res.address_changed)
        self.assertEqual(res.changed, ["VPN 地址"])
        self.assertEqual(res.addresses, ["10.8.0.20/32", "fd08::20/128"])
        self.assertEqual(res.old_allowed_ips, "10.8.0.2/32, fd08::2/128")
        self.assertTrue(any("Address" in w for w in res.warnings))
        text = svc.target.fs[CONF_PATH]
        self.assertIn("AllowedIPs = 10.8.0.20/32, fd08::20/128", text)
        self.assertNotIn("10.8.0.2/32", text)
        self.assertEqual(svc.list_peers()[0].address, "10.8.0.20, fd08::20")

    def test_update_peer_bare_ip_filled_with_prefix(self):
        _backend, svc, _dep = build_service()
        key = svc.list_peers()[1].pubkey
        res = svc.update_peer(key, allowed_ips="10.8.0.77")
        self.assertEqual(res.new_allowed_ips, "10.8.0.77/32")
        self.assertEqual(res.addresses, ["10.8.0.77/32"])

    def test_update_peer_rejects_taken_address(self):
        _backend, svc, _dep = build_service()
        views = svc.list_peers()
        original = svc.target.fs[CONF_PATH]
        with self.assertRaises(ValueError) as ctx:
            svc.update_peer(views[0].pubkey, allowed_ips="10.8.0.3/32")
        self.assertIn("已被", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx2:
            svc.update_peer(views[0].pubkey, allowed_ips="10.8.0.1")  # 服务器自己
        self.assertIn("服务器自己", str(ctx2.exception))
        with self.assertRaises(ValueError):
            svc.update_peer(views[0].pubkey, allowed_ips="0.0.0.0/0")
        self.assertEqual(svc.target.fs[CONF_PATH], original)  # 一个字节都没写

    def test_update_peer_rejects_duplicate_name(self):
        _backend, svc, _dep = build_service()
        views = svc.list_peers()
        with self.assertRaises(ValueError):
            svc.update_peer(views[0].pubkey, name="lisi-phone")
        # 改成自己原来的名字不算冲突
        self.assertFalse(svc.update_peer(views[0].pubkey, name="zhangsan-laptop").changed)

    def test_update_peer_without_change_does_not_write(self):
        _backend, svc, _dep = build_service()
        view = svc.list_peers()[0]
        original = svc.target.fs[CONF_PATH]
        res = svc.update_peer(view.pubkey, name=view.raw_name, note=view.note,
                              allowed_ips=view.allowed_ips)
        self.assertEqual(res.changed, [])
        self.assertEqual(res.backup, "")
        self.assertEqual(svc.target.fs[CONF_PATH], original)
        self.assertFalse(any("wgmgr.bak" in k for k in svc.target.fs))

    def test_update_peer_missing_pubkey(self):
        _backend, svc, _dep = build_service()
        with self.assertRaises(ValueError):
            svc.update_peer("not-a-real-key", name="x")

    def test_update_peer_out_of_subnet_warns(self):
        _backend, svc, _dep = build_service()
        key = svc.list_peers()[0].pubkey
        res = svc.update_peer(key, allowed_ips="192.168.50.9/32")
        self.assertTrue(any("VPN 网段" in w for w in res.warnings))


class _FakeChannel:
    def __init__(self):
        self.written = b""

    def write(self, data):
        self.written += data

    def flush(self):
        pass

    @property
    def channel(self):
        return self

    def shutdown_write(self):
        pass

    def recv_exit_status(self):
        return 0


class _FakeFile:
    def __init__(self, data=b""):
        self.data = data

    def read(self):
        return self.data


class _FakeSSHClient:
    def __init__(self):
        self.commands = []
        self.channels = []

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        chan = _FakeChannel()
        self.channels.append(chan)
        return chan, _FakeFile(b"0\n"), _FakeFile(b"")


class TestSSHBackend(unittest.TestCase):
    def test_sudo_password_used_for_key_auth(self):
        """私钥登录没有 SSH 密码，必须能用单独填的 sudo 密码提权。"""
        from wgmanager.backend import SSHBackend

        backend = SSHBackend("1.2.3.4", 22, "demo-user",
                             key_path="C:/fake/id_ed25519", sudo_password="test-sudo-pass")
        backend.client = _FakeSSHClient()
        backend.is_root = False
        backend.sudo_mode = "password"
        res = backend.run("cat /etc/wireguard/wg0.conf", root=True)
        self.assertTrue(res.ok)
        self.assertEqual(backend.client.commands[-1],
                         "sudo -S -p '' cat /etc/wireguard/wg0.conf")
        self.assertEqual(backend.client.channels[-1].written, b"test-sudo-pass\n")
        self.assertNotIn("test-sudo-pass", backend.client.commands[-1])

    def test_sudo_wraps_whole_chain_and_password_goes_to_stdin(self):
        from wgmanager.backend import SSHBackend

        backend = SSHBackend("1.2.3.4", 22, "ubuntu", password="s3cr3t")
        backend.client = _FakeSSHClient()
        backend.is_root = False
        backend.sudo_mode = "password"
        res = backend.run("sh -c 'cp a b && mv b c'", root=True)
        self.assertTrue(res.ok)
        self.assertEqual(backend.client.commands[-1],
                         "sudo -S -p '' sh -c 'cp a b && mv b c'")
        self.assertEqual(backend.client.channels[-1].written, b"s3cr3t\n")
        self.assertNotIn("s3cr3t", backend.client.commands[-1])

    def test_root_login_no_sudo(self):
        from wgmanager.backend import SSHBackend

        backend = SSHBackend("1.2.3.4", 22, "root")
        backend.client = _FakeSSHClient()
        backend.is_root = True
        backend.sudo_mode = "root"
        backend.run("cat /etc/wireguard/wg0.conf", root=True)
        self.assertEqual(backend.client.commands[-1], "cat /etc/wireguard/wg0.conf")

    def test_no_sudo_permission_fails_fast(self):
        from wgmanager.backend import SSHBackend

        backend = SSHBackend("1.2.3.4", 22, "ubuntu")
        backend.client = _FakeSSHClient()
        backend.sudo_mode = "none"
        res = backend.run("cat /etc/wireguard/wg0.conf", root=True)
        self.assertFalse(res.ok)
        self.assertIn("sudo 密码", res.err)


class TestWindowPlacement(unittest.TestCase):
    def test_center_window(self):
        import re

        try:
            import tkinter as tk

            from wgmanager.gui import center_window

            root = tk.Tk()
            root.withdraw()
        except Exception as exc:  # 无图形环境时跳过
            self.skipTest(f"no display: {exc}")
        try:
            sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
            center_window(root, 800, 600)
            match = re.match(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", root.geometry())
            self.assertIsNotNone(match)
            w, h, x, y = map(int, match.groups())
            self.assertAlmostEqual(x, (sw - w) // 2, delta=3)
            self.assertAlmostEqual(y, (sh - h) // 2, delta=3)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
