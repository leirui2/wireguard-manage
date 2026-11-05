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

    def test_qr_png(self):
        import struct

        from wgmanager.util import qr_png

        conf = (
            "[Interface]\nPrivateKey = aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEF=\n"
            "Address = 10.8.0.6/32\nDNS = 1.1.1.1\n\n[Peer]\n"
            "PublicKey = QwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcde=\n"
            "AllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
        )
        png, version = qr_png(conf)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"), "不是合法的 PNG")
        self.assertGreater(len(png), 500)
        self.assertGreaterEqual(version, 1)
        width, height = struct.unpack(">II", png[16:24])  # IHDR 里的宽高
        self.assertEqual(width, height, "二维码应该是正方形")
        self.assertGreaterEqual(width, 200, "二维码太小，手机扫不动")

        _small, v_small = qr_png(conf)
        _big, v_big = qr_png(conf * 8)
        self.assertGreater(v_big, v_small, "内容变长后二维码版本应该变高")

    def test_qr_symbol_is_well_formed(self):
        """三个定位角 + 时序图形都在，确保生成的确实是可扫的二维码。"""
        import segno

        text = (
            "[Interface]\nPrivateKey = aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEF=\n"
            "Address = 10.8.0.6/32\nDNS = 1.1.1.1\n\n[Peer]\n"
            "PublicKey = QwErTyUiOpAsDfGhJkLzXcVbNm1234567890abcde=\n"
            "AllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
        )
        m = [list(row) for row in segno.make(text, error="m", micro=False).matrix]
        n = len(m)

        def finder(r, c):
            blk = [m[r + i][c : c + 7] for i in range(7)]
            return (
                all(v == 1 for v in blk[0])
                and all(v == 1 for v in blk[6])
                and all(row[0] == 1 and row[6] == 1 for row in blk)
                and all(v == 0 for v in blk[1][1:6])
                and all(v == 0 for v in blk[5][1:6])
                and all(blk[3][j] == 1 for j in range(2, 5))
            )

        self.assertTrue(finder(0, 0), "缺左上定位角")
        self.assertTrue(finder(0, n - 7), "缺右上定位角")
        self.assertTrue(finder(n - 7, 0), "缺左下定位角")
        timing = m[6][8 : n - 8]
        self.assertTrue(all(timing[i] != timing[i + 1] for i in range(len(timing) - 1)),
                        "时序图形不交替，不是合法二维码")

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


class _ScriptedBackend:
    """按命令子串返回预设输出的假服务器，用来验证一键安装的每一步。

    匹配规则按顺序取第一条命中的，所以更具体的命令要排在前面
    （比如 "route show default" 必须排在 "route show" 之前）。
    """

    host = "203.0.113.9"
    sudo_mode = "password"
    is_root = False
    label = "fake"

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.commands: list[str] = []
        self.stdins: list[str | None] = []

    def run(self, cmd, root=False, stdin=None, timeout=25):
        from wgmanager.backend import CmdResult

        self.commands.append(cmd)
        self.stdins.append(stdin)
        for key, out, err, code in self.responses:
            if key in cmd:
                return CmdResult(out, err, code, cmd)
        return CmdResult("", "", 0, cmd)

    def close(self):
        pass


def _install_backend(**over):
    from wgmanager.util import local_keypair

    priv, pub = local_keypair()
    os_release = (
        'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\n'
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
    )
    base = {
        "cat /etc/os-release": (os_release, "", 0),
        "route show default": (
            "default via 192.168.3.1 dev eth0 proto dhcp src 192.168.3.88\n", "", 0),
        "ip -4 route show": (
            "default via 192.168.3.1 dev eth0 proto dhcp src 192.168.3.88\n"
            "10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.1\n"
            "192.168.3.0/24 dev eth0 proto kernel scope link src 192.168.3.88\n", "", 0),
        "ss -lun": ("UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n", "", 0),
        "command -v ufw": ("", "", 1),
        "command -v firewall-cmd": ("", "", 1),
        "sysctl -n net.ipv4.ip_forward": ("0\n", "", 0),
        "test -e /etc/wireguard/wg0.conf": ("NONE\n", "", 0),
        "wg genkey": (priv + "\n", "", 0),
        "wg pubkey": (pub + "\n", "", 0),
        "wg show wg0 public-key": (pub + "\n", "", 0),
        "apt-get": ("", "", 0),
    }
    base.update(over)
    return _ScriptedBackend([(k, *v) for k, v in base.items()]), pub, priv


class TestInstaller(unittest.TestCase):
    def test_parse_os_release(self):
        from wgmanager.installer import parse_os_release, platform_from_release

        info = parse_os_release(
            'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        )
        self.assertEqual(info["ID"], "ubuntu")
        self.assertEqual(info["PRETTY_NAME"], "Ubuntu 22.04.4 LTS")

        ubuntu = platform_from_release(info)
        self.assertEqual(ubuntu.family, "debian")
        self.assertIn("apt-get install -y wireguard", ubuntu.install_cmd)
        self.assertTrue(ubuntu.supported)

        rocky = platform_from_release({"ID": "rocky", "ID_LIKE": "rhel centos fedora"})
        self.assertEqual(rocky.family, "rhel")
        self.assertIn("wireguard-tools", rocky.install_cmd)

        arch = platform_from_release({"ID": "arch"})
        self.assertEqual(arch.family, "arch")
        self.assertIn("pacman", arch.install_cmd)

        other = platform_from_release({"ID": "plan9"})
        self.assertFalse(other.supported)
        self.assertTrue(other.notes)

    def test_build_plan_avoids_used_subnet_and_port(self):
        from wgmanager.installer import Options, build_plan

        backend, _pub, _priv = _install_backend()
        plan = build_plan(backend, Options(), "203.0.113.9")
        # 10.8.0.0/24 已被占用 -> 顺延到 10.9.0.0/24
        self.assertEqual(plan.subnet, "10.9.0.0/24")
        self.assertEqual(plan.server_address, "10.9.0.1/24")
        # 51820 已被占用 -> 顺延
        self.assertEqual(plan.listen_port, 51821)
        self.assertEqual(plan.default_iface, "eth0")
        self.assertEqual(plan.conf_path, "/etc/wireguard/wg0.conf")
        self.assertTrue(any("安装 WireGuard" in s for s in plan.steps))

    def test_render_conf(self):
        from wgmanager.installer import Options, Plan, Platform, render_conf

        plan = Plan(platform=Platform(name="Ubuntu"), default_iface="eth0")
        plan.server_address = "10.9.0.1/24"
        plan.listen_port = 51821
        text = render_conf("PRIVKEY", plan, enable_nat=True)
        self.assertIn("[Interface]", text)
        self.assertIn("Address = 10.9.0.1/24", text)
        self.assertIn("ListenPort = 51821", text)
        self.assertIn("PrivateKey = PRIVKEY", text)
        self.assertIn("POSTROUTING -o eth0 -j MASQUERADE", text)
        self.assertIn("PostDown", text)
        self.assertNotIn("SaveConfig", text)

        plain = render_conf("PRIVKEY", plan, enable_nat=False)
        self.assertNotIn("iptables", plain)

    def test_refuses_to_overwrite_existing_conf(self):
        from wgmanager.installer import Options, build_plan, run_install

        backend, _pub, _priv = _install_backend(
            **{"test -e /etc/wireguard/wg0.conf": ("EXISTS\n", "", 0)}
        )
        plan = build_plan(backend, Options(), "")
        with self.assertRaises(RuntimeError) as ctx:
            run_install(backend, plan, Options(), LOG)
        self.assertIn("已经存在", str(ctx.exception))
        # 一条安装命令都不能执行
        self.assertFalse(any("apt-get" in c for c in backend.commands))

    def test_install_happy_path(self):
        from wgmanager.installer import Options, build_plan, run_install

        backend, pub, priv = _install_backend()
        opts = Options(subnet="10.55.0.0/24", listen_port=52000)
        plan = build_plan(backend, opts, "")
        self.assertEqual(plan.subnet, "10.55.0.0/24")
        self.assertEqual(plan.server_address, "10.55.0.1/24")
        self.assertEqual(plan.listen_port, 52000)

        result = run_install(backend, plan, opts, LOG)
        self.assertTrue(result.started)
        self.assertEqual(result.public_key, pub)
        self.assertEqual(result.conf_path, "/etc/wireguard/wg0.conf")

        # 私钥只能出现在 stdin 里，绝不能出现在命令行
        self.assertFalse(any(priv in c for c in backend.commands))
        conf_stdin = [s for s in backend.stdins if s and "PrivateKey" in s]
        self.assertTrue(conf_stdin)
        self.assertIn(f"PrivateKey = {priv}", conf_stdin[0])
        self.assertIn("Address = 10.55.0.1/24", conf_stdin[0])

        joined = " ;; ".join(backend.commands)
        self.assertIn("apt-get install -y wireguard", joined)
        self.assertIn("systemctl enable wg-quick@", joined)
        self.assertIn("sysctl", joined)

    def test_warns_when_iface_already_exists(self):
        from wgmanager.installer import Options, build_plan

        backend, _pub, _priv = _install_backend(
            **{"ip -br link show": ("lo UNKNOWN\neth0 UP 00:11:22:33:44:55\nwg0 UNKNOWN\n", "", 0)}
        )
        plan = build_plan(backend, Options(), "")
        self.assertTrue(any("已经存在" in n for n in plan.notes), plan.notes)

    def test_install_rejects_busy_port(self):
        from wgmanager.installer import Options, build_plan

        backend, _pub, _priv = _install_backend()
        with self.assertRaises(ValueError) as ctx:
            build_plan(backend, Options(listen_port=51820), "")
        self.assertIn("已被占用", str(ctx.exception))

    def test_unsupported_platform_aborts(self):
        from wgmanager.installer import Options, build_plan, run_install

        backend, _pub, _priv = _install_backend(
            **{"cat /etc/os-release": ("ID=plan9\n", "", 0)}
        )
        plan = build_plan(backend, Options(), "")
        self.assertFalse(plan.platform.supported)
        with self.assertRaises(RuntimeError):
            run_install(backend, plan, Options(), LOG)


class TestServerMissing(unittest.TestCase):
    def _empty_server(self, sudo_mode="password"):
        backend = _ScriptedBackend()
        backend.sudo_mode = sudo_mode
        return backend

    def test_missing_server_is_installable(self):
        from wgmanager.probe import ServerMissing, probe

        backend = self._empty_server("password")
        with self.assertRaises(ServerMissing) as ctx:
            probe(backend, {}, LOG)
        self.assertTrue(ctx.exception.installable)

    def test_permission_problem_is_not_installable(self):
        from wgmanager.probe import ProbeError, ServerMissing, probe

        backend = self._empty_server("none")
        with self.assertRaises(ProbeError) as ctx:
            probe(backend, {}, LOG)
        self.assertNotIsInstance(ctx.exception, ServerMissing)


class TestClientDownloads(unittest.TestCase):
    """下载链接只收官方来源，写错域名等于把人导到钓鱼站。"""

    def test_links_are_official(self):
        from wgmanager.downloads import CLIENTS, OFFICIAL_INSTALL_PAGE

        allowed = (
            "https://download.wireguard.com/",
            "https://play.google.com/store/apps/details?id=com.wireguard.android",
            "https://apps.apple.com/",
            "https://www.wireguard.com/",
        )
        self.assertTrue(OFFICIAL_INSTALL_PAGE.startswith("https://www.wireguard.com/"))
        self.assertGreaterEqual(len(CLIENTS), 4)
        platforms = [c["platform"] for c in CLIENTS]
        for name in ("Windows", "Android", "iOS / iPadOS"):
            self.assertIn(name, platforms)
        for item in CLIENTS:
            with self.subTest(platform=item["platform"]):
                self.assertTrue(item["url"].startswith("https://"), item["url"])
                self.assertTrue(item["url"].startswith(allowed), item["url"])
                self.assertTrue(item["hint"].strip())
                self.assertIn(item["action"], ("下载", "打开"))

    def test_windows_installer_and_package_ids(self):
        from wgmanager.downloads import CLIENTS

        by_platform = {c["platform"]: c["url"] for c in CLIENTS}
        self.assertTrue(
            by_platform["Windows"].endswith("/wireguard-installer.exe"),
            by_platform["Windows"],
        )
        self.assertIn("com.wireguard.android", by_platform["Android"])
        self.assertIn("id1441195209", by_platform["iOS / iPadOS"])
        # macOS 的 App Store id 和 iOS 不是同一个，别抄错
        self.assertIn("id1451685025", by_platform.get("macOS", ""))
        self.assertNotEqual(by_platform["macOS"], by_platform["iOS / iPadOS"])


class TestQrDialog(unittest.TestCase):
    def test_image_survives_garbage_collection(self):
        """真实路径下没人持有 QrDialog 实例，图片引用必须挂在窗口上，否则界面留白。"""
        import gc

        try:
            import tkinter as tk
            from tkinter import ttk

            from wgmanager.gui import QrDialog

            root = tk.Tk()
            root.withdraw()
        except Exception as exc:  # 无图形环境时跳过
            self.skipTest(f"no display: {exc}")

        try:
            QrDialog(
                root, "测试二维码",
                "[Interface]\nPrivateKey = abc\nAddress = 10.8.0.6/32\n\n"
                "[Peer]\nPublicKey = xyz\nAllowedIPs = 0.0.0.0/0\n",
                "t", lambda _m: None,
            )
            gc.collect()

            tops = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)]
            self.assertTrue(tops, "二维码窗口没有创建出来")
            qr = tops[-1]
            qr.update_idletasks()

            self.assertTrue(hasattr(qr, "image"), "图片引用没挂在窗口上，会被回收")
            self.assertGreaterEqual(qr.image.width(), 300)

            def find_image_label(widget):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Label) and str(child.cget("image")):
                        return child
                    found = find_image_label(child)
                    if found is not None:
                        return found
                return None

            label = find_image_label(qr)
            self.assertIsNotNone(label, "窗口里找不到显示图片的控件")
            self.assertGreaterEqual(label.winfo_reqwidth(), 300, "图片没显示出来（引用被回收）")
        finally:
            root.destroy()


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
