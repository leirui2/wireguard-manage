"""执行后端：真实 SSH、Docker 容器、以及离线演示服务器。

三种后端都实现同一个 Backend 接口，业务层（service.py）不关心命令到底跑在哪里。

安全性：
* 主机密钥采用 TOFU（首次使用信任并落盘记录），后续指纹变化直接拒绝连接，防中间人。
* 服务器私钥只通过 stdin 交给 `wg pubkey`，不会出现在命令行、日志或进程列表里。
* 日志中的命令统一做脱敏。
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import time
from dataclasses import dataclass
from typing import Callable

from .config import WGConfig, stripped_for_syncconf
from .util import b64, local_keypair, local_psk, pub_from_priv, redact

LogFn = Callable[[str], None]


@dataclass
class CmdResult:
    out: str = ""
    err: str = ""
    code: int = 0
    cmd: str = ""

    @property
    def ok(self) -> bool:
        return self.code == 0


class Backend:
    label = "backend"
    host = "127.0.0.1"

    def run(self, cmd: str, root: bool = False, stdin: str | None = None,
            timeout: int = 25) -> CmdResult:
        raise NotImplementedError

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- SSH


class SSHBackend(Backend):
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        *,
        password: str = "",
        key_path: str = "",
        key_passphrase: str = "",
        sudo_password: str = "",
        known_hosts_path: str = "",
        log: LogFn = lambda _m: None,
    ):
        self.host = host
        self.port = int(port)
        self.username = username
        self._password = password or ""
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        # sudo 密码可以和 SSH 密码不同（私钥登录时 SSH 根本没有密码可复用）
        self._sudo_password = sudo_password or password or ""
        self.known_hosts_path = known_hosts_path
        self.log = log
        self.label = f"ssh://{username}@{host}:{port}"
        self.client = None
        self.is_root = False
        self.sudo_mode = "root"  # root | nopasswd | password | none

    def connect(self) -> None:
        import paramiko  # 延迟导入，演示模式不需要 SSH 依赖

        class _HostKeyPolicy(paramiko.MissingHostKeyPolicy):
            def __init__(self, log: LogFn):
                self.log = log

            def missing_host_key(self, client, hostname, key):
                digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
                self.log(f"首次连接 {hostname}，已记录主机指纹 SHA256:{digest.rstrip('=')}")
                client.get_host_keys().add(hostname, key.get_name(), key)

        client = paramiko.SSHClient()
        if self.known_hosts_path and os.path.isfile(self.known_hosts_path):
            try:
                client.load_host_keys(self.known_hosts_path)
            except Exception as exc:
                self.log(f"读取本机 known_hosts 失败（忽略）：{exc}")
        client.set_missing_host_key_policy(_HostKeyPolicy(self.log))

        kwargs = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            banner_timeout=20,
            auth_timeout=20,
        )
        if self.key_path:
            kwargs["pkey"] = _load_private_key(paramiko, self.key_path, self.key_passphrase)
        else:
            kwargs["password"] = self._password

        self.log(f"正在连接 {self.label} …")
        client.connect(**kwargs)
        if self.known_hosts_path:
            try:
                os.makedirs(os.path.dirname(self.known_hosts_path), exist_ok=True)
                client.save_host_keys(self.known_hosts_path)
            except Exception as exc:
                self.log(f"保存主机指纹失败（忽略）：{exc}")
        self.client = client
        self.log("SSH 连接已建立")

        who = self.run("id -u", timeout=10)
        self.is_root = who.ok and who.out.strip() == "0"
        if self.is_root:
            self.sudo_mode = "root"
            return
        probe_sudo = self.run("sudo -n true", timeout=10)
        if probe_sudo.ok:
            self.sudo_mode = "nopasswd"
            self.log("当前账号可免密 sudo")
            return
        if self._sudo_password:
            # 先假定能用密码提权，再用一条真实命令验证，避免后面一路静默失败
            self.sudo_mode = "password"
            check = self.run("id -u", root=True, timeout=12)
            if check.ok and check.out.strip() == "0":
                self.log("已用 sudo 密码取得 root 权限")
                return
            self.sudo_mode = "none"
            self.log(
                "警告：sudo 密码校验失败（可能是密码不对，或该账号不在 sudoers 里）。"
                "读取 /etc/wireguard 会失败。"
            )
            return
        self.sudo_mode = "none"
        self.log(
            "警告：当前账号既不是 root，也不能免密 sudo，且没有填写 sudo 密码。"
            "工具将无法读取/修改 /etc/wireguard。请在连接区填写「sudo 密码」，"
            "或改用 root 账号登录。"
        )

    def run(self, cmd: str, root: bool = False, stdin: str | None = None,
            timeout: int = 25) -> CmdResult:
        if self.client is None:
            return CmdResult("", "尚未建立 SSH 连接", 1, cmd)
        full = cmd
        if root and self.sudo_mode != "root":
            if self.sudo_mode == "nopasswd":
                full = "sudo -n " + cmd
            elif self.sudo_mode == "password":
                # sudo -S 只读第一行，剩余 stdin 会原样转发给子进程，二者可以共存
                full = "sudo -S -p '' " + cmd
                stdin = f"{self._sudo_password}\n" + (stdin or "")
            else:
                return CmdResult(
                    "",
                    "需要 root 权限，但当前账号不是 root、也不能免密 sudo。"
                    "请在连接区填写「sudo 密码」，或改用 root 账号登录。",
                    1,
                    cmd,
                )
        self.log("$ " + redact(full))
        try:
            si, so, se = self.client.exec_command(full, timeout=timeout)
            if stdin is not None:
                si.write(stdin.encode("utf-8"))
                si.flush()
            si.channel.shutdown_write()
            out = so.read().decode("utf-8", "replace")
            err = se.read().decode("utf-8", "replace")
            code = si.channel.recv_exit_status()
        except Exception as exc:
            return CmdResult("", str(exc), 1, full)
        return CmdResult(out, err, code, full)

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None


def _load_private_key(paramiko, path: str, passphrase: str):
    """兼容 OpenSSH / PEM / Ed25519 / ECDSA / RSA 私钥。"""
    if not os.path.isfile(path):
        raise ValueError(f"找不到私钥文件：{path}")
    pwd = passphrase.encode("utf-8") if passphrase else None
    if hasattr(paramiko.PKey, "from_path"):
        try:
            # 注意：paramiko 5.x 的 from_path 只接受 bytes 口令，传 str 会报
            # "password must be bytes"，所以这里先编码
            return paramiko.PKey.from_path(path, password=pwd)
        except Exception:
            pass
    for name in ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey"):
        cls = getattr(paramiko, name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key_file(path, password=passphrase or None)
        except Exception:
            continue
    raise ValueError("无法解析该私钥文件（格式不支持，或私钥口令不正确）")


# ------------------------------------------------------------------------ Docker


class DockerBackend(Backend):
    """把命令转发进容器执行，用于 wg-easy 之类只把配置放在容器里的部署。"""

    def __init__(self, inner: SSHBackend, container: str, need_sudo: bool = False,
                 log: LogFn = lambda _m: None):
        self.inner = inner
        self.container = container
        self.need_sudo = need_sudo
        self.host = inner.host
        self.label = f"docker://{container}@{inner.host}"
        self.log = log

    def run(self, cmd: str, root: bool = False, stdin: str | None = None,
            timeout: int = 25) -> CmdResult:
        wrapped = (
            "docker exec -i "
            + shlex.quote(self.container)
            + " sh -c "
            + shlex.quote(cmd)
        )
        # 容器内默认就是 root，root 参数只影响宿主机上的 docker 命令
        return self.inner.run(wrapped, root=self.need_sudo, stdin=stdin, timeout=timeout)

    def close(self) -> None:
        self.inner.close()


# -------------------------------------------------------------------------- 演示


def _demo_key(seed: str) -> str:
    return b64(hashlib.sha256(seed.encode("utf-8")).digest())


_SERVER_PRIV = _demo_key("demo-server-private")
_PEERS = [
    ("zhangsan-laptop", "研发部 / 长期有效", "2026-09-12 14:20", "10.8.0.2/32, fd08::2/128"),
    ("lisi-phone", "出差临时", "2026-10-03 09:05", "10.8.0.3/32, fd08::3/128"),
    ("wangwu-pad", "", "2026-10-21 16:48", "10.8.0.4/32, fd08::4/128"),
]


def _demo_conf() -> str:
    lines = [
        "[Interface]",
        "Address = 10.8.0.1/24, fd08::1/64",
        "ListenPort = 51820",
        f"PrivateKey = {_SERVER_PRIV}",
        "DNS = 1.1.1.1, 8.8.8.8",
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT",
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT",
        "",
        "# 上面这些行在工具改写配置时会原样保留",
    ]
    for i, (name, note, created, allowed) in enumerate(_PEERS):
        lines += [
            "",
            f"# WGM_NAME: {name}",
            f"# WGM_NOTE: {note}",
            f"# WGM_CREATED: {created}",
            "[Peer]",
            f"PublicKey = {_demo_key('peer-' + name)}",
            f"AllowedIPs = {allowed}",
        ]
    return "\n".join(lines) + "\n"


class DemoBackend(Backend):
    """本机模拟一台 WireGuard 服务器，用于无服务器时试用 / 自动化测试。

    实现了一个极小的命令解释器，只覆盖本工具会用到的命令；配置文件存放在内存里，
    每次启动演示模式都会重置，不会碰本机任何真实文件。
    """

    label = "演示服务器（本机模拟）"
    host = "203.0.113.10"

    def __init__(self, log: LogFn = lambda _m: None):
        self.log = log
        self.fs: dict[str, str] = {
            "/etc/wireguard/wg0.conf": _demo_conf(),
        }
        self.runtime: dict[str, dict] = {}
        self._sync_runtime_from_conf(initial=True)
        self.broken_reload = False  # 测试回滚用

    # ------------------------------------------------------------------ 内部
    def _sync_runtime_from_conf(self, initial: bool = False) -> None:
        conf = WGConfig(self.fs.get("/etc/wireguard/wg0.conf", ""))
        now = time.time()
        kept = {}
        for i, peer in enumerate(conf.peers()):
            old = self.runtime.get(peer.public_key, {})
            is_new = not old
            kept[peer.public_key] = {
                "handshake": 0 if is_new else old.get("handshake", 0),
                "rx": 0 if is_new else old.get("rx", 0),
                "tx": 0 if is_new else old.get("tx", 0),
                "endpoint": "(none)" if is_new else old.get("endpoint", "(none)"),
            }
            if initial and i == 0:
                kept[peer.public_key] = {
                    "handshake": now - 32, "rx": 1824523, "tx": 431209,
                    "endpoint": "112.65.44.21:51820",
                }
            elif initial and i == 1:
                kept[peer.public_key] = {
                    "handshake": now - 86400 * 3, "rx": 98211, "tx": 20114,
                    "endpoint": "223.104.3.9:41233",
                }
        self.runtime = kept

    def _strip(self) -> str:
        return stripped_for_syncconf(self.fs.get("/etc/wireguard/wg0.conf", ""))

    def run(self, cmd: str, root: bool = False, stdin: str | None = None,
            timeout: int = 25) -> CmdResult:
        self.log("$ " + redact(cmd))
        stripped = cmd.strip()
        # sh -c '... && ...'：先剥掉外层，否则会因引号里的 && 被错误切分
        wrapped = re.match(r"^(?:sh|bash)\s+-c\s+(['\"])(.*)\1$", stripped, re.S)
        if wrapped:
            return self.run(wrapped.group(2), stdin=stdin)
        # 只处理本工具生成的命令形式：用 && 串起来、无复杂引号嵌套
        parts = [p.strip() for p in re.split(r"\s*&&\s*", stripped) if p.strip()]
        result = CmdResult("", "", 0, cmd)
        for index, part in enumerate(parts):
            if part in {"true", ":"}:
                continue
            # shell 里同一条链上的命令共享 stdin，这里也原样传下去，
            # 真正需要它的只有 `cat > 文件` 和 `wg pubkey`
            result = self._one(part, stdin)
            if not result.ok:
                return result
        return result

    def _one(self, raw: str, stdin: str | None) -> CmdResult:
        c = raw.strip()
        c = re.sub(r"^sudo\s+-n\s+", "", c)
        c = re.sub(r"^sudo\s+-S\s+-p\s+''\s+", "", c)
        c = c.replace("2>/dev/null", "").replace("|| true", "").strip()
        c = re.sub(r"\s+", " ", c)

        # 输出重定向（wg-quick strip wg0 > /tmp/xxx）
        redirect = None
        m = re.match(r"^(.*?)\s+>\s+(\S+)\s*$", c)
        if m and not re.match(r"^cat\s*>", c):
            c, redirect = m.group(1).strip(), m.group(2)

        def ok(out: str = "", err: str = "", code: int = 0) -> CmdResult:
            if redirect is not None:
                self.fs[redirect] = out
            return CmdResult(out, err, code, raw)

        # ---- 文件操作
        if re.match(r"^cat\s*>\s*\S+", c):
            path = re.sub(r"^cat\s*>\s*", "", c).strip()
            self.fs[path] = stdin if stdin is not None else ""
            return ok()
        if c.startswith("cat "):
            path = c[4:].strip()
            if path in self.fs:
                return ok(self.fs[path])
            return ok("", f"cat: {path}: No such file or directory", 1)
        if c.startswith("cp ") or c.startswith("mv "):
            parts = c.split()
            src, dst = parts[-2], parts[-1]
            if src not in self.fs:
                return ok("", f"{parts[0]}: {src}: No such file or directory", 1)
            self.fs[dst] = self.fs[src]
            if parts[0] == "mv":
                del self.fs[src]
            return ok()
        if c.startswith("rm "):
            for path in c.split()[1:]:
                self.fs.pop(path, None)
            return ok()
        if c.startswith(("chmod ", "chown ", "install ", "mkdir ", "umask ")):
            return ok()

        # ---- 环境探测
        if c.startswith("id -u"):
            return ok("0\n")
        if c.startswith("command -v "):
            tool = c.split()[-1]
            mapping = {"wg": "/usr/bin/wg", "wg-quick": "/usr/bin/wg-quick",
                       "bash": "/usr/bin/bash", "systemctl": "/usr/bin/systemctl"}
            if tool in mapping:
                return ok(mapping[tool] + "\n")
            return ok("", "", 1)
        if c.startswith("ls "):
            if "*.conf" in c or "/etc/wireguard" in c:
                return ok("\n".join(sorted(p for p in self.fs if p.startswith("/etc/wireguard/") and p.endswith(".conf"))) + "\n")
            return ok("")
        if c.startswith("docker "):
            return ok("")
        if c.startswith("systemctl "):
            return ok("active\n")
        if c.startswith("test ") or c.startswith("["):
            return ok("", "", 1)

        # ---- wg 命令
        if c == "wg genkey":
            return ok(local_keypair()[0] + "\n")
        if c == "wg genpsk":
            return ok(local_psk() + "\n")
        if c == "wg pubkey":
            # 密码提权时 stdin 第一行是 sudo 密码，最后一行才是私钥
            lines = [x for x in (stdin or "").splitlines() if x.strip()]
            priv = lines[-1] if lines else ""
            try:
                return ok(pub_from_priv(priv) + "\n")
            except Exception as exc:
                return ok("", str(exc), 1)
        if re.match(r"^wg show interfaces", c):
            return ok("wg0\n")
        if re.match(r"^wg show \S+ listen-port", c):
            return ok("51820\n")
        if re.match(r"^wg show \S+ public-key", c):
            return ok(pub_from_priv(_SERVER_PRIV) + "\n")
        if re.match(r"^wg show \S+ peers", c):
            return ok("".join(k + "\n" for k in self.runtime))
        if re.match(r"^wg show \S+ latest-handshakes", c):
            return ok("".join(f"{k}\t{v['handshake']}\n" for k, v in self.runtime.items()))
        if re.match(r"^wg show \S+ transfer", c):
            return ok("".join(f"{k}\t{v['rx']}\t{v['tx']}\n" for k, v in self.runtime.items()))
        if re.match(r"^wg show \S+ endpoints", c):
            return ok("".join(f"{k}\t{v['endpoint']}\n" for k, v in self.runtime.items()))
        if c.startswith("wg-quick strip"):
            return ok(self._strip())
        if c.startswith("wg syncconf"):
            if self.broken_reload:
                return ok("", "wg syncconf: simulated failure", 1)
            self._sync_runtime_from_conf()
            return ok()
        if c.startswith("wg setconf"):
            self._sync_runtime_from_conf()
            return ok()

        if c.startswith("bash -c ") or c.startswith("sh -c "):
            inner = c.split(" -c ", 1)[1].strip()
            if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in "'\"":
                inner = inner[1:-1]
            return self.run(inner, stdin=stdin)

        self.log(f"[演示] 未模拟的命令，按成功处理：{c}")
        return ok()


def make_backend(conn: dict, *, log: LogFn = lambda _m: None) -> Backend:
    """根据连接参数构造后端，并返回一个占位探测结果用的探测入口。"""
    if conn.get("demo"):
        backend = DemoBackend(log=log)
    else:
        backend = SSHBackend(
            host=conn["host"],
            port=int(conn.get("port", 22)),
            username=conn.get("username", "root"),
            password=conn.get("password", ""),
            key_path=conn.get("key_path", ""),
            key_passphrase=conn.get("key_passphrase", ""),
            sudo_password=conn.get("sudo_password", ""),
            known_hosts_path=conn.get("known_hosts_path", ""),
            log=log,
        )
        backend.connect()
    return backend
