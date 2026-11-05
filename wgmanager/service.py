"""业务逻辑：查看 / 新增 / 修改 / 删除密钥。

写配置的固定流程（每一步都可回退）：
    备份 wg0.conf -> 写临时文件 -> 原子替换 -> wg syncconf 热加载 -> 校验生效
任何一步失败都自动恢复备份，绝不把服务器留在半改状态。
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import secrets
import shlex
import time
from dataclasses import dataclass, field

from .backend import Backend
from .config import WGConfig
from .probe import Deployment
from .util import (
    allocate_addresses,
    gen_keypair,
    gen_psk,
    host_addresses,
    human_bytes,
    human_handshake,
    normalize_allowed_ips,
    split_networks,
    stamp,
)


def _q(text: str) -> str:
    return shlex.quote(str(text))


def _root_chain(chain: str) -> str:
    """把整串命令包进 sh -c，确保 sudo 作用于 && 后面的每一条命令。

    否则 `sudo cmd1 && cmd2` 里的 cmd2 会以普通用户身份执行而失败。
    """
    return "sh -c " + shlex.quote(chain)


def _table(out: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in out.splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) >= 2:
            rows[parts[0]] = parts[1:]
    return rows


@dataclass
class PeerView:
    pubkey: str = ""
    name: str = ""
    raw_name: str = ""
    note: str = ""
    created: str = ""
    allowed_ips: str = ""
    address: str = ""
    handshake: str = "从未"
    traffic: str = "-"
    endpoint: str = "-"
    online: bool = False
    has_psk: bool = False


@dataclass
class AddResult:
    name: str
    public_key: str
    private_key: str
    addresses: list[str]
    client_conf: str
    backup: str
    reload_msg: str


@dataclass
class ApplyResult:
    backup: str = ""
    reload_msg: str = ""
    runtime_verified: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class UpdateResult:
    name: str = ""
    public_key: str = ""
    changed: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    old_allowed_ips: str = ""
    new_allowed_ips: str = ""
    backup: str = ""
    reload_msg: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def address_changed(self) -> bool:
        return "VPN 地址" in self.changed


def build_client_conf(
    *,
    private_key: str,
    addresses: list[str],
    dns: list[str],
    server_public_key: str,
    preshared_key: str = "",
    allowed_ips: str,
    endpoint: str,
    keepalive: int = 25,
    comment: str = "",
) -> str:
    lines = []
    if comment:
        lines.append(f"# {comment}")
    lines += [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {', '.join(addresses)}",
    ]
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    lines += ["", "[Peer]", f"PublicKey = {server_public_key}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines += [f"AllowedIPs = {allowed_ips}", f"Endpoint = {endpoint}"]
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


class WGService:
    def __init__(self, target: Backend, dep: Deployment, log=lambda _m: None):
        self.target = target
        self.dep = dep
        self.log = log

    # ------------------------------------------------------------------ 查看
    def refresh_conf(self) -> WGConfig:
        res = self.target.run("cat " + _q(self.dep.conf_path), root=True)
        if not res.ok or not res.out.strip():
            raise RuntimeError(
                f"重新读取 {self.dep.conf_path} 失败：{res.err.strip() or '空文件'}"
            )
        self.dep.conf_text = res.out
        return WGConfig(res.out)

    def runtime(self) -> tuple[dict, dict, dict]:
        if not self.dep.interface_up:
            return {}, {}, {}
        base = f"wg show {_q(self.dep.iface)}"
        handshakes = _table(self.target.run(base + " latest-handshakes", root=True).out)
        transfers = _table(self.target.run(base + " transfer", root=True).out)
        endpoints = _table(self.target.run(base + " endpoints", root=True).out)
        return handshakes, transfers, endpoints

    def list_peers(self) -> list[PeerView]:
        conf = self.refresh_conf()
        handshakes, transfers, endpoints = self.runtime()
        now = time.time()
        views = []
        for peer in conf.peers():
            hs = handshakes.get(peer.public_key, ["0"])
            tr = transfers.get(peer.public_key, [])
            ep = endpoints.get(peer.public_key, [])
            htext, online = human_handshake(hs[0] if hs else 0, now)
            traffic = (
                f"↓{human_bytes(tr[0])} / ↑{human_bytes(tr[1])}"
                if len(tr) >= 2
                else "-"
            )
            views.append(
                PeerView(
                    pubkey=peer.public_key,
                    name=peer.display_name,
                    raw_name=peer.raw_name,
                    note=peer.note,
                    created=peer.created,
                    allowed_ips=peer.allowed_ips,
                    address=peer.addresses,
                    handshake=htext,
                    traffic=traffic,
                    endpoint=(ep[0] if ep and ep[0] != "(none)" else "-"),
                    online=online,
                    has_psk=bool(peer.preshared_key),
                )
            )
        return views

    # ------------------------------------------------------------------ 新增
    def add_peer(
        self,
        *,
        name: str,
        note: str = "",
        client_allowed_ips: str = "0.0.0.0/0, ::/0",
        dns: list[str] | None = None,
        endpoint: str | None = None,
        use_psk: bool | None = None,
        vpn_addresses: str = "",
    ) -> AddResult:
        name = (name or "").strip()
        if not name:
            raise ValueError("请填写密钥名称")
        conf = self.refresh_conf()
        existing = conf.peers()
        if any(p.raw_name == name for p in existing):
            raise ValueError(f"已存在同名密钥「{name}」，请换一个名称")

        if use_psk is None:
            use_psk = any(bool(p.preshared_key) for p in existing)

        priv, pub = gen_keypair(self.target, self.log)
        psk = gen_psk(self.target) if use_psk else ""
        if vpn_addresses.strip():
            addresses = [a.strip() for a in vpn_addresses.split(",") if a.strip()]
        else:
            addresses = allocate_addresses(
                self.dep.addresses, [p.allowed_ips for p in existing]
            )
        created = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        conf.add_peer(
            public_key=pub,
            allowed_ips=", ".join(addresses),
            preshared_key=psk,
            name=name,
            note=note,
            created=created,
        )

        default_endpoint = f"{self.dep.endpoint_host}:{self.dep.listen_port}"
        client_conf = build_client_conf(
            private_key=priv,
            addresses=addresses,
            dns=dns if dns is not None else self.dep.dns,
            server_public_key=self.dep.server_public_key,
            preshared_key=psk,
            allowed_ips=client_allowed_ips,
            endpoint=(endpoint or "").strip() or default_endpoint,
            comment=f"由 WireGuard 密钥管理工具生成 | {name} | {created}",
        )

        applied = self._apply(conf.render(), expect_present={pub}, expect_absent=set())
        self.log(f"已新增密钥「{name}」，VPN 地址 {', '.join(addresses)}")
        return AddResult(
            name=name,
            public_key=pub,
            private_key=priv,
            addresses=addresses,
            client_conf=client_conf,
            backup=applied.backup,
            reload_msg=applied.reload_msg,
        )

    # ------------------------------------------------------------------ 修改
    def update_peer(
        self,
        pubkey: str,
        *,
        name: str | None = None,
        note: str | None = None,
        allowed_ips: str | None = None,
    ) -> UpdateResult:
        """修改已有密钥的名称 / 备注 / VPN 地址。

        传 None 表示该项不动。改名称和备注只动注释，对运行中的隧道没有任何影响；
        改 VPN 地址会变更服务端分配，客户端必须同步改 Address 后才能重连。
        """
        conf = self.refresh_conf()
        peers = conf.peers()
        peer = next((p for p in peers if p.public_key == pubkey), None)
        if peer is None:
            raise ValueError("该密钥在服务器上已不存在，请刷新后重试")

        changed: list[str] = []
        warnings: list[str] = []

        new_name = None
        if name is not None:
            new_name = (name or "").strip()
            if not new_name:
                raise ValueError("密钥名称不能为空")
            if new_name != (peer.raw_name or ""):
                if any(p.public_key != pubkey and p.raw_name == new_name for p in peers):
                    raise ValueError(f"已存在同名密钥「{new_name}」，请换一个名称")
                changed.append("名称")

        new_note = None
        if note is not None:
            new_note = (note or "").strip()
            if new_note != (peer.note or ""):
                changed.append("备注")

        new_allowed = None
        if allowed_ips is not None:
            new_allowed = normalize_allowed_ips(allowed_ips)
            if new_allowed != peer.allowed_ips:
                self._check_address_available(peers, pubkey, new_allowed)
                changed.append("VPN 地址")

        final_name = new_name if new_name is not None else (peer.raw_name or "")
        result = UpdateResult(
            name=final_name or f"未命名 ({pubkey[:8]})",
            public_key=pubkey,
            changed=list(changed),
            old_allowed_ips=peer.allowed_ips,
            new_allowed_ips=new_allowed if new_allowed is not None else peer.allowed_ips,
        )
        result.addresses = host_addresses(result.new_allowed_ips)

        if not changed:
            self.log(f"「{result.name}」没有需要修改的内容")
            return result

        if "VPN 地址" in changed:
            if not self._in_vpn_subnet(result.new_allowed_ips):
                warnings.append(
                    f"新地址不在 VPN 网段（{', '.join(self.dep.addresses) or '未识别'}）内，"
                    "客户端很可能连不通"
                )
            warnings.append(
                "该客户端会立即断线，需要在它的配置里把 Address 改成 "
                + (", ".join(result.addresses) or result.new_allowed_ips)
                + " 后重新连接"
            )

        conf.update_peer(peer, name=new_name, note=new_note, allowed_ips=new_allowed)
        applied = self._apply(conf.render(), expect_present={pubkey}, expect_absent=set())
        result.backup = applied.backup
        result.reload_msg = applied.reload_msg
        result.warnings = warnings + list(applied.warnings)
        self.log(f"已修改「{result.name}」：{'、'.join(changed)}")
        return result

    def _check_address_available(self, peers, pubkey: str, allowed_ips: str) -> None:
        """同一地址不能分给两个 peer，也不能占用服务器自己的地址。"""
        owner: dict[str, str] = {}
        for other in peers:
            if other.public_key == pubkey:
                continue
            for net in split_networks(other.allowed_ips):
                owner[net] = other.display_name
        server: set[str] = set()
        for group in self.dep.addresses:
            for token in str(group).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    server.add(str(ipaddress.ip_interface(token).ip))
                except ValueError:
                    continue
        for net in split_networks(allowed_ips):
            if net in owner:
                raise ValueError(f"地址 {net} 已被「{owner[net]}」占用，请换一个")
            host = net.split("/")[0]
            if host in server:
                raise ValueError(f"{host} 是服务器自己的地址，不能分配给客户端")

    def _in_vpn_subnet(self, allowed_ips: str) -> bool:
        nets = []
        for group in self.dep.addresses:
            for token in str(group).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    nets.append(ipaddress.ip_interface(token).network)
                except ValueError:
                    continue
        if not nets:
            return True  # 探测不到网段就别拦，交给用户自己判断
        for net in split_networks(allowed_ips):
            try:
                candidate = ipaddress.ip_network(net, strict=False).network_address
            except ValueError:
                continue
            for n in nets:
                if n.version == candidate.version and candidate in n:
                    return True
        return False

    # ------------------------------------------------------------------ 删除
    def remove_peers(self, pubkeys: set[str]) -> list[str]:
        if not pubkeys:
            raise ValueError("没有选中要删除的密钥")
        conf = self.refresh_conf()
        matched = [p for p in conf.peers() if p.public_key in pubkeys]
        if not matched:
            raise ValueError("选中的密钥在服务器上已不存在，请刷新后重试")
        names = [p.display_name for p in matched]
        for peer in sorted(matched, key=lambda p: p.block_start, reverse=True):
            conf.remove_peer(peer)
        self._apply(
            conf.render(),
            expect_present=set(),
            expect_absent={p.public_key for p in matched},
        )
        self.log(f"已删除 {len(matched)} 个密钥：{', '.join(names)}")
        return names

    # -------------------------------------------------------------- 写入 / 回滚
    def _reload(self) -> tuple[bool, str]:
        """返回 (是否成功, 说明)。优先 wg syncconf，不中断现有连接。"""
        if not self.dep.interface_up:
            return False, f"接口 {self.dep.iface} 未启动：配置已写入，重启服务后才生效"
        token = secrets.token_hex(4)
        stripped = f"/tmp/.wgmgr_strip_{token}.conf"
        if self.dep.has_wg_quick:
            chain = (
                "umask 077 && "
                f"wg-quick strip {_q(self.dep.iface)} > {_q(stripped)} && "
                f"wg syncconf {_q(self.dep.iface)} {_q(stripped)} && "
                f"rm -f {_q(stripped)}"
            )
            res = self.target.run(_root_chain(chain), root=True)
            if res.ok:
                return True, "已通过 wg syncconf 热加载，现有连接不中断"
            self.log(f"wg syncconf 热加载失败：{res.err.strip()}，尝试重启服务")
        restart = self.target.run(f"systemctl restart wg-quick@{_q(self.dep.iface)}", root=True)
        if restart.ok:
            return True, "已重启 wg-quick 服务（连接会短暂断开）"
        return False, (
            f"热加载和重启服务都失败了：{restart.err.strip() or '未知原因'}。"
            "配置文件已正确写入，请在服务器上手工执行 systemctl restart wg-quick@"
            + self.dep.iface
        )

    def _rollback(self, backup: str) -> None:
        res = self.target.run(f"cp -p {_q(backup)} {_q(self.dep.conf_path)}", root=True)
        if res.ok:
            self._reload()
            self.log(f"已自动回滚到备份 {backup}")
        else:
            self.log(f"!! 回滚失败，请立即手工恢复：cp -p {backup} {self.dep.conf_path}")

    def _apply(
        self, new_text: str, *, expect_present: set[str], expect_absent: set[str]
    ) -> ApplyResult:
        conf_path = self.dep.conf_path
        backup = f"{conf_path}.wgmgr.bak.{stamp()}"

        bk = self.target.run(f"cp -p {_q(conf_path)} {_q(backup)}", root=True)
        if not bk.ok:
            raise RuntimeError(
                f"备份 {conf_path} 失败，为安全起见已终止写入：{bk.err.strip()}"
            )
        self.log(f"已备份到 {backup}")

        token = secrets.token_hex(6)
        tmp = f"/tmp/.wgmgr_{token}.conf"
        staged = f"{conf_path}.wgmgr.tmp"
        try:
            write_tmp = self.target.run(
                f"umask 077 && cat > {_q(tmp)} && chmod 600 {_q(tmp)}",
                stdin=new_text,
                root=False,
            )
            if not write_tmp.ok:
                raise RuntimeError(f"写临时文件失败：{write_tmp.err.strip()}")

            replace = self.target.run(
                _root_chain(
                    "umask 077 && "
                    f"cp {_q(tmp)} {_q(staged)} && chmod 600 {_q(staged)} && "
                    f"mv -f {_q(staged)} {_q(conf_path)}"
                ),
                root=True,
            )
            if not replace.ok:
                raise RuntimeError(f"替换配置文件失败：{replace.err.strip()}")

            reloaded, reload_msg = self._reload()
            verify = self.target.run(f"wg show {_q(self.dep.iface)} peers", root=True)
            verified = False
            if reloaded and verify.ok:
                current = set(verify.out.split())
                missing = expect_present - current
                leftover = expect_absent & current
                if missing or leftover:
                    raise RuntimeError(
                        "热加载后校验不通过（"
                        + (f"未生效公钥 {len(missing)} 个；" if missing else "")
                        + (f"仍残留公钥 {len(leftover)} 个" if leftover else "")
                        + "）"
                    )
                verified = True
            else:
                # 接口没起来 / 热加载失败时，至少确认文件内容确实写进去了
                content = self.target.run("cat " + _q(conf_path), root=True)
                if not content.ok or content.out.replace("\r\n", "\n") != new_text:
                    raise RuntimeError("写入后回读配置文件内容不一致")

            self.dep.conf_text = new_text
            if not reloaded:
                self.log("注意：" + reload_msg)
            return ApplyResult(
                backup=backup,
                reload_msg=reload_msg,
                runtime_verified=verified,
                warnings=[] if reloaded else [reload_msg],
            )
        except Exception as exc:
            self.log(f"写入流程出错：{exc}")
            self._rollback(backup)
            raise
        finally:
            self.target.run(f"rm -f {_q(tmp)}", root=False)
