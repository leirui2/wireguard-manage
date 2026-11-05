"""部署方式自动探测。

连接后依次检查：
  1. wireguard-tools (wg / wg-quick) 是否安装
  2. /etc/wireguard/*.conf 里有哪些配置、wg show interfaces 有哪些活动接口
  3. 若宿主机没有配置文件，再检查是不是跑在 Docker 容器里（wg-easy 等），
     是则切换到 docker exec 通道重新探测
  4. 从配置里读出服务端私钥 -> 推导公钥、监听端口、VPN 网段、DNS、SaveConfig 风险

任何一步失败都带诊断信息返回，不会闷头改服务器配置。
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

from .backend import Backend, DockerBackend, SSHBackend
from .config import WGConfig
from .util import pub_from_priv


class ProbeError(RuntimeError):
    pass


def _is_private_host(host: str) -> bool:
    try:
        return ipaddress.ip_address((host or "").strip()).is_private
    except ValueError:
        return False


def _detect_public_ip(target: Backend) -> str:
    """内网地址连上去时，问服务器要一下出口公网 IP，供客户端 Endpoint 使用。"""
    for cmd in ("curl -s --max-time 4 ifconfig.me",
                "curl -s --max-time 4 https://api.ipify.org"):
        res = target.run(cmd, timeout=10)
        candidate = (res.out or "").strip().splitlines()
        candidate = candidate[0].strip() if candidate else ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", candidate) and not _is_private_host(candidate):
            return candidate
    return ""


@dataclass
class Deployment:
    kind: str = "native"                 # native | docker
    iface: str = "wg0"
    conf_path: str = "/etc/wireguard/wg0.conf"
    conf_text: str = ""
    server_public_key: str = ""
    listen_port: int = 51820
    addresses: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    endpoint_host: str = ""
    interface_up: bool = False
    save_config: bool = False
    container: str = ""
    has_wg_quick: bool = False
    notes: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        kind = "Docker 容器" if self.kind == "docker" else "标准 wg-quick"
        return (
            f"{kind} | 接口 {self.iface} | 配置 {self.conf_path} | "
            f"监听 {self.listen_port} | 网段 {', '.join(self.addresses) or '未识别'} | "
            f"服务端公钥 {self.server_public_key[:12]}…"
        )


def _q(text: str) -> str:
    return shlex.quote(str(text))


def _collect(backend: Backend, log) -> dict:
    info: dict = {}
    # command 是 shell 内建命令，不能套 sudo，这里也不需要 root
    info["wg"] = backend.run("command -v wg").out.strip()
    info["wg_quick"] = backend.run("command -v wg-quick").out.strip()
    info["ifaces"] = backend.run("wg show interfaces", root=True).out.split()
    # 不要把 stderr 丢掉：目录权限不足和「目录为空」必须能区分开
    ls = backend.run("sh -c 'ls -1 /etc/wireguard/*.conf 2>&1'", root=True)
    info["conf_scan_raw"] = (ls.out + "\n" + ls.err).strip()
    info["conf_files"] = [
        line.strip() for line in ls.out.splitlines() if line.strip().endswith(".conf")
    ]
    dir_ls = backend.run("ls -ld /etc/wireguard 2>&1", root=True)
    info["conf_dir_raw"] = (dir_ls.out + "\n" + dir_ls.err).strip()
    info["sudo_mode"] = getattr(backend, "sudo_mode", "root")
    docker = backend.run("docker ps --format '{{.Names}} {{.Image}}'", root=True)
    containers = []
    for line in docker.out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and (
            "wg-easy" in parts[1].lower()
            or "wireguard" in parts[1].lower()
            or "wireguard" in parts[0].lower()
        ):
            containers.append((parts[0], parts[1]))
    info["containers"] = containers

    params = backend.run("cat /etc/wireguard/params", root=True)
    info["params"] = params.out if params.ok else ""
    info["docker_raw"] = (docker.out + "\n" + docker.err).strip()
    log(
        f"探测：wg={info['wg'] or '未找到'}，活动接口={info['ifaces'] or '无'}，"
        f"配置文件={info['conf_files'] or '无'}，容器={info['containers'] or '无'}"
    )
    return info


def _diagnose_no_conf(info: dict) -> str:
    """把「扫不到配置」拆成能看懂的几种原因，而不是笼统报没找到。"""
    raw = (info.get("conf_scan_raw") or "") + " " + (info.get("conf_dir_raw") or "")
    lowered = raw.lower()
    if info.get("sudo_mode") == "none":
        return (
            "当前 SSH 账号不是 root，服务器也没开免密 sudo，工具拿不到 root 权限，"
            "读不到 /etc/wireguard 目录（配置很可能就在那里）。\n"
            "解决办法：在连接区填写「sudo 密码」后再连；或改用 root 账号登录。"
        )
    if "permission denied" in lowered or "权限不够" in raw or "operation not permitted" in lowered:
        return (
            "读取 /etc/wireguard 被系统拒绝（权限不足），当前账号的 sudo 未生效。\n"
            "请确认「sudo 密码」是否正确，或改用 root 账号登录。"
        )
    if "no such file or directory" in lowered:
        return (
            "服务器上不存在 /etc/wireguard 目录，WireGuard 可能装在别的路径或 Docker 容器里。\n"
            "可以在「高级设置」里手动填写配置文件的绝对路径；"
            "如果是容器部署，请把容器名和容器内路径告我，我再适配。"
        )
    return (
        "没有找到 WireGuard 配置文件（已检查 /etc/wireguard/*.conf 和 Docker 容器）。\n"
        "可以在「高级设置」里手动填写配置文件的绝对路径，例如 /etc/wireguard/wg0.conf。"
    )


def probe(backend: Backend, conn: dict, log) -> tuple[Backend, Deployment]:
    """返回 (实际执行命令的后端, 探测结果)。Docker 场景下后端会被替换。"""
    target: Backend = backend
    info = _collect(target, log)
    dep = Deployment()
    dep.endpoint_host = conn.get("endpoint_host") or getattr(backend, "host", "") or ""
    if not conn.get("endpoint_host") and _is_private_host(dep.endpoint_host):
        public_ip = _detect_public_ip(target)
        if public_ip:
            dep.notes.append(
                f"SSH 用的是内网地址，已自动把客户端 Endpoint 改用服务器公网 IP {public_ip}"
                f"（{dep.endpoint_host} 只能在局域网内用）。"
            )
            dep.endpoint_host = public_ip

    # 宿主机没有 wg0.conf，但发现了 WireGuard 容器 -> 切到容器内探测
    if not info["conf_files"] and info["containers"] and isinstance(backend, SSHBackend):
        container, image = info["containers"][0]
        log(f"宿主机没有配置文件，检测到容器 {container} ({image})，切换到容器内探测")
        need_sudo = not backend.is_root
        docker_backend = DockerBackend(backend, container, need_sudo=need_sudo, log=log)
        docker_info = _collect(docker_backend, log)
        if docker_info["conf_files"]:
            target = docker_backend
            info = docker_info
            dep.kind = "docker"
            dep.container = container
            dep.notes.append(
                f"检测到 WireGuard 运行在 Docker 容器 {container} 中。"
                "注意：wg-easy 新版可能用数据库管理客户端，直接改文件可能不生效，"
                "请先在测试环境确认，或改用「手动指定配置路径」。"
            )

    if not info["wg"]:
        dep.notes.append("未在服务器上找到 wg 命令：密钥生成将改用本机算法，热加载可能不可用。")
    dep.has_wg_quick = bool(info["wg_quick"])
    if not dep.has_wg_quick:
        dep.notes.append("未找到 wg-quick：热加载会退回重启 wg-quick 服务（会短暂断开所有连接）。")

    if not info["conf_files"]:
        raise ProbeError(_diagnose_no_conf(info))

    manual_conf = (conn.get("conf_path") or "").strip()
    if manual_conf:
        conf_path = manual_conf
    else:
        preferred = [
            p for p in info["conf_files"]
            if p.endswith(f"/{(conn.get('iface') or '').strip()}.conf")
        ]
        if not preferred and info["ifaces"]:
            preferred = [p for p in info["conf_files"] if p.endswith(f"/{info['ifaces'][0]}.conf")]
        conf_path = preferred[0] if preferred else info["conf_files"][0]

    cat = target.run("cat " + _q(conf_path), root=True)
    if not cat.ok or not cat.out.strip():
        reason = (cat.err or "").strip() or "文件为空"
        if getattr(target, "sudo_mode", "") == "none":
            reason += "\n（当前账号没有 root 权限，请在连接区填写「sudo 密码」或改用 root 登录）"
        raise ProbeError(f"读取 {conf_path} 失败：{reason}")

    dep.conf_path = conf_path
    dep.conf_text = cat.out
    iface = (conn.get("iface") or "").strip()
    if not iface:
        iface = conf_path.rsplit("/", 1)[-1].replace(".conf", "")
    dep.iface = iface
    dep.interface_up = iface in info["ifaces"]

    conf = WGConfig(dep.conf_text)
    itf = conf.interface()
    dep.addresses = [a.strip() for a in (itf.get("address") or "").split(",") if a.strip()]
    dep.save_config = (itf.get("save_config") or "").strip().lower() in {"true", "1", "yes"}
    if dep.save_config:
        dep.notes.append(
            "警告：[Interface] 里 SaveConfig = true。wg-quick 停止服务时会按运行时状态"
            "重写配置文件，可能覆盖本工具写入的备注注释；建议改为 false。"
        )

    try:
        dep.listen_port = int(itf.get("listen_port") or 0)
    except ValueError:
        dep.listen_port = 0
    if not dep.listen_port:
        port_res = target.run(f"wg show {_q(iface)} listen-port", root=True)
        try:
            dep.listen_port = int(port_res.out.strip())
        except ValueError:
            dep.listen_port = 51820

    # 服务端公钥：优先用配置里的私钥本地推导（接口没起来也能用）
    private_key = itf.get("private_key") or ""
    if not private_key and itf.get("private_key_file"):
        key_file = target.run("cat " + _q(itf["private_key_file"]), root=True)
        private_key = key_file.out.strip().splitlines()[0] if key_file.ok and key_file.out.strip() else ""
    if private_key:
        try:
            dep.server_public_key = pub_from_priv(private_key)
        except Exception:
            dep.server_public_key = ""
    if not dep.server_public_key:
        pub_res = target.run(f"wg show {_q(iface)} public-key", root=True)
        dep.server_public_key = pub_res.out.strip()
    if not dep.server_public_key:
        dep.notes.append("无法确定服务端公钥，生成的客户端配置需要你手工补上 [Peer] PublicKey。")

    dns = [d.strip() for d in (itf.get("dns") or "").split(",") if d.strip()]
    if not dns and info["params"]:
        for line in info["params"].splitlines():
            if line.startswith("CLIENT_DNS="):
                dns = [d.strip() for d in line.split("=", 1)[1].strip('"\' ').split(",") if d.strip()]
                break
    dep.dns = dns or ["1.1.1.1", "8.8.8.8"]

    if info["params"]:
        dep.notes.append("检测到一键安装脚本留下的 /etc/wireguard/params，配置格式与标准 wg-quick 兼容。")
    if not dep.interface_up:
        dep.notes.append(
            f"接口 {iface} 当前未启动：配置仍可读写，但无法热加载，重启 wg-quick@{iface} 后生效。"
        )
    if not dep.addresses:
        dep.notes.append("[Interface] 里没读到 Address 网段，新增密钥时需要手动指定 VPN 地址。")

    dep.diagnostics = [
        f"wg: {info['wg'] or '未安装'}",
        f"wg-quick: {info['wg_quick'] or '未安装'}",
        f"活动接口: {', '.join(info['ifaces']) or '无'}",
        f"配置文件: {', '.join(info['conf_files'])}",
        f"容器: {', '.join(c[0] for c in info['containers']) or '无'}",
    ]
    return target, dep
