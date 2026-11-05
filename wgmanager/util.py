"""通用工具：WireGuard 密钥生成、VPN 地址分配、格式化。

密钥优先在服务器上用 `wg genkey` / `wg pubkey` 生成（保证与服务端实现完全一致）；
服务器没有 wg 命令时，退回本机使用 Curve25519/X25519 生成，算法与 WireGuard 一致。
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import os
import re
import time
from typing import Iterable


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def is_wg_key(value: str) -> bool:
    """WireGuard 密钥是 32 字节的 base64，长度固定 44 且以 = 结尾。"""
    value = (value or "").strip()
    if len(value) != 44 or not value.endswith("="):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except Exception:
        return False


def pub_from_priv(priv_b64: str) -> str:
    """由 base64 私钥推导公钥（X25519，与 wg pubkey 等价）。"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    raw = base64.b64decode(priv_b64, validate=True)
    key = X25519PrivateKey.from_private_bytes(raw)
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64(pub)


def local_keypair() -> tuple[str, str]:
    """本机生成一个 WireGuard 密钥对，私钥按 Curve25519 规范做位钳制。"""
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    priv = b64(bytes(raw))
    return priv, pub_from_priv(priv)


def local_psk() -> str:
    return b64(os.urandom(32))


def gen_keypair(target, log=lambda _msg: None) -> tuple[str, str]:
    res = target.run("wg genkey", timeout=15)
    if res.ok and is_wg_key(res.out.strip()):
        priv = res.out.strip()
        pub_res = target.run("wg pubkey", stdin=priv + "\n", timeout=15)
        if pub_res.ok and is_wg_key(pub_res.out.strip()):
            return priv, pub_res.out.strip()
    log("服务器上 wg genkey/pubkey 不可用，已改用本机 Curve25519 生成密钥对")
    return local_keypair()


def gen_psk(target) -> str:
    res = target.run("wg genpsk", timeout=15)
    if res.ok and is_wg_key(res.out.strip()):
        return res.out.strip()
    return local_psk()


def derive_server_pubkey(target, private_key: str) -> str:
    """服务端公钥：优先从运行中的接口取，取不到就用配置里的私钥推导。

    注意：私钥只通过 stdin 传给 wg pubkey，绝不出现在命令行或日志里。
    """
    return pub_from_priv(private_key)


def allocate_addresses(iface_addresses: Iterable[str], used_allowed_ips: Iterable[str]) -> list[str]:
    """根据 [Interface] Address 网段和现有 Peer 的 AllowedIPs，挑一组未占用的地址。

    同时支持 IPv4 / IPv6，返回形如 ['10.8.0.5/32', 'fd08::5/128'] 的列表。
    """
    networks: list[ipaddress._BaseNetwork] = []
    used: set[object] = set()
    for group in iface_addresses:
        for token in str(group or "").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                itf = ipaddress.ip_interface(token)
            except ValueError:
                continue
            networks.append(itf.network)
            used.add(itf.ip)          # 服务端自己占用的地址
            used.add(itf.network.network_address)
    for group in used_allowed_ips:
        for token in str(group or "").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                used.add(ipaddress.ip_network(token, strict=False).network_address)
            except ValueError:
                continue

    result: list[str] = []
    for net in networks:
        base = int(net.network_address)
        # IPv6 /64 是天文数字，最多向后探 65536 个地址就够用了
        limit = min(int(net.num_addresses) - 1, 65536)
        for offset in range(1, limit):
            candidate = ipaddress.ip_address(base + offset)
            if candidate in used:
                continue
            used.add(candidate)
            result.append(f"{candidate}/{net.max_prefixlen}")
            break
    if not result:
        raise ValueError(
            "无法自动分配 VPN 地址：请检查 [Interface] Address 是否为合法网段，"
            "以及网段内是否还有空闲地址。"
        )
    return result


def short_key(key: str, n: int = 10) -> str:
    key = key or ""
    return key[:n] + ("…" if len(key) > n else "")


def human_bytes(value) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_handshake(ts, now: float | None = None) -> tuple[str, bool]:
    """返回 (可读文本, 是否视为在线)。WireGuard 活跃时约每 2 分钟握手一次。"""
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return "从未", False
    if ts <= 0:
        return "从未", False
    now = time.time() if now is None else now
    delta = now - ts
    if delta < 0:
        return "刚刚", True
    if delta < 60:
        text = f"{int(delta)} 秒前"
    elif delta < 3600:
        text = f"{int(delta // 60)} 分钟前"
    elif delta < 86400:
        text = f"{int(delta // 3600)} 小时前"
    else:
        text = dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    return text, delta <= 300


def stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def safe_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|\r\n\t]', "_", (name or "").strip())
    name = name.strip(" .")
    return name or "client"


def redact(text: str) -> str:
    """日志脱敏：即便误把密钥拼进命令，也不会写进日志。"""
    return re.sub(
        r"(PrivateKey|PresharedKey|PrivateKeyFile|password|passphrase)\s*[=:]\s*\S+",
        lambda m: f"{m.group(1)}=***",
        text or "",
        flags=re.IGNORECASE,
    )
