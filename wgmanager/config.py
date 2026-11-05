"""wg0.conf 保真解析与改写。

设计要点：
* 按「原始行」保存，未改动的行逐字保留（包括注释、空行、大小写、未知字段）。
* 新增的 Peer 用 `# WGM_NAME:` / `# WGM_NOTE:` / `# WGM_CREATED:` 三行注释携带备注，
  放在 [Peer] 段上方；读取时也兼容 `### Client xxx`、`# Name = xxx`、`# BEGIN_PEER xxx`
  等常见一键脚本的写法。
* 不改动 [Interface]，不重写整个文件，避免破坏 PostUp / PostDown / MTU 等设置。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

HEADER_RE = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*(?:[#;].*)?$")
KV_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$")
META_RE = re.compile(r"^#\s*WGM_(NAME|NOTE|CREATED)\s*:\s*(.*)$", re.IGNORECASE)
FOREIGN_NAME_RE = re.compile(
    r"^#{1,3}\s*(?:BEGIN_PEER|Client|Name|Peer)\s*[:=]?\s*(.+)$", re.IGNORECASE
)


@dataclass
class Peer:
    public_key: str = ""
    preshared_key: str = ""
    allowed_ips: str = ""
    endpoint: str = ""
    persistent_keepalive: str = ""
    name: str = ""
    note: str = ""
    created: str = ""
    raw_name: str = ""          # 元数据里确实写了名字
    block_start: int = -1       # 含上方备注注释
    header_index: int = -1
    block_end: int = -1         # 不含，下一个段头
    extra: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        if self.raw_name:
            return self.raw_name
        return f"未命名 ({self.public_key[:8]})" if self.public_key else "未命名"

    @property
    def addresses(self) -> str:
        """从 AllowedIPs 里挑出主机地址，作为「VPN 地址」展示。"""
        parts = []
        for token in (self.allowed_ips or "").split(","):
            token = token.strip()
            if token.endswith("/32") or token.endswith("/128"):
                parts.append(token.split("/")[0])
        return ", ".join(parts) if parts else (self.allowed_ips or "-")


class WGConfig:
    def __init__(self, text: str):
        self.lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")

    def render(self) -> str:
        return "\n".join(self.lines)

    def sections(self) -> list[tuple[int, str, int]]:
        """[(段头行号, 段名, 下一段头行号或文件末尾)]"""
        headers = [
            (i, HEADER_RE.match(line).group(1).strip())
            for i, line in enumerate(self.lines)
            if HEADER_RE.match(line)
        ]
        return [
            (
                i,
                name,
                headers[k + 1][0] if k + 1 < len(headers) else len(self.lines),
            )
            for k, (i, name) in enumerate(headers)
        ]

    def get(self, start: int, end: int, key: str, default: str = "") -> str:
        for line in self.lines[start + 1 : end]:
            match = KV_RE.match(line)
            if match and match.group(1).lower() == key.lower():
                return match.group(2).strip()
        return default

    def interface(self) -> dict:
        for start, name, end in self.sections():
            if name.lower() == "interface":
                return {
                    "address": self.get(start, end, "Address"),
                    "listen_port": self.get(start, end, "ListenPort"),
                    "private_key": self.get(start, end, "PrivateKey"),
                    "private_key_file": self.get(start, end, "PrivateKeyFile"),
                    "dns": self.get(start, end, "DNS"),
                    "mtu": self.get(start, end, "MTU"),
                    "save_config": self.get(start, end, "SaveConfig"),
                    "post_up": self.get(start, end, "PostUp"),
                }
        return {}

    def _meta_start(self, header_index: int) -> int:
        i = header_index - 1
        while i >= 0:
            stripped = self.lines[i].strip()
            if stripped == "" or stripped.startswith("#") or stripped.startswith(";"):
                i -= 1
            else:
                break
        return i + 1

    @staticmethod
    def _parse_meta(comment_lines: list[str]) -> dict:
        meta = {"name": "", "note": "", "created": ""}
        for line in comment_lines:
            stripped = line.strip()
            m = META_RE.match(stripped)
            if m:
                meta[m.group(1).lower()] = m.group(2).strip()
                continue
            if not meta["name"] and not re.match(r"^#\s*END_PEER", stripped, re.I):
                m2 = FOREIGN_NAME_RE.match(stripped)
                if m2:
                    candidate = m2.group(1).strip().strip("=# ").strip()
                    if candidate:
                        meta["name"] = candidate
        return meta

    def peers(self) -> list[Peer]:
        result = []
        for start, name, end in self.sections():
            if name.lower() != "peer":
                continue
            block_start = self._meta_start(start)
            meta = self._parse_meta(self.lines[block_start:start])
            peer = Peer(
                public_key=self.get(start, end, "PublicKey"),
                preshared_key=self.get(start, end, "PresharedKey"),
                allowed_ips=self.get(start, end, "AllowedIPs"),
                endpoint=self.get(start, end, "Endpoint"),
                persistent_keepalive=self.get(start, end, "PersistentKeepalive"),
                name=meta["name"] or "",
                raw_name=meta["name"],
                note=meta["note"],
                created=meta["created"],
                block_start=block_start,
                header_index=start,
                block_end=end,
            )
            result.append(peer)
        return result

    def add_peer(
        self,
        *,
        public_key: str,
        allowed_ips: str,
        preshared_key: str = "",
        name: str = "",
        note: str = "",
        created: str = "",
        persistent_keepalive: str = "",
        endpoint: str = "",
    ) -> None:
        lines = [
            f"# WGM_NAME: {name or '未命名'}",
            f"# WGM_NOTE: {note or ''}",
            f"# WGM_CREATED: {created or ''}",
            "[Peer]",
            f"PublicKey = {public_key}",
        ]
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
        lines.append(f"AllowedIPs = {allowed_ips}")
        if endpoint:
            lines.append(f"Endpoint = {endpoint}")
        if persistent_keepalive:
            lines.append(f"PersistentKeepalive = {persistent_keepalive}")

        body = list(self.lines)
        while body and body[-1].strip() == "":
            body.pop()
        self.lines = body + [""] + lines + [""]

    def remove_peer(self, peer: Peer) -> None:
        if peer.block_start < 0 or peer.block_end > len(self.lines):
            raise ValueError("该 Peer 的段落位置已失效，请刷新后重试")
        had_trailing_newline = bool(self.lines) and self.lines[-1] == ""
        del self.lines[peer.block_start : peer.block_end]
        # 合并删除后可能出现的多余空行
        i = peer.block_start
        while (
            0 < i < len(self.lines) - 1
            and self.lines[i].strip() == ""
            and self.lines[i - 1].strip() == ""
        ):
            del self.lines[i]
        if had_trailing_newline and (not self.lines or self.lines[-1] != ""):
            self.lines.append("")


def stripped_for_syncconf(conf_text: str) -> str:
    """模拟 wg-quick strip：只保留 wg(8) 认识的接口字段和 Peer 段。"""
    keep_interface = {"privatekey", "listenport", "fwmark"}
    out: list[str] = []
    current = None
    for line in conf_text.replace("\r\n", "\n").split("\n"):
        s = line.strip()
        if HEADER_RE.match(s):
            current = HEADER_RE.match(s).group(1).strip().lower()
            if current == "interface":
                out.append("[Interface]")
            elif current == "peer":
                out.append("[Peer]")
            else:
                current = None
            continue
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        m = KV_RE.match(s)
        if not m:
            continue
        key = m.group(1).lower()
        if current == "interface":
            if key in keep_interface:
                out.append(f"{m.group(1)} = {m.group(2)}")
        elif current == "peer":
            if key in {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}:
                out.append(f"{m.group(1)} = {m.group(2)}")
    return "\n".join(out) + "\n"
