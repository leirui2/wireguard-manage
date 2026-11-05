"""操作审计日志。

把「什么时候、对哪台服务器、哪个密钥、做了什么」记成一行 JSON，
追加写进 audit.jsonl。多人共用一台服务器时，能查出是谁的哪次操作导致的变化。

安全边界：只记公钥和名称，绝不落私钥 / PresharedKey / 任何口令 ——
这个文件是明文，会被随手发出去排查问题。

文件超过 1MB 轮转一次，保留 5 份，不会无限长。
"""
from __future__ import annotations

import csv
import datetime as dt
import getpass
import json
import os

DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_KEEP = 5

# 动作 → 展示用的中文，界面和导出都用它
ACTION_LABELS = {
    "add": "新增密钥",
    "edit": "修改密钥",
    "delete": "删除密钥",
    "restore": "还原配置",
    "install": "安装服务端",
    "expire": "清理过期",
}


class AuditLog:
    def __init__(self, app_dir: str, max_bytes: int = DEFAULT_MAX_BYTES,
                 keep: int = DEFAULT_KEEP):
        self.path = os.path.join(app_dir, "audit.jsonl")
        self.max_bytes = max_bytes
        self.keep = keep

    # ------------------------------------------------------------ 写
    def record(self, action: str, *, host: str = "", name: str = "",
               pubkey: str = "", detail: str = "", result: str = "ok",
               backup: str = "") -> bool:
        """追加一条记录。失败不抛异常 —— 审计日志写不进去不该阻断正常操作。"""
        now = dt.datetime.now()
        row = {
            "ts": now.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": round(now.timestamp(), 3),
            "user": _current_user(),
            "host": host or "",
            "action": action,
            "name": name or "",
            "pubkey": pubkey or "",
            "detail": _scrub(detail),
            "result": result,
            "backup": os.path.basename(backup) if backup else "",
        }
        try:
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            return True
        except Exception:
            return False

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        # audit.4 → 丢弃，audit.3 → audit.4 …… 最后 audit.jsonl → audit.1
        oldest = f"{self.path}.{self.keep - 1}"
        if os.path.exists(oldest):
            try:
                os.remove(oldest)
            except OSError:
                pass
        for i in range(self.keep - 2, 0, -1):
            src = f"{self.path}.{i}"
            if os.path.exists(src):
                try:
                    os.replace(src, f"{self.path}.{i + 1}")
                except OSError:
                    pass
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError:
            pass

    # ------------------------------------------------------------ 读
    def rows(self, limit: int = 500, host: str = "",
             action: str = "", keyword: str = "") -> list[dict]:
        """最近 limit 条，倒序（新的在前）。可按服务器 / 动作 / 关键词过滤。

        排序用 (时间戳, 写入序号)：同一毫秒内写了多条时，光比时间戳会乱序
        —— 程序里连着调几次 record 是常事。
        """
        out: list[dict] = []
        seq = 0
        for path in self._all_files():
            for row in self._read_file(path):
                seq += 1
                if host and row.get("host") != host:
                    continue
                if action and row.get("action") != action:
                    continue
                if keyword:
                    blob = " ".join(str(row.get(k, "")) for k in
                                    ("name", "detail", "pubkey", "user", "host"))
                    if keyword.lower() not in blob.lower():
                        continue
                row = dict(row)
                row["_seq"] = seq
                out.append(row)
        out.sort(key=lambda r: (r.get("epoch", 0), r["_seq"]), reverse=True)
        return out[:limit]

    def hosts(self) -> list[str]:
        seen = {r.get("host", "") for r in self.rows(limit=5000)}
        return sorted(h for h in seen if h)

    def count(self) -> int:
        return sum(len(self._read_file(p)) for p in self._all_files())

    def _all_files(self) -> list[str]:
        """从旧到新，保证同一条记录不会被重复计入。"""
        files = [f"{self.path}.{i}" for i in range(self.keep - 1, 0, -1)]
        files.append(self.path)
        return [p for p in files if os.path.exists(p)]

    @staticmethod
    def _read_file(path: str) -> list[dict]:
        rows = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue  # 断电写坏的行，跳过就好，别让整个窗口打不开
                    if isinstance(obj, dict):
                        rows.append(obj)
        except OSError:
            pass
        return rows


def export_csv(rows: list[dict], path: str) -> int:
    """导出成 Excel 能直接打开的 CSV（带 BOM，否则中文乱码）。"""
    headers = ["时间", "操作", "服务器", "密钥名", "公钥", "详情", "结果", "操作者"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            w.writerow([
                r.get("ts", ""),
                ACTION_LABELS.get(r.get("action", ""), r.get("action", "")),
                r.get("host", ""),
                r.get("name", ""),
                r.get("pubkey", ""),
                r.get("detail", ""),
                "成功" if r.get("result") == "ok" else "失败",
                r.get("user", ""),
            ])
    return len(rows)


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or ""


def _scrub(text: str) -> str:
    """兜底：万一调用方把私钥之类塞进 detail，这里再挡一道。

    只拦明显是密钥材料的形态，不做过度替换 —— 正常文本不该被改。
    """
    if not text:
        return ""
    out = str(text)
    for marker in ("PrivateKey", "PresharedKey", "PrivateKey =", "password="):
        if marker.lower() in out.lower():
            return "（内容含敏感字段，已隐去）"
    return out[:300]
