"""本地配置快照 —— 每次改服务器之前，把当时的 wg0.conf 原样留一份。

为什么要在本地留
----------------

服务端本身有备份（``wg0.conf.wgmgr.bak.<时间戳>``），但它只在服务器上，
界面上看不到，也没法挑一个旧版本点一下还原。误删一批密钥之后，只能 ssh
进去手工 ``cp``。

这里把每次「改动前」的配置存到本地 ``history/``，带时间戳和变更摘要。
界面里能翻历史、预览、一键还原 —— 还原本身走的是和普通改动同一条
备份 -> 替换 -> 热加载 -> 校验 -> 失败回滚的路径，不会绕过安全措施。

存的是明文配置，不加密
----------------------

wg0.conf 里有服务器私钥，按说该加密。但它同时也是救命的备份 —— 换机器、
重装、误删之后要靠它恢复，加密绑定 Windows 账号会让"换机器"这个最主要的
使用场景直接失效。所以和 ``clients.vault.json`` 的处理不同，这里存明文，
只保证不进 git（``history/`` 在 .gitignore 里）。
"""
from __future__ import annotations

import datetime
import json
import os
import re

HISTORY_DIR = "history"
INDEX_NAME = "index.json"
FORMAT_VERSION = 1

#: 默认保留多少条。配置一般几 KB，100 条也就几百 KB，不用太抠。
DEFAULT_KEEP = 100


class History:
    def __init__(self, app_dir: str, keep: int = DEFAULT_KEEP):
        self.root = os.path.join(app_dir, HISTORY_DIR)
        self.index_path = os.path.join(self.root, INDEX_NAME)
        self.keep = keep
        self._cache: dict | None = None

    # ---------------------------------------------------------------- 读写
    def _read(self) -> dict:
        if self._cache is not None:
            return self._cache
        data = {"version": FORMAT_VERSION, "entries": []}
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
                data = loaded
        except FileNotFoundError:
            pass
        except Exception:
            pass
        self._cache = data
        return data

    def _write_index(self, data: dict) -> bool:
        tmp = self.index_path + ".tmp"
        try:
            os.makedirs(self.root, exist_ok=True)
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.index_path)
            self._cache = data
            return True
        except Exception:
            try:
                if os.path.isfile(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False

    # ---------------------------------------------------------------- 对外
    def record(self, host: str, text: str, action: str,
               summary: str = "", peers: int = 0) -> dict | None:
        """存一份快照。返回条目；失败返回 None（不该因此中断正在做的改动）。"""
        if not text:
            return None
        now = datetime.datetime.now()
        stamp = now.strftime("%Y%m%d-%H%M%S-%f")[:21]
        entry_id = f"{stamp}-{re.sub(r'[^0-9A-Za-z]+', '', host)[:20] or 'local'}"
        file_name = entry_id + ".conf"
        path = os.path.join(self.root, file_name)
        try:
            os.makedirs(self.root, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except Exception:
            return None

        entry = {
            "id": entry_id,
            "host": host,
            "time": now.isoformat(timespec="seconds"),
            "action": action or "改动",
            "summary": summary,
            "peers": int(peers or 0),
            "file": file_name,
            "size": len(text.encode("utf-8")),
        }
        data = self._read()
        data["entries"].append(entry)
        data["version"] = FORMAT_VERSION
        self._write_index(data)
        self._prune()
        return entry

    def entries(self, host: str = "") -> list[dict]:
        """按时间倒序返回。传 host 只看那台机器的。"""
        items = self._read()["entries"]
        if host:
            items = [e for e in items if e.get("host") == host]
        return list(reversed(items))

    def read(self, entry_id: str) -> str:
        for entry in self._read()["entries"]:
            if entry.get("id") == entry_id:
                try:
                    with open(os.path.join(self.root, entry["file"]),
                              encoding="utf-8") as fh:
                        return fh.read()
                except Exception:
                    return ""
        return ""

    def find(self, entry_id: str) -> dict | None:
        for entry in self._read()["entries"]:
            if entry.get("id") == entry_id:
                return entry
        return None

    def count(self) -> int:
        return len(self._read()["entries"])

    def _prune(self) -> None:
        """只留最近 keep 条，老的连同文件一起清掉，免得 history/ 无限长大。"""
        data = self._read()
        entries = data["entries"]
        if len(entries) <= self.keep:
            return
        drop, entries = entries[: len(entries) - self.keep], entries[-self.keep:]
        for entry in drop:
            try:
                os.remove(os.path.join(self.root, entry["file"]))
            except OSError:
                pass
        data["entries"] = entries
        self._write_index(data)
