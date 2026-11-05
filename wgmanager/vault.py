"""客户端配置保险箱 —— 按公钥索引，加密保存每份客户端 .conf。

解决什么问题
------------

客户端私钥只在生成那一刻出现在内存里，服务端只存公钥，事后按理说再也
导不出来。而 ``clients/<名字>.conf`` 一旦被删、被改名、或者当初没勾选
「保存到 clients/」，这份配置就永久丢了 —— 想再给同一个客户端出个二维码
只能重新生成密钥、重新发给对方。

这里在生成时顺手留一份**加密副本**，按客户端公钥（= 服务端 peer 的
公钥）索引。之后可以：

* 随时重看二维码 / 重新导出 .conf；
* 服务器换了公网 IP 或端口，用新 Endpoint 重建所有客户端配置；
* 误删了 clients/ 目录也能从保险箱恢复。

为什么按公钥索引
----------------

公钥改名不变。用名字做 key 的话，用户改一次备注就找不到了。

加密方式
--------

复用 ``secrets.py`` 的 DPAPI，整份 .conf 文本加密后存 ``clients.vault.json``。
密文绑定当前 Windows 用户，换机器解不开 —— 和 connections.json 同一套逻辑。
"""
from __future__ import annotations

import datetime
import json
import os

from . import secrets

VAULT_NAME = "clients.vault.json"
FORMAT_VERSION = 1


class Vault:
    """``clients.vault.json`` 的读写封装。所有异常都内部消化，不往上抛。

    界面是"顺手存一份"的语义，存不上最多是这条密钥以后找不回配置，
    不该因此让「新增密钥」整体失败。
    """

    def __init__(self, app_dir: str):
        self.path = os.path.join(app_dir, VAULT_NAME)
        self._cache: dict | None = None

    # ---------------------------------------------------------------- 读写
    def _read(self) -> dict:
        if self._cache is not None:
            return self._cache
        data = {"version": FORMAT_VERSION, "entries": {}}
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), dict):
                data = loaded
        except FileNotFoundError:
            pass
        except Exception:
            # 文件坏了就当空的，别让界面起不来；原文件留在原地下次覆盖
            pass
        self._cache = data
        return data

    def _write(self, data: dict) -> bool:
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
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
    def put(self, pubkey: str, name: str, conf_text: str,
            file_name: str = "") -> bool:
        """保存一份客户端配置。返回 False 表示没存上（加密不可用或写盘失败）。"""
        if not pubkey or not conf_text:
            return False
        sealed = secrets.protect(conf_text)
        if not sealed:
            # 加密不可用 —— 宁可不存，也不把明文私钥写进 json
            return False
        data = self._read()
        entry = {
            "name": name,
            "file": file_name,
            "sealed": sealed,
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        data["entries"][pubkey] = entry
        data["version"] = FORMAT_VERSION
        return self._write(data)

    def get(self, pubkey: str) -> dict | None:
        """取出并解密。解不开（换机器/换账号）返回 None，界面提示重新生成。"""
        if not pubkey:
            return None
        entry = self._read()["entries"].get(pubkey)
        if not isinstance(entry, dict):
            return None
        conf = secrets.unprotect(entry.get("sealed", ""))
        if not conf:
            return None
        return {
            "name": entry.get("name", ""),
            "file": entry.get("file", ""),
            "created": entry.get("created", ""),
            "conf": conf,
        }

    def has(self, pubkey: str) -> bool:
        return isinstance(self._read()["entries"].get(pubkey), dict)

    def drop(self, pubkey: str) -> None:
        """删除密钥时顺手清掉，避免私钥越积越多。"""
        data = self._read()
        if pubkey in data["entries"]:
            del data["entries"][pubkey]
            self._write(data)

    def count(self) -> int:
        return len(self._read()["entries"])

    def rename(self, pubkey: str, name: str, file_name: str = "") -> None:
        """改备注时同步一下，方便以后按名字找。配置内容不动。"""
        data = self._read()
        entry = data["entries"].get(pubkey)
        if not isinstance(entry, dict):
            return
        entry["name"] = name
        if file_name:
            entry["file"] = file_name
        self._write(data)
