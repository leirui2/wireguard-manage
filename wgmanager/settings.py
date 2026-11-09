"""界面偏好的持久化。

和 `connections.json` 分开存：那边是连接凭据（加密的），
这边只是开关和数值，混在一起以后想同步/分享容易出事。
"""
from __future__ import annotations

import json
import os

DEFAULTS = {
    "minimize_to_tray": True,     # 点 × 时藏到托盘而不是退出
    "autostart": False,           # 开机自动启动（写注册表）
    "monitor_enabled": True,      # 自动刷新在线状态
    "monitor_interval": 60,       # 秒
    "tray_enabled": True,         # 是否启用托盘
    # 退出时要不要拆掉本程序建立的本机组网隧道。默认不拆 ——
    # 隧道是 Windows 服务，别的程序可能正借着它在用。
    "tunnel_disconnect_on_exit": False,
    # 界面字号基准（磅）。Tk 默认 10，改这里全界面一起变；
    # 只影响显示，不影响任何配置内容或写进服务器的东西。
    "ui_font_size": 10,
}


class Settings:
    def __init__(self, app_dir: str):
        self.path = os.path.join(app_dir, "settings.json")
        self.data = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                for key in DEFAULTS:
                    if key in raw:
                        self.data[key] = raw[key]
        except Exception:
            pass  # 读不出来就用默认值，不该因为配置文件坏了起不来

    def save(self) -> bool:
        try:
            with open(self.path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def get(self, key: str, default=None):
        return self.data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value) -> None:
        self.data[key] = value
        self.save()
