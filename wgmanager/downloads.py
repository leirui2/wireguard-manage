"""官方 WireGuard 客户端下载地址。

**只收录官方来源**，不放任何第三方市场或镜像：

| 平台 | 来源 |
|---|---|
| Windows | `download.wireguard.com` 安装包直链（来自 wireguard-windows 官方仓库 README） |
| Android | Google Play，包名 `com.wireguard.android` |
| iOS / iPadOS | App Store `id1441195209` |
| macOS | App Store `id1451685025` |
| 全平台 | `wireguard.com/install/` 官方安装页（版本一直在更新，拿不准就看这里） |

2026-11-05 逐个核实过。两点现实问题，界面上必须讲清楚：

1. **中国区 App Store 没有这两个 App**（打开链接只会跳到 App Store 首页），
   需要非中国区 Apple ID 才能搜到；
2. **Google Play 在国内打不开**，Android 可以在官方安装页拿 APK 直链。
"""
from __future__ import annotations

OFFICIAL_INSTALL_PAGE = "https://www.wireguard.com/install/"

# (平台, 说明, 下载地址, 按钮文字)
CLIENTS: list[dict] = [
    {
        "platform": "Windows",
        "hint": "官方安装包，自动选 64/ARM 架构；装完双击 .conf 就能导入",
        "url": "https://download.wireguard.com/windows-client/wireguard-installer.exe",
        "action": "下载",
    },
    {
        "platform": "Android",
        "hint": "Google Play 官方版；国内打不开的话，去官方安装页下 APK",
        "url": "https://play.google.com/store/apps/details?id=com.wireguard.android",
        "action": "打开",
    },
    {
        "platform": "iOS / iPadOS",
        "hint": "App Store 官方版，需非中国区 Apple ID 才能搜到",
        "url": "https://apps.apple.com/app/wireguard/id1441195209",
        "action": "打开",
    },
    {
        "platform": "macOS",
        "hint": "App Store 官方版，需要 macOS 12 或更高",
        "url": "https://apps.apple.com/app/wireguard/id1451685025",
        "action": "打开",
    },
    {
        "platform": "Linux",
        "hint": "内核模块 + wg / wg-quick 命令行工具，apt / dnf / pacman 直接装",
        "url": OFFICIAL_INSTALL_PAGE,
        "action": "打开",
    },
]


def open_url(url: str) -> bool:
    """用系统默认浏览器打开链接，失败返回 False。"""
    try:
        import webbrowser

        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False
