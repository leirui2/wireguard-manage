"""打包前确定版本号：本地打的包要跟线上发布版对齐。

为什么需要这个
--------------
CI 出的号是「源码基线.构建号」（例如 1.0.17.16），本地手动打包只有基线
（1.0.17）。三段号对四段号比较时永远偏小，于是本地这个明明是最新代码
打的包，点「检查更新」却一直被告知有新版 —— 就是个死循环。

这里让本地打包也去读一眼线上最新版本：线上更新的就把号跟上去，源码基线
更新（开发者手动升过）就用基线的。两种情况都不会再自己跟自己打架。

失败不阻断构建：读不到线上（没网 / 代理挂了 / API 限流）就退回源码基线，
只在屏幕上提示一句。

用法：
    python build_assets/resolve_version.py           # 自动对齐后 stamp
    python build_assets/resolve_version.py --dry-run # 只打印，不写文件
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "build_assets"))

from stamp_version import stamp  # noqa: E402  （同目录，避免依赖 build_assets 是包）

INIT = ROOT / "wgmanager" / "__init__.py"


def read_base() -> str:
    text = INIT.read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]*)"', text)
    if not m:
        raise SystemExit(f"{INIT} 里找不到 __version__")
    return m.group(1).strip()


def read_online() -> str:
    """读线上最新版本号。任何失败都返回空串，由调用方退回基线。"""
    try:
        from wgmanager.updater import fetch_latest

        return fetch_latest(timeout=8).version
    except Exception as exc:
        print(f"  (读取线上版本失败：{type(exc).__name__}: {exc})")
        return ""


def main() -> int:
    base = read_base()
    print(f"  源码基线 : {base}")

    online = read_online()
    if online:
        print(f"  线上最新 : {online}")
    else:
        print("  线上最新 : (读不到，退回源码基线)")

    # 线上比基线新才跟上去；基线更新（手动升过版本）就保留基线。
    # 相等的情况两个分支结果一样，走 else 少一次解析。
    from wgmanager.updater import is_newer

    final = online if (online and is_newer(online, base)) else base

    if final != base:
        print(f"  -> 采用线上号 {final}（否则本地包会被判成旧版，天天提示更新）")
    else:
        print(f"  -> 使用 {final}")

    if "--dry-run" in sys.argv:
        print(f"final={final}")
        return 0

    stamp(final)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
