"""WireGuard 密钥管理工具 —— 入口。

开发时：双击 启动工具.bat，或执行 `python main.py`
打包后：直接双击 dist\\WireGuard密钥管理工具.exe
"""
from __future__ import annotations

import os
import sys
import traceback

FROZEN = bool(getattr(sys, "frozen", False))
# 打包后 __file__ 在临时解压目录里，日志要写回 exe 旁边
ROOT = (
    os.path.dirname(os.path.abspath(sys.executable))
    if FROZEN
    else os.path.dirname(os.path.abspath(__file__))
)
if not FROZEN:
    for path in (ROOT, os.path.join(ROOT, "vendor")):
        if path not in sys.path:
            sys.path.insert(0, path)


def main() -> None:
    from wgmanager.gui import App

    App().run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        tb = traceback.format_exc()
        try:
            with open(os.path.join(ROOT, "error.log"), "a", encoding="utf-8") as f:
                f.write(tb + "\n" + "=" * 70 + "\n")
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb

            mb.showerror("WireGuard 管理工具启动失败", tb[-1800:])
        except Exception:
            pass
        sys.exit(1)
