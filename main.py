"""WireGuard 管理台 —— 入口。

开发时：双击 启动工具.bat，或执行 `python main.py`
打包后：直接双击 dist\\WireGuard管理台.exe
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


def _close_splash() -> None:
    """收掉启动画面。

    只有带 splash 的打包版本才有 ``pyi_splash``；目录版和源码模式 import 不到，
    这是正常的，不是错误 —— 所以这里一律吞掉异常。
    """
    try:
        import pyi_splash  # type: ignore

        pyi_splash.close()
    except Exception:
        pass


def main() -> None:
    from wgmanager.gui import App

    app = App()
    # 走到这里主窗口已经显示（App.__init__ 末尾会 deiconify），启动图可以退了
    _close_splash()
    app.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _close_splash()
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
