"""开机自启：写 HKCU 的 Run 键。

用注册表而不是「启动」文件夹的快捷方式 —— 不需要管理员权限，
也不依赖 shell 链接解析，删起来就是删一个键值。

只对打包好的 exe 有意义：源码模式下 `sys.executable` 是 python.exe，
写进去重启会变成"打开一个空的 Python 窗口"。
"""
from __future__ import annotations

import os
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "WireGuardManager"


def available() -> bool:
    return sys.platform == "win32" and bool(os.environ.get("USERPROFILE"))


def _target_path() -> str:
    """要写进注册表的可执行文件路径。打包后就是 exe 自己。"""
    if getattr(sys, "frozen", False):
        return os.path.normpath(sys.executable)
    return ""


def supported() -> tuple[bool, str]:
    """返回 (能不能用, 不能用的原因)。"""
    if not available():
        return False, "只有 Windows 支持开机自启"
    if not getattr(sys, "frozen", False):
        return False, "源码模式不支持 —— 写进去的是 python.exe，重启会打开空窗口。打包成 exe 后可用"
    return True, ""


def is_enabled() -> bool:
    if not available():
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except (FileNotFoundError, OSError):
        return False


def enable() -> tuple[bool, str]:
    ok, reason = supported()
    if not ok:
        return False, reason
    path = _target_path()
    if not path or not os.path.exists(path):
        return False, f"找不到程序文件：{path or '(空)'}"
    import winreg
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
            # 引号必须加：路径里带空格时，不加会被拆成多个参数
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{path}"')
        return True, path
    except OSError as exc:
        return False, str(exc)


def disable() -> tuple[bool, str]:
    if not available():
        return False, "只有 Windows 支持"
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
        return True, "已取消开机自启"
    except FileNotFoundError:
        return True, "本来就没设置开机自启"
    except OSError as exc:
        return False, str(exc)


def current_target() -> str:
    """注册表里现在记的是哪个路径，用于发现"程序搬家了"的情况。"""
    if not available():
        return ""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, APP_NAME)
            return str(value).strip('"')
    except (FileNotFoundError, OSError):
        return ""
