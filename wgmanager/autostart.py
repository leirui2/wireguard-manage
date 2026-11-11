"""开机自启：写 HKCU 的 Run 键。

用注册表而不是「启动」文件夹的快捷方式 —— 不需要管理员权限，
也不依赖 shell 链接解析，删起来就是删一个键值。

只对打包好的 exe 有意义：源码模式下 `sys.executable` 是 python.exe，
写进去重启会变成"打开一个空的 Python 窗口"。

写进注册表的命令行后面带一个 ``--boot``：登录时被系统拉起来的那一次
要自动连隧道，用户自己双击打开的那一次不该自动弹 UAC。两种启动方式
只能靠参数区分 —— 注册表里存的是同一个 exe。
"""
from __future__ import annotations

import os
import re
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "WireGuardManager"

#: 开机自启专用的启动参数。用户双击 exe 时没有它。
BOOT_FLAG = "--boot"


def available() -> bool:
    return sys.platform == "win32" and bool(os.environ.get("USERPROFILE"))


def _target_path() -> str:
    """要写进注册表的可执行文件路径。打包后就是 exe 自己。"""
    if getattr(sys, "frozen", False):
        return os.path.normpath(sys.executable)
    return ""


def _command() -> str:
    """完整命令行：引号包住路径，再跟上 ``--boot``。

    引号必须有：路径里带空格时，不加会被 Windows 拆成多个参数，
    结果是"找不到文件"或者被别的程序接手。
    """
    path = _target_path()
    return f'"{path}" {BOOT_FLAG}' if path else ""


_QUOTED = re.compile(r'"([^"]*)"\s*(.*)$')


def parse_command(value: str) -> tuple[str, list[str]]:
    """把注册表里存的那串命令行拆成 (路径, 参数列表)。

    单独抽出来是为了能不碰注册表就测 —— 解析错了会把"程序搬家"误判成
    "没设置过"，比写错更麻烦。
    """
    text = str(value or "").strip()
    if not text:
        return "", []
    match = _QUOTED.match(text)
    if match:
        return match.group(1), match.group(2).split()
    parts = text.split()
    if not parts:
        return "", []
    return parts[0].strip('"'), parts[1:]


def is_boot_launch(argv) -> bool:
    """这次启动是不是开机自启拉起来的。

    参数比较不区分大小写：注册表被别人手改过的话可能是 ``--BOOT``。
    """
    return BOOT_FLAG in [str(arg).strip().lower() for arg in (argv or [])]


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
    command = _command()
    if not path or not os.path.exists(path):
        return False, f"找不到程序文件：{path or '(空)'}"
    import winreg
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
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


def current_command() -> str:
    """注册表里现在存的完整命令行（可能带参数）。没有就是空串。"""
    if not available():
        return ""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, APP_NAME)
            return str(value)
    except (FileNotFoundError, OSError):
        return ""


def current_target() -> str:
    """注册表里现在记的是哪个 exe，用于发现"程序搬家了"的情况。

    命令行里可能还有 ``--boot`` 之类的参数，这里只取路径 ——
    把整串直接 strip 引号会得到 ``C:\\...\\a.exe" --boot`` 这种半截东西。
    """
    path, _args = parse_command(current_command())
    return path


def refresh() -> bool:
    """给已设过的自启项补上 ``--boot``（老版本写进去的是纯路径）。

    不补齐的话新的「开机自动连隧道」永远不会触发。三条自我约束：

    * 没设过自启 → 什么都不做，不擅自替用户开启；
    * 注册表里记的是**另一份** exe（用户从下载目录直接跑便携版）→ 不动。
      否则跑一次别的副本就把自启路径抢过去了，下次登录起来的是那一份；
    * 已经有 ``--boot`` → 不重复写，省得每次启动都碰注册表。

    返回是否真的写了注册表。
    """
    if not available() or not is_enabled():
        return False
    exe = _target_path()
    if not exe:
        return False
    path, args = parse_command(current_command())
    if not path or os.path.normcase(path) != os.path.normcase(exe):
        return False
    if is_boot_launch(args):
        return False
    ok, _msg = enable()
    return ok
