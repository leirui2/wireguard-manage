"""本地口令保险箱 —— 用 Windows DPAPI 加密后再落盘。

为什么不直接存明文：``connections.json`` 就躺在 exe 旁边，很容易被同步网盘、
被打包发给同事排查问题、或者被录屏顺手带走。SSH 密码泄露意味着服务器直接
被人登进去。

DPAPI（``CryptProtectData``）是 Windows 自带的、不需要管理密钥的加密：
密文和**当前 Windows 用户账号**绑定，换机器、换账号都解不开。这正是我们要的
性质 —— 配置文件被复制走也没用。代价是重装系统后已存的口令要重新输一遍，
这个代价可以接受。

设计取舍：

* 只加密**口令**，主机、端口、用户名这些照旧明文，方便人直接看文件排查；
* 解密失败（换了机器 / 换了账号 / 文件被改过）一律返回空串，界面就当没存过，
  让用户重输，绝不因为读不出而报错卡住流程；
* 非 Windows 平台（源码在 Linux 上跑）直接降级成"不保存"。宁可每次重输，
  也不明文落盘。
"""
from __future__ import annotations

import base64
import sys

#: 密文前缀。带前缀是为了能一眼看出这个字段是加密的，
#: 而不是把明文误当成密文去 base64 解码。
PREFIX = "dpapi:"

#: CRYPTPROTECT_UI_FORBIDDEN —— 禁止弹任何系统对话框，
#: 否则在没有交互的线程里会直接卡死。
_UI_FORBIDDEN = 0x1

_available: bool | None = None

#: 必须缓存 —— 每次调用都重新定义 DATA_BLOB 类的话，argtypes 里登记的是
#: 第一次那个类，后面传新类的实例会被 ctypes 判定类型不符直接抛错。
_api = None


def _load_api():
    """第一次调用时才碰 ctypes，非 Windows 上不会进这里。"""
    global _api
    if _api is None:
        _api = _build_api()
    return _api


def _build_api():
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    # 64 位下必须显式声明，否则指针会被按 32 位截断，直接崩
    blob_p = ctypes.POINTER(DATA_BLOB)
    crypt32.CryptProtectData.argtypes = [
        blob_p, wintypes.LPCWSTR, blob_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_p,
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        blob_p, ctypes.POINTER(wintypes.LPWSTR), blob_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_p,
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    return ctypes, DATA_BLOB, crypt32, kernel32


def available() -> bool:
    """DPAPI 能不能用。界面据此决定"记住密码"要不要置灰。"""
    global _available
    if _available is None:
        if sys.platform != "win32":
            _available = False
        else:
            try:
                _load_api()
                _available = True
            except Exception:
                _available = False
    return _available


def _pack(data: bytes):
    """把 bytes 装成 DATA_BLOB，同时把底层缓冲区一并返回。

    缓冲区必须由调用方持有：只返回结构体的话，create_string_buffer 出的
    buf 在函数返回时就被回收了，pbData 指向释放过的内存 —— 加密出来是垃圾
    或者直接崩。
    """
    import ctypes

    _, DATA_BLOB, _, _ = _load_api()
    buf = ctypes.create_string_buffer(data, len(data) or 1)
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _take(blob, kernel32, ctypes) -> bytes:
    """把出参 blob 取成 bytes，并释放系统分配的内存。"""
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        if blob.pbData:
            kernel32.LocalFree(blob.pbData)


def protect(text: str) -> str:
    """加密。空串返回空串；失败也返回空串（调用方就当没记住）。"""
    if not text or not available():
        return ""
    try:
        ctypes, DATA_BLOB, crypt32, kernel32 = _load_api()
        blob_in, _keep = _pack(text.encode("utf-8"))
        blob_out = DATA_BLOB()
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None,
            _UI_FORBIDDEN, ctypes.byref(blob_out),
        )
        if not ok:
            return ""
        raw = _take(blob_out, kernel32, ctypes)
        return PREFIX + base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


def unprotect(blob: str) -> str:
    """解密。解不开一律返回空串 —— 换机器、换账号、文件被改都会走到这里。"""
    if not blob or not blob.startswith(PREFIX) or not available():
        return ""
    try:
        ctypes, DATA_BLOB, crypt32, kernel32 = _load_api()
        raw = base64.b64decode(blob[len(PREFIX):])
        blob_in, _keep = _pack(raw)
        blob_out = DATA_BLOB()
        descr = ctypes.c_wchar_p()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), ctypes.byref(descr), None, None, None,
            _UI_FORBIDDEN, ctypes.byref(blob_out),
        )
        if not ok:
            return ""
        if descr.value:
            kernel32.LocalFree(descr)
        return _take(blob_out, kernel32, ctypes).decode("utf-8", "replace")
    except Exception:
        return ""


def is_sealed(value) -> bool:
    """这个字段是不是存过加密口令。界面用它决定"记住密码"要不要自动勾上。"""
    return isinstance(value, str) and value.startswith(PREFIX)
