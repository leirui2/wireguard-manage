"""本机组网隧道 —— 托管 Windows 版 WireGuard 客户端的隧道服务。

为什么不自己实现：WireGuard 在 Windows 上要靠 ``wgntdrv.sys`` 内核虚拟网卡
加一个 SYSTEM 服务才能建隧道，这些是官方客户端装好的。本程序只做调度：
把配置交给 ``wireguard.exe``，由它注册 / 卸载 ``WireGuardTunnel$<名字>``
服务。**流量一个字节都不经过本程序**，崩了也不影响已建立的隧道。

三条必须记住的性质，代码里所有奇怪写法都是为它们服务的：

* 隧道是 **Windows 服务**，生命周期比本程序长。程序崩了、被任务管理器杀了，
  隧道还在跑。所以"拉起"必须幂等（已在跑就复用），退出时也要显式卸载。
* ``wireguard.exe`` 内部走 ``ShellExecute`` 自己弹 UAC 提权，父进程**拿不到
  子进程的退出码和输出**。成功与否只能靠查服务状态和端口可达性判断 ——
  不要试图看 returncode。
* 隧道名和官方客户端 GUI 共用同一个命名空间，撞名会直接失败
  （``Another tunnel already exists with the name``），所以统一加 ``wgm-`` 前缀。
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

from .secrets import protect, unprotect

#: 隧道名统一前缀。官方客户端建的隧道（如 18-rl）和我们共用一个命名空间，
#: 不带前缀迟早撞名，撞了就是"另一个同名隧道已存在"直接失败。
TUNNEL_PREFIX = "wgm-"

#: 隧道起来到端口真正可用通常 1~3 秒，给 25 秒容差（慢机器 / 远端握手慢）。
DEFAULT_WAIT = 25

_SERVICE_RUNNING = 0x04
_SERVICE_STOPPED = 0x01
_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_ERROR_SERVICE_DOES_NOT_EXIST = 1060


class TunnelError(RuntimeError):
    """隧道没建成 / 卸载没生效。message 是给用户直接看的，别写英文报错码。"""


@dataclass
class TunnelSpec:
    """一条服务器绑定的组网隧道。"""

    name: str           # 隧道名（不含 WireGuardTunnel$ 前缀）
    conf: str           # 明文 conf 内容，只在内存里待着
    host: str           # 隧道起来后要连的地址（VPN 地址，不是公网 IP）
    port: int = 22


@dataclass
class TunnelResult:
    """``ensure_up`` 的结果。

    ``started`` 区分"这次是我们亲手装的"和"本来就在跑/根本不用连" ——
    退出时只该拆自己装的那条，别人（官方客户端、别的程序）建的不许动。
    """

    note: str
    started: bool


# ---------------------------------------------------------------- 客户端探测
def client_path() -> str:
    """找 wireguard.exe。找不到返回空串，由调用方给出引导文案。"""
    override = os.environ.get("WGM_WIREGUARD_EXE", "")
    if override and os.path.isfile(override):
        return override
    # 官方安装包会写 InstallDir，优先信它（有人装在 D 盘）
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WireGuard") as key:
            try:
                install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
            except OSError:
                install_dir = ""
        if install_dir:
            exe = os.path.join(str(install_dir).rstrip("\\"), "wireguard.exe")
            if os.path.isfile(exe):
                return exe
    except Exception:
        pass
    for base in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(base)
        if not root:
            continue
        exe = os.path.join(root, "WireGuard", "wireguard.exe")
        if os.path.isfile(exe):
            return exe
    return ""


def available() -> bool:
    """客户端装没装。界面据此决定组网功能能不能用。"""
    return bool(client_path())


def installed_tunnels() -> list[str]:
    """官方客户端配置目录里已有的隧道名（含 GUI 里建的那些）。

    配置在 ``Data\\Configurations`` 下存成 ``<名字>.conf.dpapi``（DPAPI 加密），
    这里只读文件名，不碰内容。
    """
    folder = config_dir()
    if not folder:
        return []
    try:
        names = []
        for entry in os.listdir(folder):
            if not entry.endswith(".conf.dpapi"):
                continue
            names.append(entry[: -len(".conf.dpapi")])
        return sorted(names)
    except OSError:
        return []


def config_dir() -> str:
    """官方客户端存隧道配置的目录。找不到客户端就是空串。"""
    exe = client_path()
    if not exe:
        return ""
    return os.path.join(os.path.dirname(exe), "Data", "Configurations")


def is_stored(name: str) -> bool:
    """wireguard.exe 有没有把这份配置收下（收下 = 加密写进 Configurations）。

    失败时靠它区分"根本没接手"和"接手了但服务起不来" —— 两种故障的
    排查方向完全不同。

    注意这里**不** normalize：调用方给的已经是真实隧道名，
    再洗一遍会把客户端自己建的 ``18-rl`` 洗成 ``wgm-18-rl`` 查错文件。
    """
    folder = config_dir()
    if not folder or not name:
        return False
    return os.path.isfile(os.path.join(folder, str(name) + ".conf.dpapi"))


def is_admin() -> bool:
    """当前进程是不是已经提权了。提权过就不会再弹 UAC，提示文案可以变。"""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- 名称与校验
_INVALID_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def normalize_name(raw: str) -> str:
    """清洗成合法隧道名：只留字母数字和 ``_-.``，并保证带 ``wgm-`` 前缀。"""
    name = (raw or "").strip()
    if name.lower().endswith(".conf"):
        name = name[: -len(".conf")]
    name = _INVALID_CHARS.sub("-", name).strip("-._")
    if not name:
        name = "tunnel"
    if not name.lower().startswith(TUNNEL_PREFIX):
        name = TUNNEL_PREFIX + name
    return name[:60]


def unique_name(base: str, taken: list[str]) -> str:
    """名字被占用时自动加序号，避免把官方客户端的隧道顶掉。"""
    name = normalize_name(base)
    if name not in taken:
        return name
    for i in range(2, 100):
        candidate = f"{name}-{i}"
        if candidate not in taken:
            return candidate
    return f"{name}-{int(time.time()) % 10000}"


def _conf_fields(text: str) -> dict[str, dict[str, str]]:
    """把 conf 拆成 {"interface": {...}, "peer": {...}}，只取第一个 Peer。

    只做存在性检查，格式细节交给 ``wireguard.exe`` —— 我们不是解析器，
    没必要重复实现一套 wg-quick 的规则，也避免版本差异带来的误判。
    """
    fields: dict[str, dict[str, str]] = {"interface": {}, "peer": {}}
    section = ""
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low == "[interface]":
            section = "interface"
            continue
        if low == "[peer]":
            section = "peer"
            continue
        if section and "=" in line:
            key, value = line.split("=", 1)
            fields[section].setdefault(key.strip().lower(), value.strip())
    return fields


def validate_conf(text: str) -> list[str]:
    """检查导入的 conf 能不能用，返回中文问题列表（空 = 通过）。"""
    if not text or not text.strip():
        return ["文件是空的"]
    fields = _conf_fields(text)
    iface, peer = fields["interface"], fields["peer"]
    problems = []
    if not iface:
        problems.append("缺少 [Interface] 段")
    if not peer:
        problems.append("缺少 [Peer] 段")
    if iface and not iface.get("privatekey"):
        problems.append("Interface 缺少 PrivateKey（这台电脑的私钥）")
    if iface and not iface.get("address"):
        problems.append("Interface 缺少 Address（这台电脑的 VPN 地址）")
    if peer and not peer.get("publickey"):
        problems.append("Peer 缺少 PublicKey（服务器公钥）")
    if peer and not peer.get("endpoint"):
        problems.append("Peer 缺少 Endpoint（服务器地址:端口）")
    if peer and not peer.get("allowedips"):
        problems.append("Peer 缺少 AllowedIPs")
    return problems


def conf_notes(text: str) -> list[str]:
    """不拦路但值得提醒的情况。"""
    peer = _conf_fields(text)["peer"]
    allowed = peer.get("allowedips", "")
    notes = []
    if "0.0.0.0/0" in allowed or "::/0" in allowed:
        notes.append(
            "AllowedIPs 是 0.0.0.0/0（全隧道）：整机流量都会绕进隧道，"
            "连公网 IP 也会。如果这台服务器走的是内网地址，建议改成内网网段。"
        )
    if not _conf_fields(text)["peer"].get("persistentkeepalive"):
        notes.append(
            "没有 PersistentKeepalive：对面是 NAT 后面时容易掉线，"
            "长连接管理建议加 PersistentKeepalive = 25。"
        )
    return notes


def conf_summary(text: str) -> dict:
    """从 conf 里抠出列表页要显示的两三个字段。解不开就当空。"""
    fields = _conf_fields(text or "")
    return {
        "address": fields["interface"].get("address", ""),
        "endpoint": fields["peer"].get("endpoint", ""),
        "allowed": fields["peer"].get("allowedips", ""),
    }


# ---------------------------------------------------------------- 服务状态
def service_name(name: str) -> str:
    return "WireGuardTunnel$" + name


def _query_service(svc_name: str) -> str:
    """查服务状态：running / stopped / pending / absent / unknown。

    走 advapi32 而不是 ``sc query`` 再解析文本 —— 中文版 Windows 的
    sc 输出字段名可能被本地化，解析文本会在某些机器上莫名其妙失效。
    """
    import ctypes
    from ctypes import wintypes

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                        wintypes.DWORD]
    advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                      wintypes.DWORD]
    advapi32.OpenServiceW.restype = wintypes.HANDLE
    advapi32.QueryServiceStatus.argtypes = [wintypes.HANDLE,
                                            ctypes.POINTER(SERVICE_STATUS)]
    advapi32.QueryServiceStatus.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi32.CloseServiceHandle.restype = wintypes.BOOL

    scm = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not scm:
        return "unknown"
    state = 0
    try:
        svc = advapi32.OpenServiceW(scm, svc_name, _SERVICE_QUERY_STATUS)
        if not svc:
            err = ctypes.get_last_error()
            return "absent" if err == _ERROR_SERVICE_DOES_NOT_EXIST else "unknown"
        try:
            status = SERVICE_STATUS()
            if not advapi32.QueryServiceStatus(svc, ctypes.byref(status)):
                return "unknown"
            state = status.dwCurrentState
        finally:
            advapi32.CloseServiceHandle(svc)
    finally:
        advapi32.CloseServiceHandle(scm)

    if state == _SERVICE_RUNNING:
        return "running"
    if state == _SERVICE_STOPPED:
        return "stopped"
    return "pending"


def service_state(name: str) -> str:
    if sys.platform != "win32":
        return "unknown"
    try:
        return _query_service(service_name(normalize_name(name)))
    except Exception:
        return "unknown"


STATE_CN = {
    "running": "运行中",
    "stopped": "已停止",
    "pending": "启动中",
    # 别写"未安装"：那是说隧道服务还没建，容易被读成"没装 WireGuard 客户端"
    "absent": "尚未建立",
    "unknown": "未知",
}


# ---------------------------------------------------------------- 网络探测
def tcp_ok(host: str, port: int, timeout: float = 1.5) -> bool:
    """目标端口通不通。这是"隧道到底有没有用"的唯一判据。"""
    if not host:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait_ready(host: str, port: int, name: str = "",
               timeout: int = DEFAULT_WAIT, log=print) -> bool:
    """等隧道真正可用。install 返回 ≠ 可用，网卡/路由/DNS 还要 1~3 秒。"""
    deadline = time.monotonic() + max(1, timeout)
    last_note = 0.0
    while time.monotonic() < deadline:
        if tcp_ok(host, port):
            return True
        now = time.monotonic()
        if name and now - last_note > 6:
            last_note = now
            log(f"等待 {host}:{port} 可达…（隧道服务："
                f"{STATE_CN.get(service_state(name), '未知')}）")
        time.sleep(0.7)
    return False


# ---------------------------------------------------------------- 装卸隧道
def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    """跑 wireguard.exe。注意：它自己弹 UAC，退出码**不可信**，只用来记日志。"""
    flags = 0
    if sys.platform == "win32":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=flags)
    except FileNotFoundError:
        raise TunnelError("找不到 wireguard.exe，请确认 WireGuard 客户端还在。")
    except subprocess.TimeoutExpired:
        raise TunnelError(
            "调用 WireGuard 客户端超时 —— 大概率是 UAC 弹窗一直没人点。\n"
            "请重试并在弹窗里点「是」。"
        )
    except OSError as exc:
        raise TunnelError(f"调用 wireguard.exe 失败：{exc}")
    out = (proc.stdout or b"").decode("utf-8", "replace")
    out += (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, out.strip()


def _write_temp_conf(name: str, conf_text: str) -> str:
    """把 conf 写到只有当前用户能进的临时目录，返回路径。

    没有额外去改 ACL：``%TEMP%`` 默认就只给当前用户和 Administrators/SYSTEM，
    已经够了；手动收紧反而会把自己后面的删除权限一起去掉（删不掉明文私钥
    比留几秒钟更糟）。文件在隧道确认起来后立刻删，正常情况下存续几秒。
    """
    folder = tempfile.mkdtemp(prefix="wgm-tunnel-")
    path = os.path.join(folder, name + ".conf")
    body = conf_text if conf_text.endswith("\n") else conf_text + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    return path


def _cleanup(path: str) -> None:
    """删掉临时 conf 和它所在的目录。删不掉不报错，下次启动还会再扫一遍。"""
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass
    try:
        os.rmdir(os.path.dirname(path))
    except OSError:
        pass


def cleanup_stale(max_age: float = 600) -> int:
    """清理上次异常退出留下的临时 conf（超过 10 分钟的才动）。"""
    base = tempfile.gettempdir()
    try:
        entries = os.listdir(base)
    except OSError:
        return 0
    now = time.time()
    removed = 0
    for entry in entries:
        if not entry.startswith("wgm-tunnel-"):
            continue
        folder = os.path.join(base, entry)
        if not os.path.isdir(folder):
            continue
        try:
            if now - os.path.getmtime(folder) < max_age:
                continue
            for item in os.listdir(folder):
                try:
                    os.remove(os.path.join(folder, item))
                except OSError:
                    pass
            os.rmdir(folder)
            removed += 1
        except OSError:
            continue
    return removed


def _shell_execute_runas(exe: str, params: str) -> int:
    """显式用"以管理员身份运行"启动 exe，返回 ShellExecute 的结果码。

    为什么不用 ``subprocess``：``wireguard.exe`` 装隧道服务必须先提权，它内部
    虽然也会尝试自提权，但从一个非提权进程被 CreateProcess 起来时并不可靠 ——
    实测会静默失败，我们连原因都拿不到。自己走 ``ShellExecuteW(runas)`` 后：

    * UAC 一定会弹（这是用户该看到的）
    * 返回值能区分"用户取消了"（1223）和真的失败
    * 返回值 > 32 只代表成功发起，进程是异步的，成败还得靠轮询服务状态
    """
    import ctypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                      ctypes.c_wchar_p, ctypes.c_wchar_p,
                                      ctypes.c_wchar_p, ctypes.c_int]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    # SW_HIDE：wireguard.exe 带开关运行时本来就不显示窗口，隐藏更稳妥
    res = shell32.ShellExecuteW(None, "runas", exe, params, None, 0)
    return int(res or 0)


#: ShellExecute 返回值小于等于这个数就是错误码，不是 HINSTANCE
_SE_ERROR_LIMIT = 32


def _elevate_error(code: int) -> str:
    if code in (1223, 5):
        return ("你在 Windows 权限确认（UAC）里点了「否」或直接关掉了，"
                "隧道没能建立。\n重试时请点「是」。")
    if code == 2:
        return "找不到 wireguard.exe，可能客户端被卸载了。"
    if code == 31:
        return "系统里没有可用的文件关联，无法启动 wireguard.exe。"
    return f"启动 wireguard.exe 失败（ShellExecute 返回 {code}）。"


def _launch(exe: str, args: list[str], log=print) -> str:
    """把一条 wireguard.exe 命令跑起来，需要时弹 UAC 提权。

    已经提权就直接跑（能拿到输出，排查方便）；没提权就走 ShellExecute(runas)。
    返回 wireguard.exe 的文本输出（提权路径下拿不到，返回空串）。
    """
    if is_admin():
        rc, out = _run([exe] + args, timeout=150)
        if out:
            log("wireguard.exe：" + " ".join(out.split())[:300])
        return out
    params = " ".join([args[0]] + [f'"{a}"' for a in args[1:]])
    res = _shell_execute_runas(exe, params)
    if res <= _SE_ERROR_LIMIT:
        raise TunnelError(_elevate_error(res))
    log("已请求管理员权限（UAC 弹窗请点「是」）")
    return ""


def install(name: str, conf_text: str, log=print) -> str:
    """安装并启动隧道服务，返回临时 conf 路径 —— 调用方负责删。"""
    exe = client_path()
    if not exe:
        raise TunnelError(
            "没有检测到 WireGuard 客户端。\n"
            "组网功能需要官方客户端提供内核驱动，请先安装（安装包可在"
            "「下载客户端」里拿），装好后回来重试。"
        )
    name = normalize_name(name)
    path = _write_temp_conf(name, conf_text)
    try:
        _launch(exe, ["/installtunnelservice", path], log)
    except Exception:
        _cleanup(path)
        raise
    return path


def down(name: str, log=print) -> str:
    """卸载隧道服务。已经在跑的话会弹一次 UAC。"""
    name = normalize_name(name)
    if service_state(name) == "absent":
        return f"隧道 {name} 本来就没在运行"
    exe = client_path()
    if not exe:
        raise TunnelError("找不到 wireguard.exe，没法卸载隧道。")
    out = _launch(exe, ["/uninstalltunnelservice", name], log)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if service_state(name) == "absent":
            log(f"组网隧道 {name} 已断开")
            return f"已断开组网隧道 {name}"
        time.sleep(0.5)
    detail = ("（" + " ".join(out.split())[:200] + "）") if out else ""
    raise TunnelError(f"卸载隧道 {name} 没有生效{detail}")


def _fail_hint(name: str) -> str:
    """隧道没起来时给用户的诊断。靠"配置有没有被收下"分流排查方向。"""
    name = normalize_name(name)
    state = service_state(name)
    if is_stored(name):
        return (
            f"WireGuard 客户端收下了配置，但隧道服务没起来"
            f"（当前状态：{STATE_CN.get(state, state)}）。\n\n"
            "这基本不是配置问题，多半是内核驱动 wgntdrv.sys 没装上或被安全软件拦住。\n"
            "可以这样确认：打开 WireGuard 客户端，试着连它自己列表里的隧道；"
            "连得上说明驱动没问题，那就是本工具的调用方式要再看。"
        )
    return (
        f"WireGuard 客户端没有接手这份配置（隧道 {name} 仍不存在）。\n\n"
        "常见原因：\n"
        "• 权限确认（UAC）被点了「否」或者直接关掉了 —— 重试时点「是」\n"
        f"• 已有同名隧道 {name} 且配置不同 —— 换个隧道名再试\n"
        "• 客户端装得不完整（只有 wireguard.exe，驱动没装上）"
    )


# ---------------------------------------------------------------- 对外主入口
def ensure_up(spec: TunnelSpec, wait: int = DEFAULT_WAIT,
              log=print) -> TunnelResult:
    """确保隧道可用。

    幂等设计，按顺序判断：

    1. 目标端口本来就通 → 什么都不做（可能走的是公网，或者隧道已被官方客户端
       建好了）。少弹一次 UAC 少一次打扰。
    2. 服务已经在跑 → 只等端口，不重复 install（否则会报同名隧道已存在）。
    3. 都没有 → install 并等待。
    """
    name = normalize_name(spec.name)
    if not spec.conf.strip():
        raise TunnelError("这条配置没有导入组网 conf，无法建立隧道。")

    if tcp_ok(spec.host, spec.port):
        if service_state(name) == "running":
            return TunnelResult(f"组网隧道 {name} 已在运行", False)
        return TunnelResult("目标地址已可直接连接，跳过组网", False)

    path = ""
    started = False
    try:
        if service_state(name) == "running":
            log(f"隧道 {name} 已在运行，等待 {spec.host}:{spec.port} 可达…")
            total_wait = wait
        else:
            log(f"正在建立组网隧道 {name} …")
            asked_uac = not is_admin()
            if asked_uac:
                log("即将弹出 Windows 权限确认，请点「是」，否则隧道建不起来。")
            path = install(name, spec.conf, log)
            started = True
            # UAC 弹窗在用户手里，得给人留点击时间，不能按机器速度算超时
            total_wait = max(wait, 90) if asked_uac else wait

        if wait_ready(spec.host, spec.port, name=name, timeout=total_wait, log=log):
            return TunnelResult(
                f"组网隧道 {name} 已连通（{spec.host}:{spec.port}）", started)
    finally:
        _cleanup(path)

    state = service_state(name)
    if state == "running":
        raise TunnelError(
            f"隧道 {name} 已经起来了，但 {spec.host}:{spec.port} 连不通。\n"
            "常见原因：服务器 SSH 只监听内网另一个地址、防护墙没放行、"
            "或者上面填的 IP 不是这台服务器的 VPN 地址。"
        )
    raise TunnelError(_fail_hint(name))


def start(name: str, conf_text: str, wait: int = 20,
          log=print) -> TunnelResult:
    """只建隧道，不管服务器 —— 组网页用的就是它。

    和 ``ensure_up`` 的区别：这里没有目标端口可探，所以"成功"的判据是
    **服务进入 RUNNING**。网卡地址、路由可能还差半秒，但对使用者来说
    "隧道连上了"就是这个意思。
    """
    name = normalize_name(name)
    if service_state(name) == "running":
        return TunnelResult(f"隧道 {name} 已经在运行", False)
    if not conf_text.strip():
        raise TunnelError("这条隧道没有可用的配置（配置丢了，重新导入一份）")
    if not client_path():
        raise TunnelError(
            "没有检测到 WireGuard 客户端。\n"
            "组网需要官方客户端提供内核驱动，请先安装后再试。"
        )
    # 没提权时 UAC 弹窗在用户手里，等待时间要按人算而不是按机器算
    asked_uac = not is_admin()
    path = ""
    try:
        log(f"正在建立隧道 {name} …")
        if asked_uac:
            log("即将弹出 Windows 权限确认，请点「是」，否则隧道建不起来。")
        path = install(name, conf_text, log)
        limit = max(5, wait, 90 if asked_uac else 0)
        deadline = time.monotonic() + limit
        last_note = 0.0
        while time.monotonic() < deadline:
            if service_state(name) == "running":
                return TunnelResult(f"组网隧道 {name} 已连接", True)
            now = time.monotonic()
            if asked_uac and now - last_note > 12:
                last_note = now
                log("还在等你点「是」（权限确认没点的话隧道起不来）…")
            time.sleep(0.5)
    finally:
        _cleanup(path)

    raise TunnelError(_fail_hint(name))


class TunnelStore:
    """本机隧道的配置仓库，落在 ``tunnels.json``。

    键是隧道名，值是 **DPAPI 加密后的整份 conf**。和 ``connections.json``
    分开存，是因为这两件事生命周期不同：服务器配置删了，隧道还该留着
    （别的地方可能正拿它上网）。

    为什么必须加密：conf 里有本机私钥，明文落盘等于把内网入口留在硬盘上。
    """

    def __init__(self, app_dir: str):
        self.path = os.path.join(app_dir, "tunnels.json")
        self._items: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for name, item in raw.items():
            if isinstance(item, dict) and isinstance(item.get("conf"), str):
                self._items[str(name)] = item

    def save(self) -> bool:
        try:
            with open(self.path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(self._items, f, ensure_ascii=False, indent=2)
            return True
        except OSError:
            return False

    def names(self) -> list[str]:
        return list(self._items)

    def all(self) -> list[dict]:
        """解密后的全部隧道，按名字排序。解不开的 conf 直接跳过。"""
        out = []
        for name in sorted(self._items):
            item = self._items[name]
            conf = unprotect(item.get("conf", ""))
            if not conf:
                continue
            out.append({
                "name": name,
                "conf": conf,
                "note": item.get("note", ""),
                "created": item.get("created", ""),
            })
        return out

    def get(self, name: str) -> str:
        """取某条隧道的明文 conf，没有或解不开就是空串。"""
        item = self._items.get(str(name or ""))
        if not item:
            return ""
        return unprotect(item.get("conf", ""))

    def put(self, name: str, conf_text: str, note: str = "") -> str:
        """新增/覆盖一条隧道，返回实际使用的名字（撞名会自动加序号）。"""
        sealed = protect(conf_text)
        if not sealed:
            raise TunnelError(
                "拿不到 Windows DPAPI，没法加密保存隧道配置。\n"
                "为了不把私钥明文写进磁盘，这次导入中止了。"
            )
        taken = list(self._items) + installed_tunnels()
        # 先把名字洗成合法隧道名再比对：否则传进来的 "office" 永远不等于
        # 已存的 "wgm-office"，同一条隧道会被重复加一份 -2
        final = normalize_name(name)
        if final not in self._items:
            final = unique_name(final, taken)
        self._items[final] = {
            "conf": sealed,
            "note": note,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.save()
        return final

    def drop(self, name: str) -> bool:
        if name not in self._items:
            return False
        self._items.pop(name, None)
        self.save()
        return True

    def rename(self, old: str, new: str) -> str:
        """改名（隧道名会给 Windows 服务用，改完要重新连接才生效）。"""
        if old not in self._items:
            raise TunnelError(f"没有这条隧道：{old}")
        item = self._items.pop(old)
        final = unique_name(new, list(self._items) + installed_tunnels())
        self._items[final] = item
        self.save()
        return final


# ------------------------------------------------------------ 实时流量与详情
# 界面上的"实时网速"有两个数据源，按可靠性排序：
#
# 1. ``wg show <名字> dump`` —— 有握手时间、每个 peer 的收发字节，最完整。
#    但它走命名管道，服务没起或权限不够时直接失败（返回码非 0）。
# 2. ``GetIfTable2`` 读虚拟网卡的字节计数 —— 不需要任何权限，一定有数，
#    但没有握手信息，也分不出是哪个 peer。
#
# 所以界面上用 2 保证"总是有数"，1 只是锦上添花。两者都是纯只读，
# 不会改动配置、不会碰服务器。

_IF_API = None


def _if_api():
    """按需构建 ctypes 结构。必须在模块级缓存 ——

    每次重建 MIB_IF_ROW2 类都会让已设好的 argtypes 与新类的类型不符，
    ctypes 会静默传错指针（踩过一次，症状是乱码 alias）。
    """
    global _IF_API
    if _IF_API is not None:
        return _IF_API

    import ctypes
    from ctypes import wintypes

    class MIB_IF_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", wintypes.DWORD),
            ("InterfaceGuid", ctypes.c_ubyte * 16),
            ("Alias", wintypes.WCHAR * 257),
            ("Description", wintypes.WCHAR * 257),
            ("PhysicalAddressLength", wintypes.ULONG),
            ("PhysicalAddress", ctypes.c_ubyte * 32),
            ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
            ("Mtu", wintypes.ULONG),
            ("Type", wintypes.ULONG),
            ("TunnelType", wintypes.ULONG),
            ("MediaType", wintypes.ULONG),
            ("PhysicalMediumType", wintypes.ULONG),
            ("AccessType", wintypes.ULONG),
            ("DirectionType", wintypes.ULONG),
            ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
            ("OperStatus", wintypes.ULONG),
            ("AdminStatus", wintypes.ULONG),
            ("MediaConnectState", wintypes.ULONG),
            ("NetworkGuid", ctypes.c_ubyte * 16),
            ("ConnectionType", wintypes.ULONG),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("InOctets", ctypes.c_uint64),
            ("InUcastPkts", ctypes.c_uint64),
            ("InNUcastPkts", ctypes.c_uint64),
            ("InDiscards", ctypes.c_uint64),
            ("InErrors", ctypes.c_uint64),
            ("InUnknownProtos", ctypes.c_uint64),
            ("InUcastOctets", ctypes.c_uint64),
            ("InMulticastOctets", ctypes.c_uint64),
            ("InBroadcastOctets", ctypes.c_uint64),
            ("OutOctets", ctypes.c_uint64),
            ("OutUcastPkts", ctypes.c_uint64),
            ("OutNUcastPkts", ctypes.c_uint64),
            ("OutDiscards", ctypes.c_uint64),
            ("OutErrors", ctypes.c_uint64),
            ("OutUcastOctets", ctypes.c_uint64),
            ("OutMulticastOctets", ctypes.c_uint64),
            ("OutBroadcastOctets", ctypes.c_uint64),
            ("OutQLen", ctypes.c_uint64),
        ]

    class MIB_IF_TABLE2(ctypes.Structure):
        _fields_ = [("NumEntries", wintypes.ULONG),
                    ("Table", MIB_IF_ROW2 * 1)]

    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.POINTER(MIB_IF_TABLE2))]
    api.GetIfTable2.restype = wintypes.DWORD
    api.FreeMibTable.argtypes = [ctypes.c_void_p]
    api.FreeMibTable.restype = None
    _IF_API = (ctypes, MIB_IF_ROW2, MIB_IF_TABLE2, api)
    return _IF_API


def if_counters() -> dict[str, tuple[int, int, int]]:
    """{网卡别名小写: (接收字节, 发送字节, 操作状态)}，一次调用拿全部。

    别名就是 WireGuard 隧道名（客户端建的、我们建的都一样），所以可以直接
    按隧道名对。返回空 dict 表示这台机器上读不到（非 Windows 或 API 异常），
    界面据此把速率列显示成「—」，不是错误。
    """
    if sys.platform != "win32":
        return {}
    try:
        ctypes, _row_t, table_t, api = _if_api()
        ptr = ctypes.POINTER(table_t)()
        if api.GetIfTable2(ctypes.byref(ptr)) != 0:
            return {}
        try:
            count = int(ptr.contents.NumEntries)
            if count <= 0:
                return {}
            # Table 声明成 1 元素的数组（C 里的柔性数组），实际有 count 行，
            # 所以按 count 重新圈一块内存再读
            row_t = table_t._fields_[1][1]._type_
            rows = ctypes.cast(ctypes.byref(ptr.contents.Table),
                               ctypes.POINTER(row_t * count)).contents
            out: dict[str, tuple[int, int, int]] = {}
            for row in rows:
                alias = str(row.Alias or "")
                if not alias:
                    continue
                out[alias.lower()] = (int(row.InOctets), int(row.OutOctets),
                                      int(row.OperStatus))
            return out
        finally:
            api.FreeMibTable(ptr)
    except Exception:
        return {}


def iface_counters(name: str) -> tuple[int, int] | None:
    """某条隧道虚拟网卡的 (接收, 发送) 累计字节。没这块网卡就是 None。"""
    if not name:
        return None
    hit = if_counters().get(name.strip().lower())
    return (hit[0], hit[1]) if hit else None


def wg_path() -> str:
    """wg.exe，和 wireguard.exe 在同一个目录。找不到是空串。"""
    exe = client_path()
    if not exe:
        return ""
    cand = os.path.join(os.path.dirname(exe), "wg.exe")
    return cand if os.path.isfile(cand) else ""


def parse_wg_dump(text: str) -> dict:
    """解析 ``wg show <名字> dump``。

    格式（制表符分隔）：
        第一行：私钥 / 本机公钥 / 监听端口 / fwmark
        之后每行一个 peer：公钥 / 预共享密钥 / 对端 / 允许的IP / 最近握手 /
                          接收字节 / 发送字节 / 保活间隔

    握手时间是 unix 秒，0 表示"还没握过手"（隧道起着但对面没回应）。
    解析失败就返回空 dict，界面回落到只看累计字节。
    """
    lines = [ln for ln in (text or "").replace("\r", "").split("\n") if ln.strip()]
    if not lines:
        return {}
    first = lines[0].split("\t")
    if len(first) < 4:
        return {}
    out: dict = {
        "public_key": first[1].strip(),
        "listen_port": int(first[2]) if first[2].strip().isdigit() else 0,
        "peers": [],
    }
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        try:
            handshake = int(parts[4] or 0)
        except ValueError:
            handshake = 0
        out["peers"].append({
            "public_key": parts[0].strip(),
            "preshared": parts[1].strip() not in ("", "(none)"),
            "endpoint": parts[2].strip(),
            "allowed": parts[3].strip(),
            "handshake": handshake,
            "rx": int(parts[5] or 0),
            "tx": int(parts[6] or 0),
            "keepalive": parts[7].strip(),
        })
    return out


def wg_dump(name: str, timeout: float = 3.0) -> dict:
    """读一条隧道的运行状态。读不到就返回空 dict —— 调用方别当成错误。"""
    wg = wg_path()
    if not wg or not name:
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run([wg, "show", name, "dump"], capture_output=True,
                              timeout=timeout, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if proc.returncode != 0:
        return {}
    return parse_wg_dump((proc.stdout or b"").decode("utf-8", "replace"))


def conf_detail(text: str) -> dict:
    """把 conf 摊成详情面板要显示的字段。解不开的项是空串。"""
    fields = _conf_fields(text or "")
    iface, peer = fields["interface"], fields["peer"]
    return {
        "address": iface.get("address", ""),
        "dns": iface.get("dns", ""),
        "listen_port": iface.get("listenport", ""),
        "endpoint": peer.get("endpoint", ""),
        "allowed": peer.get("allowedips", ""),
        "keepalive": peer.get("persistentkeepalive", ""),
        "preshared": bool(peer.get("presharedkey")),
        "peer_key": peer.get("publickey", ""),
    }


def short_key(key: str, head: int = 8, tail: int = 6) -> str:
    """公钥太长，列表里只显示头尾，中间省略。"""
    key = (key or "").strip()
    if len(key) <= head + tail + 1:
        return key
    return f"{key[:head]}…{key[-tail:]}"
