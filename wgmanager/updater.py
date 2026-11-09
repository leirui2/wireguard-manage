"""检查更新 + 自我替换。

更新源固定为本项目的 GitHub Releases —— 和 CI 发布的是同一个地方，不读任何
外部配置。这样即使有人在配置文件里动手脚，也改不掉下载地址。

四条硬规矩：

1. **只允许从 github.com / objects.githubusercontent.com 下载**，其他域名一律拒绝；
2. **下载后必须核对 SHA256**（release 里附带的 SHA256.txt），对不上就地删掉；
3. **替换自己必须靠外部进程** —— Windows 不允许覆盖正在运行的 exe，
   所以生成一个 .bat，主程序退出后由它接管：等文件解锁 -> 覆盖 -> 启动新版；
4. **失败可回退**：新文件下到 updates/ 而不是直接动原文件，
   覆盖失败时原 exe 还在，用户手动点一下就能继续用旧版。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__

REPO = "leirui2/wireguard-manage"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
ASSET_EXE = "WireGuardManager.exe"
ASSET_SHA = "SHA256.txt"
ASSET_VERSION = "version.txt"

#: 允许下载的域名，热更新最怕被改成任意下载器
ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com", "api.github.com"}

USER_AGENT = f"WireGuardManager/{__version__} (+https://github.com/{REPO})"


class UpdateError(RuntimeError):
    pass


@dataclass
class Latest:
    version: str = ""
    notes: str = ""
    size: int = 0
    exe_url: str = ""
    sha_url: str = ""
    page_url: str = RELEASES_PAGE


# ------------------------------------------------------------------ 版本比较

def parse_version(text: str) -> tuple[int, ...]:
    """"v1.0.10" / "1.0.10" / "最新构建 v1.0.10" 都能解析出 (1, 0, 10)。"""
    match = re.search(r"(\d+(?:\.\d+)*)", text or "")
    if not match:
        return ()
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return ()


def is_newer(remote: str, local: str = "") -> bool:
    remote_parts = parse_version(remote)
    local_parts = parse_version(local or __version__)
    if not remote_parts:
        return False
    # 补齐长度再逐段比，避免 (1,0,10) 和 (1,0,9) 因为长度不同误判
    width = max(len(remote_parts), len(local_parts))
    a = remote_parts + (0,) * (width - len(remote_parts))
    b = local_parts + (0,) * (width - len(local_parts))
    return a > b


def normalize_version(text: str) -> str:
    """"最新构建 v1.0.10" -> "1.0.10"。

    release 标题是人写的，直接拿来显示会变成「发现新版本 v最新构建 v1.0.10」。
    """
    parts = parse_version(text)
    return ".".join(str(part) for part in parts) if parts else ""


def release_line(version: str, keep: int = 3) -> str:
    """取版本号里的「发布线」，丢掉 CI 追加的构建号。

    ``1.0.17.16`` → ``1.0.17``。CI 每次 push 都会在基线后面追加构建号
    （见 .github/workflows/build.yml），如果检查更新按完整号比较，
    本地打出来的包永远比线上"少一位"，于是天天提示有新版本 —— 但实际上
    两边可能是同一份代码。

    所以只在发布线变化时才提示：1.0.17.x → 1.0.18 会提示，
    1.0.17.16 → 1.0.17.17 不提示（只是同一版本的又一次构建）。
    """
    parts = parse_version(version)[:keep]
    return ".".join(str(part) for part in parts) if parts else ""


# ------------------------------------------------------------------ 查询

def _check_host(url: str) -> None:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise UpdateError(f"拒绝从非官方域名下载：{host or url}")


def _get(url: str, timeout: int = 10) -> bytes:
    _check_host(url)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json, application/octet-stream",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_latest(timeout: int = 10) -> Latest:
    """读 GitHub 上的最新发行版信息。只读，不下载 exe。"""
    try:
        raw = _get(API_LATEST, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError("仓库或发行版不存在（可能还没发布过）") from exc
        if exc.code == 403:
            raise UpdateError("GitHub 接口限流了，过几分钟再试") from exc
        raise UpdateError(f"GitHub 返回 HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise UpdateError(f"连不上 GitHub：{exc.reason}") from exc
    except TimeoutError as exc:
        raise UpdateError("连接 GitHub 超时，检查网络或代理") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise UpdateError("GitHub 返回的内容看不懂，可能是网络被劫持") from exc

    latest = Latest(page_url=data.get("html_url") or RELEASES_PAGE)
    latest.notes = (data.get("body") or "").strip()

    assets = {item.get("name"): item for item in data.get("assets") or []}
    exe = assets.get(ASSET_EXE)
    if not exe:
        raise UpdateError(f"这个发行版里没有 {ASSET_EXE} 资产")
    latest.exe_url = exe.get("browser_download_url") or ""
    latest.size = int(exe.get("size") or 0)
    if assets.get(ASSET_SHA):
        latest.sha_url = assets[ASSET_SHA].get("browser_download_url") or ""

    # 版本号优先读 version.txt（最准），读不到再从 release 标题里抠
    if assets.get(ASSET_VERSION):
        try:
            latest.version = _get(
                assets[ASSET_VERSION]["browser_download_url"], timeout=timeout
            ).decode("utf-8", "replace").strip()
        except Exception:
            latest.version = ""
    if not latest.version:
        latest.version = (data.get("name") or data.get("tag_name") or "").strip()
    latest.version = normalize_version(latest.version)
    if not latest.version:
        raise UpdateError("认不出最新版本的版本号")
    return latest


# ------------------------------------------------------------------ 下载

def download(url: str, dest: str, expected_sha: str = "",
             progress=None, timeout: int = 30) -> str:
    """下载到 dest，返回实际 SHA256（大写）。校验不过会删掉文件并抛错。"""
    _check_host(url)
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    done = 0
    tmp = dest + ".part"

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            with open(tmp, "wb") as fh:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    digest.update(chunk)
                    done += len(chunk)
                    if progress and total:
                        progress(min(100, done * 100 // total), done, total)
        os.replace(tmp, dest)
    except Exception:
        # 断网、超时都会留下半截文件，下次下载前先清掉
        if os.path.isfile(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise

    actual = digest.hexdigest().upper()
    if expected_sha:
        if actual != expected_sha.strip().upper():
            try:
                os.remove(dest)
            except OSError:
                pass
            raise UpdateError(
                "下载文件的 SHA256 和官方记录对不上，已丢弃。\n"
                f"  期望：{expected_sha.strip().upper()}\n"
                f"  实际：{actual}"
            )
    return actual


def fetch_sha(latest: Latest, timeout: int = 10) -> str:
    """取官方 SHA256.txt 里的第一段十六进制。取不到就返回空（跳过校验）。"""
    if not latest.sha_url:
        return ""
    try:
        text = _get(latest.sha_url, timeout=timeout).decode("utf-8", "replace")
    except Exception:
        return ""
    match = re.search(r"\b([0-9A-Fa-f]{64})\b", text)
    return match.group(1).upper() if match else ""


# ------------------------------------------------------------------ 应用

UPDATE_DIR = "updates"

_WRAPPER = r"""@echo off
set "NEW=%WGMGR_NEW%"
set "OLD=%WGMGR_OLD%"
rem cmd 的 copy / start 都不认正斜杠路径，这里统一换成反斜杠
set "NEW=%NEW:/=\%"
set "OLD=%OLD:/=\%"
if not exist "%NEW%" goto failed
set /a tries=0
:wait
ping -n 2 127.0.0.1 >nul
copy /y "%NEW%" "%OLD%" >nul 2>&1
if not errorlevel 1 goto done
set /a tries+=1
if %tries% geq 30 goto failed
goto wait
:done
start "" "%OLD%"
del "%NEW%" >nul 2>&1
(goto) 2>nul & del "%~f0"
:failed
echo copy failed > "%~dp0update-error.txt"
(goto) 2>nul & del "%~f0"
"""


def exe_path() -> str:
    """当前正在运行的 exe（源码模式下返回空）。"""
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)
    return ""


def is_portable() -> bool:
    """当前跑的是不是「目录布局」（安装版就是这种）。

    两种打包形态的自更新方式不一样，必须分清楚：

    * 单文件（onefile）：程序就是一个 exe，下载新的盖掉旧的即可。
    * 目录布局（onedir，即安装版）：exe 旁边有个 ``_internal`` 目录，程序运行期间
      那些 DLL 全被占用、盖不掉，所以不能在程序内替换 —— 引导用户下载新的
      安装包覆盖安装。用 ``_internal`` 是否存在来判断，比看解压路径可靠
      （onefile 的 ``sys._MEIPASS`` 在 %TEMP%，目录布局的就在 exe 旁边）。
    """
    if not getattr(sys, "frozen", False):
        return False
    return os.path.isdir(
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "_internal"))


def update_dir(app_dir: str) -> str:
    path = os.path.join(app_dir, UPDATE_DIR)
    os.makedirs(path, exist_ok=True)
    return path


def apply_update(new_exe: str, old_exe: str, work_dir: str) -> str:
    """生成替身脚本并启动它，返回脚本路径。调用方随后应立即退出程序。"""
    if not os.path.isfile(new_exe):
        raise UpdateError("下载的新版本不见了，请重新检查更新")
    if not old_exe:
        raise UpdateError("当前不是以 exe 方式运行，没法自我替换")

    script = os.path.join(work_dir, "_apply_update.bat")
    with open(script, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(_WRAPPER)

    err_file = os.path.join(work_dir, "update-error.txt")
    if os.path.isfile(err_file):
        try:
            os.remove(err_file)
        except OSError:
            pass

    env = os.environ.copy()
    # normpath 把正斜杠转成反斜杠：cmd 的 copy 只认 Windows 风格路径
    env["WGMGR_NEW"] = os.path.normpath(os.path.abspath(new_exe))
    env["WGMGR_OLD"] = os.path.normpath(os.path.abspath(old_exe))

    subprocess.Popen(
        ["cmd.exe", "/c", script],
        creationflags=0x08000000,   # CREATE_NO_WINDOW，别闪黑框
        close_fds=True,
        env=env,
        cwd=work_dir,
    )
    return script


def pending_update(work_dir: str) -> str:
    """上次更新没成功时，这里会留下一个 update-error.txt。"""
    path = os.path.join(work_dir, "update-error.txt")
    return path if os.path.isfile(path) else ""


def cleanup_stale(work_dir: str, keep: str = "") -> None:
    """清掉以前下载的旧包，别让 updates 目录越积越大。"""
    try:
        for name in os.listdir(work_dir):
            if not name.lower().endswith(".exe"):
                continue
            full = os.path.join(work_dir, name)
            if keep and os.path.abspath(full) == os.path.abspath(keep):
                continue
            try:
                os.remove(full)
            except OSError:
                pass
    except OSError:
        pass
