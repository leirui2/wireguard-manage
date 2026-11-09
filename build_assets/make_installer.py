"""把目录版打成 Windows 安装包（Inno Setup 6）。

用法（由 打包exe.bat 调用，也可以单独跑）：

    python build_assets/make_installer.py            # 版本号读 version.txt
    python build_assets/make_installer.py 1.0.24     # 指定版本号
    python build_assets/make_installer.py --force    # 跳过 msi 签名校验

前置条件：
  * `build\\installer-src\\WireGuard管理台\\` 里已经有目录版产物
    （`打包exe.bat` 会先用 onedir spec 编到这里；单独跑本脚本前要先编一次）
  * 装过 Inno Setup 6（`winget install JRSoftware.InnoSetup`）
  * 可选：`build_assets\\wireguard-amd64-*.msi` 存在时会打进去当可选项

为什么用目录版布局做安装包：装完之后文件位置固定，启动 1 秒；单文件每次启动
还要自解压到临时目录，装了也没意义。目录版只是这里的中间产物，不对外发布。
"""

from __future__ import annotations

import glob
import hashlib
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build_assets")
DIST = os.path.join(ROOT, "dist")
# 安装包的"料"是目录版（onedir）布局：装完启动 1 秒，不用每次自解压。
# 但它不再是发行产物 —— 只落在 build\installer-src 里，给 Inno 做输入。
SRC_DIR = os.path.join(ROOT, "build", "installer-src", "WireGuard管理台")
ISS = os.path.join(BUILD, "wireguard-manager.iss")


def find_iscc() -> str:
    """找 Inno Setup 的命令行编译器。找不到返回空串。"""
    found = shutil.which("iscc") or shutil.which("ISCC")
    if found:
        return found
    env = os.environ
    candidates = [
        os.path.join(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     "Inno Setup 6", "ISCC.exe"),
        os.path.join(env.get("ProgramFiles", r"C:\Program Files"),
                     "Inno Setup 6", "ISCC.exe"),
        os.path.join(env.get("LOCALAPPDATA", ""),
                     "Programs", "Inno Setup 6", "ISCC.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def app_version(argv: list[str]) -> str:
    for arg in argv:
        if arg and arg[0].isdigit():
            return arg
    path = os.path.join(ROOT, "version.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read().strip()
        return text or "0.0.0"
    except OSError:
        return "0.0.0"


def find_msi() -> str:
    hits = sorted(glob.glob(os.path.join(BUILD, "wireguard-amd64-*.msi")))
    return hits[-1] if hits else ""


def msi_signature(path: str) -> tuple[bool, str]:
    """用 Windows 自己的 Authenticode 校验 msi。

    装的是内核驱动，不能只信"文件是从哪下的"。签名链有效且签发给
    WireGuard LLC 才算数 —— 这样从哪个镜像拿到的都无所谓。
    """
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath "
        f"'{path}'; "
        "$s.Status; "
        "if ($s.SignerCertificate) { $s.SignerCertificate.Subject }"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"调用签名校验失败：{exc}"
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    status = lines[0] if lines else "(空)"
    subject = lines[1] if len(lines) > 1 else ""
    ok = status == "Valid" and "wireguard" in subject.lower()
    return ok, f"{status} · {subject or '无签名者信息'}"


def main(argv: list[str]) -> int:
    force = "--force" in argv
    version = app_version(argv)
    # --out=WireGuardManager-setup 用于 CI：发行版资产必须是纯 ASCII 名
    out_name = next((a.split("=", 1)[1] for a in argv if a.startswith("--out=")), "")

    if not os.path.isdir(SRC_DIR):
        print(f"[ERROR] 找不到安装包的源目录：{SRC_DIR}")
        print("        先跑一次目录版构建（打包exe.bat 会自动做这一步）：")
        print("        .build-venv\\Scripts\\python.exe -m PyInstaller --clean "
              "--distpath build\\installer-src wireguard-manager-onedir.spec")
        return 2

    iscc = find_iscc()
    if not iscc:
        print("[ERROR] 没装 Inno Setup 6，装一次就行：")
        print("        winget install JRSoftware.InnoSetup")
        return 2

    defines = [
        f"/DMyVersion={version}",
        f"/DSourceDir={SRC_DIR}",
    ]
    if out_name:
        defines.append(f"/DOutName={out_name}")

    lang = os.path.join(BUILD, "ChineseSimplified.isl")
    if os.path.isfile(lang):
        defines.append("/DUseZH=1")
        defines.append(f"/DZhFile={lang}")
    else:
        defines.append("/DUseZH=0")
        print("[WARN] 缺 build_assets\\ChineseSimplified.isl，安装向导会是英文的")

    msi = find_msi()
    if msi:
        ok, detail = msi_signature(msi)
        if ok:
            defines.append("/DHasWGMSI=1")
            defines.append(f"/DWGMsiPath={msi}")
            size = os.path.getsize(msi) / 1048576
            print(f"[OK] 带上官方客户端：{os.path.basename(msi)}  {size:.1f} MB")
            print(f"     签名：{detail}")
        elif force:
            defines.append("/DHasWGMSI=1")
            defines.append(f"/DWGMsiPath={msi}")
            print(f"[WARN] --force：签名校验没过，仍然打包（{detail}）")
        else:
            print(f"[WARN] 客户端安装包签名校验没过，不打包进去（{detail}）")
            print("       确认来源可靠的话加 --force 跳过校验")
    else:
        print("[INFO] build_assets 里没有 wireguard-amd64-*.msi，安装包不含客户端选项")

    cmd = [iscc, "/Q", *defines, ISS]
    print("[..] 调用 Inno Setup 编译…")
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        print("[ERROR] 编译失败：")
        print((proc.stdout or "") + (proc.stderr or ""))
        return proc.returncode

    out = os.path.join(
        DIST, (out_name or f"WireGuard管理台-安装包-{version}") + ".exe"
    )
    if not os.path.isfile(out):
        print(f"[ERROR] 编译看似成功，但没找到 {out}")
        return 3

    size = os.path.getsize(out) / 1048576
    with open(out, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    print(f"[OK] {os.path.basename(out)}  {size:.1f} MB")
    print(f"     SHA256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
