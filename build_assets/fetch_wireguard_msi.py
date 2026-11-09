"""下载官方 WireGuard for Windows 安装包，校验签名后存进 build_assets\\。

为什么要单独一步：安装包里可选地带上官方客户端，省得用户自己去官网找。
但官网 `download.wireguard.com` 在国内部分网络会被 DNS 污染（本机实测解析到
境外黑洞地址，连不上），所以这一步必须是"失败也不影响打包"的软步骤。

    python build_assets/fetch_wireguard_msi.py
    python build_assets/fetch_wireguard_msi.py 0.5.3        # 指定版本
    python build_assets/fetch_wireguard_msi.py --url https://.../wireguard-amd64-x.msi

拿到文件后的可信度判据不是"从哪下的"，而是 **Authenticode 签名**：
签名链有效且签发给 WireGuard LLC 才留下，否则直接删掉。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

# GitHub Actions 的 Windows runner 控制台默认 cp1252，本文件里的中文 print
# 会直接抛 UnicodeEncodeError。这一步是 continue-on-error 的软步骤，崩了会被
# 静默跳过 → 安装包莫名少了「同时装客户端」选项，很难看出原因。
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build_assets")
BASE = "https://download.wireguard.com/windows-client/wireguard-amd64-{}.msi"

# 从新到旧试；新版本发布后在这里补一行即可
CANDIDATES = ["1.1.1", "1.1", "1.0.1", "1.0", "0.6.1", "0.6", "0.5.3"]

# 已知版本的官方 SHA256（取自 microsoft/winget-pkgs 的安装清单，那是微软收录时
# 按官方文件算的）。对得上的文件就是官方原件，从哪个镜像拿到都无所谓；
# 对不上直接删。没收录的版本退回只看 Authenticode 签名。
KNOWN_SHA256 = {
    "1.1.1": "7BFED60AD61B785C914B38B61555A975488E1D3EC472DBFB2FCDF498FCA75242",
}


def sha256_of(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def verify(path: str) -> tuple[bool, str]:
    """哈希（有官方值时必须对上）+ Authenticode 签名，两道都过才留下。"""
    name = os.path.basename(path)
    version = ""
    if name.startswith("wireguard-amd64-") and name.endswith(".msi"):
        version = name[len("wireguard-amd64-"):-len(".msi")]
    expect = KNOWN_SHA256.get(version)
    if expect:
        got = sha256_of(path)
        if got != expect:
            return False, f"SHA256 对不上官方值\n  实际 {got}\n  官方 {expect}"
    ok, detail = signature_ok(path)
    if not ok:
        return False, detail
    tail = "，SHA256 与官方一致" if expect else "（该版本无官方哈希可比对）"
    return True, detail + tail


def signature_ok(path: str) -> tuple[bool, str]:
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath "
        f"'{path}'; "
        "$s.Status; "
        "if ($s.SignerCertificate) { $s.SignerCertificate.Subject }"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"校验调用失败：{exc}"
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    status = lines[0] if lines else "(空)"
    subject = lines[1] if len(lines) > 1 else ""
    return (status == "Valid" and "wireguard" in subject.lower()), f"{status} · {subject}"


def proxy_candidates() -> list[str | None]:
    """要试的代理，按可能性排序。

    这台机器的环境变量里有一个代理（可能没开），Windows 的"Internet 选项"里
    还有一个（实际能用的往往是这个）。所以两边都试，最后再试直连。
    """
    found: list[str | None] = []
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(key)
        if val and val not in found:
            found.append(val)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            if winreg.QueryValueEx(k, "ProxyEnable")[0]:
                server = winreg.QueryValueEx(k, "ProxyServer")[0]
                if server and server not in found:
                    found.append(server if "://" in server else "http://" + server)
    except OSError:
        pass
    found.append(None)
    return found


def download(url: str, dest: str) -> bool:
    for proxy in proxy_candidates():
        label = proxy or "直连"
        print(f"[..] {url}  （{label}）")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({} if proxy is None else
                                        {"http": proxy, "https": proxy})
        )
        try:
            with opener.open(url, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length") or 0)
                tmp = dest + ".part"
                got = 0
                with open(tmp, "wb") as fh:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        fh.write(chunk)
                        got += len(chunk)
                if total and got != total:
                    os.remove(tmp)
                    print(f"[WARN] 下载不完整 {got}/{total} 字节")
                    continue
                os.replace(tmp, dest)
                print(f"      {got / 1048576:.1f} MB")
                return True
        except (urllib.error.URLError, OSError) as exc:
            print(f"[WARN] 失败：{exc}")
    return False


def main(argv: list[str]) -> int:
    url = ""
    versions = list(CANDIDATES)
    if "--url" in argv:
        url = argv[argv.index("--url") + 1]
    elif argv and not argv[0].startswith("-"):
        versions = [argv[0]]

    targets = [url] if url else [BASE.format(v) for v in versions]
    for target in targets:
        name = os.path.basename(target) or "wireguard-amd64.msi"
        if not name.endswith(".msi"):
            name = "wireguard-amd64.msi"
        dest = os.path.join(BUILD, name)
        if os.path.isfile(dest) and os.path.getsize(dest) > 1_000_000:
            ok, detail = verify(dest)
            if ok:
                print(f"[OK] 已存在且校验通过：{name}")
                print(f"     {detail}")
                return 0
            print(f"[WARN] 已存在的 {name} 校验没过，重新下载（{detail}）")
            keep = dest + ".rejected"
            os.replace(dest, keep)
            print(f"       旧文件已改名为 {os.path.basename(keep)}，确认无用后可删")

        tmpdir = tempfile.mkdtemp(prefix="wgm-msi-")
        probe = os.path.join(tmpdir, name)
        if not download(target, probe):
            continue

        ok, detail = verify(probe)
        if not ok:
            print(f"[WARN] 校验没过，丢弃（{detail}）")
            os.remove(probe)
            continue
        os.replace(probe, dest)
        print(f"[OK] {name}  {os.path.getsize(dest) / 1048576:.1f} MB")
        print(f"     {detail}")
        return 0

    print()
    print("[ERROR] 没拿到可用的安装包。")
    print("        国内网络常见原因：download.wireguard.com 被 DNS 污染 / 直连被重置。")
    print("        三个办法：")
    print("          1) 开代理再跑一次（脚本会自动读系统代理和 HTTP(S)_PROXY 环境变量）")
    print("          2) 浏览器里手动下载 wireguard-amd64-<版本>.msi，放进 build_assets\\")
    print("          3) 有 VPN 的话先连上再跑")
    print("        没有这个文件也能打包，只是安装包里少了「同时安装客户端」选项。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
