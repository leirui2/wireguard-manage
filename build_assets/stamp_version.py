"""把版本号写进源码和 exe 资源。

本地打包与 GitHub Actions 共用这一份逻辑，避免两边规则不一致 ——
比如 CI 打出来是 1.0.11、本地还留 1.0.0，用户点「检查更新」就会永远
被告知有新版本。

写入三处：

* `wgmanager/__init__.py` 的 `__version__`（程序里读的就是它）
* `build_assets/version_info.txt`（exe 右键属性里的版本）
* `version.txt`（随发行版一起上传，客户端用它判断版本，比从标题抠字符串可靠）

用法：
    python build_assets/stamp_version.py 1.0.12
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# GitHub Actions 的 Windows runner 控制台默认 cp1252，中文输出会抛
# UnicodeEncodeError（SystemExit 里的中文报错同样会炸），统一转 UTF-8。
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

VERSION_RE = re.compile(r"\d+(\.\d+){0,3}")


def stamp(version: str) -> str:
    version = (version or "").strip().lstrip("vV")
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"版本号格式不对：{version!r}（应该像 1.0.12 这样）")

    init = ROOT / "wgmanager" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    new_text, count = re.subn(
        r'__version__\s*=\s*"[^"]*"', f'__version__ = "{version}"', text
    )
    if count != 1:
        raise SystemExit(f"{init} 里找不到唯一的 __version__ 赋值")
    init.write_text(new_text, encoding="utf-8", newline="\n")

    quad = ", ".join((version.split(".") + ["0", "0", "0"])[:4])
    # PE 的 FileVersion 只接受 4 段数字。三段号（1.0.16）补成 1.0.16.0；
    # 四段号（CI 出的 1.0.16.14）必须原样用，再补一个 .0 就成 5 段，PyInstaller 会报错。
    file_ver = version if len(version.split(".")) >= 4 else version + ".0"
    info = ROOT / "build_assets" / "version_info.txt"
    info_text = info.read_text(encoding="utf-8")
    info_text = re.sub(r"filevers=\([^)]*\)", f"filevers=({quad})", info_text)
    info_text = re.sub(r"prodvers=\([^)]*\)", f"prodvers=({quad})", info_text)
    info_text = re.sub(
        r"StringStruct\('FileVersion', '[^']*'\)",
        f"StringStruct('FileVersion', '{file_ver}')", info_text,
    )
    info_text = re.sub(
        r"StringStruct\('ProductVersion', '[^']*'\)",
        f"StringStruct('ProductVersion', '{file_ver}')", info_text,
    )
    info.write_text(info_text, encoding="utf-8", newline="\n")

    (ROOT / "version.txt").write_text(version + "\n", encoding="utf-8", newline="\n")
    print(f"stamped version {version}")
    return version


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    stamp(sys.argv[1])
