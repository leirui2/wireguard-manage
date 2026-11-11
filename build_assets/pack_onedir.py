"""把目录版打成一个 zip：解压即用，不需要安装。

中文路径不写在 bat 里 —— bat 必须保持纯 ASCII（历史教训：含中文的 bat
在 GBK/UTF-8 之间会读错路径），所以文件夹名和 zip 名都在这里写死。
"""
from __future__ import annotations

import os
import sys
import zipfile

FOLDER_NAME = "WireGuard管理台"
ZIP_NAME = "WireGuard管理台-目录版.zip"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main() -> int:
    dist = os.path.join(ROOT, "dist")
    src = os.path.join(dist, FOLDER_NAME)
    if not os.path.isdir(src):
        print(f"[ERROR] 找不到目录版产物：{src}")
        return 1
    exe = os.path.join(src, FOLDER_NAME + ".exe")
    if not os.path.isfile(exe):
        print(f"[ERROR] 目录里没有主程序：{exe}")
        return 1

    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(dist, ZIP_NAME)
    out = os.path.abspath(out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        os.remove(out)

    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, dist)
                z.write(full, rel)
                count += 1

    size = os.path.getsize(out) / 1048576
    print(f"[OK] {os.path.basename(out)}  {count} 个文件  {size:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
