"""生成启动画面 splash.png（打包时用，不参与运行时）。

单文件 exe 每次启动要先把 49 MB 解压到 %TEMP%，这段时间里窗口还不存在，
双击后像「没反应」。PyInstaller 的 splash 是**引导程序**画的，解压开始之前
就显示，所以能立刻给用户一个反馈。

标题和版本号写进图里，所以每次打包都要重新生成 —— 由 打包exe.bat 调用。
"""
from __future__ import annotations

import os
import re
import sys

W, H = 460, 250
BG = "#ffffff"
TITLE = "#1a1a1a"
GREY = "#6b6b6b"
FAINT = "#9a9a9a"
ACCENT = "#0f6e56"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def current_version() -> str:
    try:
        with open(os.path.join(ROOT, "wgmanager", "__init__.py"),
                  encoding="utf-8") as f:
            hit = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
        return hit.group(1) if hit else ""
    except OSError:
        return ""


def _font(size: int, bold: bool = False):
    from PIL import ImageFont

    for name in (("msyhbd.ttc" if bold else "msyh.ttc"), "msyh.ttc", "simhei.ttf"):
        path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", name)
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def main() -> int:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # 顶部一条强调色，和主界面「已连接」的绿色一致
    d.rectangle([0, 0, W, 4], fill=ACCENT)

    # 图标：app.ico 里挑最大的一帧，没有就画个圆角方块顶上
    icon_path = os.path.join(HERE, "app.ico")
    icon = None
    if os.path.isfile(icon_path):
        try:
            ico = Image.open(icon_path)
            best = max(ico.info.get("sizes", [(0, 0)]))
            ico.size = best
            icon = ico.convert("RGBA").resize((64, 64))
        except Exception:
            icon = None
    if icon is not None:
        img.paste(icon, (34, 40), icon)
    else:
        d.rounded_rectangle([34, 40, 98, 104], radius=14, fill=ACCENT)

    d.text((114, 42), "WireGuard 管理台", font=_font(23, bold=True), fill=TITLE)
    version = current_version()
    if version:
        d.text((117, 76), f"v{version}", font=_font(12), fill=FAINT)

    d.line([34, 132, W - 34, 132], fill="#e6e6e6")

    # 这一行是给"点了没反应"一个解释，别看翻译腔
    d.text((34, 152), "正在启动…", font=_font(14), fill=GREY)
    d.text((34, 180), "首次启动要把运行库解压到临时目录，需要几秒钟",
           font=_font(11), fill=FAINT)
    d.text((34, 200), "之后就快了。这个窗口会自动消失。",
           font=_font(11), fill=FAINT)

    out = os.path.join(HERE, "splash.png")
    img.save(out)
    print(f"splash: {out} ({W}x{H}, v{version or '?'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
