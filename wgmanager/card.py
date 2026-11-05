"""把一份客户端配置渲染成一张可以直接发微信的图片卡片。

为什么不直接发 .conf
--------------------

收配置的人多半不熟 WireGuard：发一个 .conf 过去，对方还得知道存到哪、怎么导入。
一张图里带上二维码、服务器地址、备注和一句导入说明，扫一下就完事。

为什么需要 Pillow
-----------------

``segno`` 只会画二维码，画不了文字。要让二维码和说明文字在同一张图上，
必须有字体渲染 —— 这是 Pillow 唯一不可替代的地方。

字体优先用微软雅黑，退化到黑体；都没有时用 PIL 内置点阵字体（中文会变成方块，
但不至于崩，且在中文 Windows 上基本不会走到这一步）。
"""
from __future__ import annotations

import os
import re
from io import BytesIO

from .util import qr_png

WIDTH = 600
PAD = 44
QR_SIZE = 400

BRAND = (27, 58, 92)
TEXT = (31, 41, 55)
MUTED = (107, 114, 128)
FAINT = (156, 163, 175)
LINE = (226, 232, 240)
BG = (255, 255, 255)

_BOLD_FONTS = [
    r"C:\Windows\Fonts\msyhbd.ttc",
    r"C:\Windows\Fonts\msyh.ttc",
    r"C:\Windows\Fonts\simhei.ttf",
]
_REGULAR_FONTS = [
    r"C:\Windows\Fonts\msyh.ttc",
    r"C:\Windows\Fonts\simhei.ttf",
]


def _font(size: int, bold: bool = False):
    from PIL import ImageFont

    for path in (_BOLD_FONTS if bold else _REGULAR_FONTS):
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


def endpoint_of(conf_text: str) -> str:
    """从客户端配置里抠出 Endpoint，卡片上要显示它。"""
    match = re.search(r"(?im)^\s*Endpoint\s*=\s*(\S+)", conf_text or "")
    return match.group(1) if match else ""


def render_card(conf_text: str, *, name: str = "", note: str = "",
                endpoint: str = "", out_path: str = "") -> str:
    """生成卡片 PNG，返回写入的路径。out_path 为空时返回 PNG 字节的 base64。"""
    if not (conf_text or "").strip():
        raise ValueError("没有客户端配置内容，无法生成卡片")

    from PIL import Image, ImageDraw

    raw_png, _version = qr_png(conf_text)
    qr = Image.open(BytesIO(raw_png)).convert("RGB")
    qr = qr.resize((QR_SIZE, QR_SIZE), Image.NEAREST)

    f_title = _font(26, bold=True)
    f_sub = _font(13)
    f_name = _font(22, bold=True)
    f_note = _font(14)
    f_info = _font(14)
    f_tiny = _font(12)

    endpoint = endpoint or endpoint_of(conf_text)

    # 先按内容算高度，再开画布
    head_h = 104
    y = head_h + 34
    y += 32                                    # 名称
    if note:
        y += 26                                # 备注
    y += 18
    qr_y = y
    y += QR_SIZE + 26

    info = []
    if endpoint:
        info.append(("服务器", endpoint))
    info.append(("生成时间", _today()))
    y += len(info) * 26 + 10

    y += 1 + 30 + 46                            # 分隔线 + 提示 + 底边距
    height = y

    img = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(img)

    # 顶部色带
    draw.rectangle([0, 0, WIDTH, head_h], fill=BRAND)
    draw.text((PAD, 30), "WireGuard 配置", font=f_title, fill=(255, 255, 255))
    draw.text((PAD, 64), "用手机 WireGuard App 扫描二维码即可导入", font=f_sub,
              fill=(191, 210, 232))

    y = head_h + 34
    if name:
        draw.text((PAD, y), name, font=f_name, fill=TEXT)
    y += 32
    if note:
        draw.text((PAD, y), note, font=f_note, fill=MUTED)
        y += 26

    y += 18
    qr_x = (WIDTH - QR_SIZE) // 2
    draw.rectangle([qr_x - 8, y - 8, qr_x + QR_SIZE + 8, y + QR_SIZE + 8],
                   outline=LINE, width=1)
    img.paste(qr, (qr_x, y))
    y += QR_SIZE + 26

    for label, value in info:
        draw.text((PAD, y), label, font=f_tiny, fill=FAINT)
        draw.text((PAD + 72, y - 1), value, font=f_info, fill=TEXT)
        y += 26

    y += 10
    draw.line([PAD, y, WIDTH - PAD, y], fill=LINE, width=1)
    y += 14
    draw.text((PAD, y), "导入后首次连接需要允许 VPN 权限；配置含私钥，别转发给他人。",
              font=f_tiny, fill=MUTED)

    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
        img.save(out_path, "PNG", optimize=True)
        return out_path
    buffer = BytesIO()
    img.save(buffer, "PNG", optimize=True)
    import base64

    return base64.b64encode(buffer.getvalue()).decode("ascii")


def _today() -> str:
    import datetime

    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
