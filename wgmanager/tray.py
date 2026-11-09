"""系统托盘 + 托盘图标。

线程模型是这个模块最容易踩坑的地方：pystray 的 `Icon.run()` 会独占一个
消息循环并阻塞，而 tkinter 只能在主线程操作。所以：

* `run()` 必须放子线程；
* 菜单回调都在 pystray 的线程里执行，碰 Tk 控件一律要 `root.after(0, ...)`
  编组回主线程，否则随机崩溃（而且是那种"跑一百次才崩一次"的崩溃）。

图标用 Pillow 现画，不依赖外部 .ico 文件，打包时也不用额外处理资源。
"""
from __future__ import annotations

import threading

# 图标底色：正常 / 有告警（掉线或过期）/ 未连接
COLOR_OK = "#185FA5"
COLOR_ALERT = "#C26A00"
COLOR_IDLE = "#777777"


def available() -> bool:
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except Exception:
        return False


def _icon_image(color: str = COLOR_OK):
    """画一个圆底 + 挂锁的托盘图标。

    先按 4 倍尺寸画再缩小，靠 LANCZOS 做抗锯齿 ——
    直接画 64px 的边缘会很脏，任务栏上尤其明显。
    """
    from PIL import Image, ImageDraw

    size, scale = 64, 4
    px = size * scale
    img = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    def box(x0, y0, x1, y1):
        return [x0 * scale, y0 * scale, x1 * scale, y1 * scale]

    draw.ellipse(box(0, 0, 63, 63), fill=color)
    # 锁梁：上半圆
    draw.arc(box(21, 13, 43, 35), start=180, end=360,
             fill=(255, 255, 255, 255), width=5 * scale)
    # 两条竖边，把半圆接到锁体上
    draw.rectangle(box(21, 24, 23.2, 32), fill=(255, 255, 255, 255))
    draw.rectangle(box(40.8, 24, 43, 32), fill=(255, 255, 255, 255))
    # 锁体
    draw.rounded_rectangle(box(16, 30, 48, 53), radius=4 * scale,
                           fill=(255, 255, 255, 255))
    # 钥匙孔
    draw.ellipse(box(29, 36, 35, 42), fill=color)
    draw.rectangle(box(31, 40, 33, 48), fill=color)
    return img.resize((size, size), Image.LANCZOS)


class Tray:
    """托盘本体。所有回调都会被编组到 Tk 主线程。"""

    def __init__(self, tk_root, *, on_show, on_quit, on_check_update=None,
                 title: str = "WireGuard 管理台"):
        import pystray

        self.root = tk_root
        self.on_show = on_show
        self.on_quit = on_quit
        self.on_check_update = on_check_update
        self.title = title
        self._state = "ok"
        self._thread: threading.Thread | None = None
        self._stopped = False

        items = [
            pystray.MenuItem("显示主窗口", self._wrap(on_show), default=True),
        ]
        if on_check_update is not None:
            items.append(pystray.MenuItem("检查更新", self._wrap(on_check_update)))
        items += [pystray.Menu.SEPARATOR,
                  pystray.MenuItem("退出", self._wrap(on_quit))]
        self._icon = pystray.Icon("wgmanager", _icon_image(),
                                  title, menu=pystray.Menu(*items))

    def _wrap(self, fn):
        def handler(_icon=None, _item=None):
            # 这里是 pystray 的线程，不能直接碰 Tk
            try:
                self.root.after(0, fn)
            except Exception:
                pass
        return handler

    # ------------------------------------------------------------ 生命周期
    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        try:
            self._thread = threading.Thread(
                target=self._icon.run, daemon=True, name="wgm-tray")
            self._thread.start()
            return True
        except Exception:
            self._thread = None
            return False

    def stop(self) -> None:
        self._stopped = True
        try:
            self._icon.stop()
        except Exception:
            pass

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ------------------------------------------------------------ 状态
    def set_state(self, state: str) -> None:
        """state 取 ok / alert / idle，只在真的变了才重画图标。"""
        if state == self._state or self._stopped:
            return
        self._state = state
        color = {"ok": COLOR_OK, "alert": COLOR_ALERT}.get(state, COLOR_IDLE)
        try:
            self._icon.icon = _icon_image(color)
            self._icon.title = self.title
        except Exception:
            pass

    def notify(self, message: str, title: str = "") -> None:
        """弹一个系统气泡。pystray 在 Windows 上走 Shell_NotifyIcon。"""
        if self._stopped:
            return
        try:
            self._icon.notify(message, title or self.title)
        except Exception:
            pass
