"""系统托盘 + 托盘图标。

线程模型是这个模块最容易踩坑的地方：pystray 的 `Icon.run()` 会独占一个
消息循环并阻塞，而 tkinter 只能在主线程操作。所以：

* `run()` 必须放子线程；
* 菜单回调都在 pystray 的线程里执行，碰 Tk 控件一律要 `root.after(0, ...)`
  编组回主线程，否则随机崩溃（而且是那种"跑一百次才崩一次"的崩溃）。

菜单里带一个「组网隧道」子菜单，把本工具管的隧道直接列出来，点一下连/断。
状态靠勾选框表达：pystray 的菜单是**构造时生成、之后缓存**的（win32 后端
只在 `_update_menu()` 里建 HMENU），所以隧道状态变了必须调 `refresh_menu()`
重建，否则勾选会跟实际状态对不上。

图标用 Pillow 现画，不依赖外部 .ico 文件，打包时也不用额外处理资源。
"""
from __future__ import annotations

import threading

# 图标底色：正常 / 有告警（掉线或过期）/ 未连接
COLOR_OK = "#185FA5"
COLOR_ALERT = "#C26A00"
COLOR_IDLE = "#777777"


def _toggle_action(name: str, on_toggle):
    """生成一个"点了就切这条隧道"的菜单回调。

    不能写成 ``lambda n=name: on_toggle(n)`` —— pystray 用 ``co_argcount``
    判断回调要几个参数，带默认值的 lambda 会被算成 1 个参数，于是它按
    "接收 icon" 处理，把 Icon 对象当隧道名传进来（踩过：日志里出现
    ``Icon object at 0x...``）。零参数的 lambda 才走它那条无参包装分支，
    name 靠外层函数的参数绑住，顺带避开循环变量的延迟绑定问题。
    """
    def action() -> None:
        on_toggle(name)
    return action


def _tunnel_menu_items(names, is_running, on_toggle) -> list:
    """「组网隧道」子菜单的内容。

    抽成模块级函数是为了能在没有图标、没有窗口的环境里直接测 ——
    pystray 的 Menu/MenuItem 是纯对象，构造它们不需要屏幕。

    :param names: 隧道名列表（只放本工具导入的那些，客户端建的起不了）
    :param is_running: 回调 name -> bool，菜单重建时现查一次
    :param on_toggle: 回调 name -> None，点一下就算「切换」（连或断）
    """
    # 这个模块会被 gui 无条件 import，所以 pystray 只能在用到时再引用 ——
    # 没有 pystray 的机器上程序要能照常跑（只是没有托盘）
    from pystray import Menu, MenuItem

    if not names:
        return [MenuItem("还没有导入隧道（先在主窗口导入 .conf）", None,
                         enabled=False)]
    items = [MenuItem("勾选表示正在运行，点一下连接 / 断开", None, enabled=False)]
    for name in names:
        try:
            running = bool(is_running(name))
        except Exception:
            running = False
        items.append(MenuItem(
            name,
            _toggle_action(name, on_toggle),
            # checked 只能是「可调用」或 None，这里固定用构造时的快照值：
            # 反正是每次重建菜单才求值，查太细也没意义
            checked=lambda _item, r=running: r,
        ))
    items.append(Menu.SEPARATOR)
    # 这一项本身不做任何事 —— 但点菜单里任何一项，pystray 都会重建菜单，
    # 勾选状态因此刷新。外部（官方客户端）改了隧道状态时用它手动对一下。
    items.append(MenuItem("刷新状态", lambda: None))
    return items


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
                 title: str = "WireGuard 管理台",
                 tunnel_names=None, tunnel_running=None, on_toggle_tunnel=None):
        import pystray

        self.root = tk_root
        self.on_show = on_show
        self.on_quit = on_quit
        self.on_check_update = on_check_update
        self.title = title
        self._state = "ok"
        self._thread: threading.Thread | None = None
        self._stopped = False

        def toggle(name: str) -> None:
            # 这里是 pystray 的线程，连／断隧道必须在主线程做
            try:
                self.root.after(0, on_toggle_tunnel, name)
            except Exception:
                pass

        items = [
            pystray.MenuItem("显示主窗口", self._wrap(on_show), default=True),
        ]
        # 隧道列表做成子菜单：条目本身不固定（增删隧道会变），所以传一个
        # 工厂函数进去，每次重建菜单时现取。注意 pystray 只在 update_menu()
        # 时重建，所以状态变了要记得调 refresh_menu()
        if tunnel_names is not None and on_toggle_tunnel is not None:
            items.append(pystray.MenuItem(
                "组网隧道",
                pystray.Menu(lambda: _tunnel_menu_items(
                    tunnel_names(), tunnel_running or (lambda _n: False), toggle)),
            ))
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
    def refresh_menu(self) -> None:
        """重建菜单，让隧道勾选和实际状态对上。

        win32 后端的菜单句柄是建一次就缓存的，勾选框里存的是构造时的快照，
        所以状态变了不重建就会显示成旧的。**只能在菜单关着的时候调** ——
        弹出期间销毁 HMENU 会和 TrackPopupMenuEx 打架，所以调用点都放在
        隧道动作结束之后（那时菜单早就关了）。
        """
        if self._stopped:
            return
        try:
            self._icon.update_menu()
        except Exception:
            pass

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
