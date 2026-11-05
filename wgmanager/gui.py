"""Windows 桌面界面（tkinter / ttk）。

界面分四块：连接服务器 -> 探测结果 -> 密钥列表与增删改 -> 操作日志。
所有 SSH 操作都放在后台线程，界面不会卡死；线程只通过队列把日志和结果送回主线程。
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import os
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import __version__
from . import autostart as autostart_mod
from . import tray as tray_mod
from .audit import ACTION_LABELS, AuditLog, export_csv
from .backend import make_backend
from .downloads import CLIENTS, OFFICIAL_INSTALL_PAGE, open_url
from .history import History
from .installer import Options as InstallOptions
from .installer import build_plan, run_install
from .probe import ProbeError, ServerMissing, probe
from .secrets import available as sealed_available
from .secrets import is_sealed, protect, unprotect
from .service import WGService
from .settings import Settings
from .traffic import TrafficStore, human_rate, nice_rate_ceiling
from .updater import (
    RELEASES_PAGE,
    Latest,
    UpdateError,
    apply_update,
    cleanup_stale,
    download,
    exe_path,
    fetch_latest,
    fetch_sha,
    is_newer,
    pending_update,
    update_dir,
)
from .util import (
    normalize_allowed_ips,
    parse_expire_date,
    patch_client_conf,
    qr_png,
    safe_filename,
    stamp,
)
from .vault import Vault

# 动作下拉里显示中文，查询时再换回内部 key
_ACTION_BY_LABEL = {v: k for k, v in ACTION_LABELS.items()}


def app_dir() -> str:
    """运行时数据目录。

    打包成 exe（PyInstaller onefile）后，__file__ 指向临时解压目录 _MEIPASS，
    数据写在那里退出就丢；所以 frozen 时要改用 exe 自己所在的目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


APP_DIR = app_dir()
CONN_FILE = os.path.join(APP_DIR, "connections.json")
KNOWN_HOSTS = os.path.join(APP_DIR, "known_hosts")
CLIENTS_DIR = os.path.join(APP_DIR, "clients")

CN_FONT = "Microsoft YaHei UI"


def _enable_dpi() -> None:
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _setup_fonts(root: tk.Tk) -> None:
    import tkinter.font as tkfont

    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(name).configure(family=CN_FONT, size=10)
        except Exception:
            pass


def center_window(win, width: int | None = None, height: int | None = None,
                  parent=None) -> None:
    """把窗口摆到屏幕正中。

    先 withdraw 再定位、最后 deiconify，避免窗口先在左上角闪一下再跳过去。
    多显示器横向排列时，以父窗口所在的那块屏幕为基准。
    """
    win.withdraw()
    win.update_idletasks()
    w = width or max(win.winfo_width(), win.winfo_reqwidth(), 1)
    h = height or max(win.winfo_height(), win.winfo_reqheight(), 1)
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    if sw <= 0 or sh <= 0:
        sw, sh = 1920, 1080
    screen_left = 0
    if parent is not None:
        try:
            screen_left = (parent.winfo_rootx() // sw) * sw
        except (tk.TclError, ZeroDivisionError):
            screen_left = 0
    x = screen_left + max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")
    win.deiconify()
    win.lift()
    try:
        win.focus_set()
    except tk.TclError:
        pass


def show_dialog(top, parent, *, width: int | None = None,
                height: int | None = None, modal: bool = False) -> None:
    """对话框统一收尾：居中显示，需要模态时在窗口可见后再 grab_set。"""
    top.withdraw()
    try:
        top.transient(parent)
    except tk.TclError:
        pass
    center_window(top, width, height, parent)
    if modal:
        top.grab_set()


def _load_profiles() -> list[dict]:
    try:
        with open(CONN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_profiles(profiles: list[dict]) -> None:
    try:
        with open(CONN_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles[:20], f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _profile_key(profile: dict) -> tuple[str, int, str]:
    """一条配置的唯一标识：同一个 IP 换端口或换用户都是另一条，不能互相覆盖。

    以前只按 host 去重，于是 ``1.2.3.4:22 root`` 和 ``1.2.3.4:10022 jsd``
    会挤成一条，后存的把先存的连同口令一起顶掉。
    """
    try:
        port = int(profile.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    return (
        str(profile.get("host", "")).strip(),
        port,
        str(profile.get("username", "")).strip(),
    )


def _conn_key(conn: dict) -> str:
    """一台服务器的唯一标识，和配置档用同一套规则（host + port + username）。"""
    host, port, user = _profile_key(conn)
    return f"{host}:{port}/{user}"


def _server_label(conn: dict) -> str:
    """下拉里显示的名字。带端口和用户名，同 IP 不同账号才不会混。"""
    if conn.get("demo"):
        return "演示模式"
    return (f"{conn.get('host', '')}:{conn.get('port', 22)} "
            f"({conn.get('username', '')})")


class App:
    def __init__(self):
        _enable_dpi()
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(f"WireGuard 密钥管理工具  v{__version__}")
        self.root.geometry("1270x760")
        self.root.minsize(1060, 680)
        _setup_fonts(self.root)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=27)
        style.configure("Treeview.Heading", font=(CN_FONT, 10, "bold"))
        style.configure("Accent.TButton", font=(CN_FONT, 10, "bold"))

        self.queue: queue.Queue = queue.Queue()
        self.busy = False
        self.backend = None
        self.target = None
        self.dep = None
        self.conn: dict = {}
        self.service: WGService | None = None
        self.views = []
        self.row_keys: dict[str, str] = {}
        # 多服务器：连上的每台都留在 servers 里，切换只是换当前上下文，
        # 不断开、不重连、不用重新输密码
        self.servers: dict[str, dict] = {}
        self.active: str = ""
        # 客户端配置保险箱：key 是客户端公钥（改名不变），内容是加密后的 .conf
        self.vault = Vault(APP_DIR)
        # 本地配置历史：每次改动前存一份原样，可预览、可还原
        self.history = History(APP_DIR)
        # 操作审计：每次写操作记一行，只记公钥不记私钥
        self.audit = AuditLog(APP_DIR)
        # 界面偏好（托盘 / 自启 / 刷新间隔），和连接凭据分开存
        self.settings = Settings(APP_DIR)
        # 流量采样：wg show transfer 是累计值，存下来才能算速率画趋势
        self.traffic = TrafficStore(APP_DIR)
        self._last_sample = 0.0
        # 系统托盘：pystray 跑在子线程，菜单回调经 root.after 编组回主线程
        self.tray = None
        self._tray_hint_shown = False
        # 在线状态监控：定时轮询当前服务器，只在状态翻转时提示。
        # 不走 _async —— 那条路会把界面锁住（busy），每分钟锁一次没法用。
        self.monitor_var = tk.BooleanVar(
            value=bool(self.settings.get("monitor_enabled", True)))
        self._monitor_job = None
        self._monitor_running = False
        self._monitor_started = 0.0
        self.monitor_interval = max(
            10, int(self.settings.get("monitor_interval", 60))) * 1000
        # paramiko 的 Transport 不适合并发跑命令：监控线程和用户操作
        # 同时发 exec_command 有概率互相踩，用一把锁串起来
        self._ssh_lock = threading.Lock()

        self._poll_job = None
        self._build()
        self._poll_job = self.root.after(120, self._poll)
        self._monitor_job = self.root.after(3000, self._monitor_tick)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if self.settings.get("tray_enabled", True) and tray_mod.available():
            self.root.after(800, self._start_tray_if_enabled)
        self._log("就绪。填好服务器信息后点「连接」；也可以直接勾选「演示模式」先试用。")
        self._refresh_profile_combo()
        self._refresh_server_combo()
        # 按内容实际需要的尺寸开窗，并限制在屏幕内，避免新增控件被裁切
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        width = min(max(1270, self.root.winfo_reqwidth() + 12), int(sw * 0.94))
        height = min(max(720, self.root.winfo_reqheight() + 12), int(sh * 0.90))
        center_window(self.root, width, height)
        self._check_pending_update()

    def _check_pending_update(self) -> None:
        """上次替换失败会留下 update-error.txt，启动时提醒一句，别让人以为更新成功了。"""
        try:
            work_dir = update_dir(app_dir())
        except Exception:
            return
        err = pending_update(work_dir)
        if not err:
            return
        self._append_log(
            "上次自动更新没有成功，当前运行的仍是旧版本。可以重新点「检查更新」再试一次。"
        )
        self.update_hint.configure(text="上次更新未完成", foreground="#b03030")
        try:
            os.remove(err)
        except OSError:
            pass

    # ------------------------------------------------------------------ 布局
    def _build(self) -> None:
        root = self.root
        self._build_connection(ttk.LabelFrame(root, text=" ① 连接服务器 ", padding=10))
        self.info_frame = ttk.LabelFrame(root, text=" ② 探测结果 ", padding=10)
        self.info_frame.pack(fill="x", padx=12, pady=(0, 8))
        self.info_var = tk.StringVar(value="尚未连接")
        ttk.Label(self.info_frame, textvariable=self.info_var, wraplength=1040,
                  justify="left", foreground="#333333").pack(side="left", fill="x", expand=True)
        ttk.Button(self.info_frame, text="探测详情", command=self._show_diagnostics,
                   width=12).pack(side="right", padx=(10, 0))

        self._build_peers(ttk.LabelFrame(root, text=" ③ 密钥列表 ", padding=10))
        self._build_log(ttk.LabelFrame(root, text=" 操作日志 ", padding=6))
        self._build_footer()

    def _build_footer(self) -> None:
        """底部状态条：版本号 + 检查更新。不占按钮行，避免把连接区挤宽。"""
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=14, pady=(0, 8))
        ttk.Label(bar, text=f"v{__version__}", foreground="#8a8a8a").pack(side="left")
        ttk.Label(bar, text="·", foreground="#c8c8c8").pack(side="left", padx=6)
        self.update_btn = ttk.Button(bar, text="检查更新", width=11,
                                     command=self.check_update)
        self.update_btn.pack(side="left")
        self.update_hint = ttk.Label(bar, text="", foreground="#8a8a8a")
        self.update_hint.pack(side="left", padx=10)
        ttk.Button(bar, text="发行版页面", width=12,
                   command=lambda: open_url(RELEASES_PAGE)).pack(side="right")
        self.monitor_check = ttk.Checkbutton(
            bar, text="自动刷新在线状态", variable=self.monitor_var,
            command=self._on_monitor_toggle)
        self.monitor_check.pack(side="right", padx=(0, 14))
        ttk.Button(bar, text="设置", width=8,
                   command=self.show_settings).pack(side="right", padx=(0, 6))

    def _build_connection(self, frame) -> None:
        frame.pack(fill="x", padx=12, pady=(10, 8))
        self.conn_frame = frame

        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="root")
        self.auth_var = tk.StringVar(value="password")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar()
        self.key_pass_var = tk.StringVar()
        self.sudo_pwd_var = tk.StringVar()
        self.demo_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="● 未连接")
        self.profile_var = tk.StringVar()
        # 默认记住：省得每次选完配置还要再敲一遍密码
        self.remember_var = tk.BooleanVar(value=True)

        row = ttk.Frame(frame)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="服务器 IP：", width=11).pack(side="left")
        self.host_entry = ttk.Entry(row, textvariable=self.host_var, width=22)
        self.host_entry.pack(side="left")
        ttk.Label(row, text="SSH 端口：").pack(side="left", padx=(14, 0))
        self.port_entry = ttk.Entry(row, textvariable=self.port_var, width=7)
        self.port_entry.pack(side="left")
        ttk.Label(row, text="用户名：").pack(side="left", padx=(14, 0))
        self.user_entry = ttk.Entry(row, textvariable=self.user_var, width=14)
        self.user_entry.pack(side="left")
        ttk.Label(row, text="已保存配置：").pack(side="left", padx=(14, 0))
        self.profile_combo = ttk.Combobox(row, textvariable=self.profile_var,
                                          state="readonly", width=24)
        self.profile_combo.pack(side="left")
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)
        ttk.Checkbutton(row, text="演示模式（不要服务器）", variable=self.demo_var,
                        command=self._on_demo_toggle).pack(side="right")

        row2 = ttk.Frame(frame)
        row2.pack(fill="x", pady=(8, 2))
        ttk.Label(row2, text="认证方式：", width=11).pack(side="left")
        self.rb_pwd = ttk.Radiobutton(row2, text="密码", value="password",
                                      variable=self.auth_var, command=self._on_auth_change)
        self.rb_key = ttk.Radiobutton(row2, text="私钥文件", value="key",
                                      variable=self.auth_var, command=self._on_auth_change)
        self.rb_pwd.pack(side="left")
        self.rb_key.pack(side="left", padx=(8, 0))
        ttk.Label(row2, text="密码：").pack(side="left", padx=(18, 0))
        self.pwd_entry = ttk.Entry(row2, textvariable=self.password_var, width=20, show="●")
        self.pwd_entry.pack(side="left")
        ttk.Label(row2, text="私钥：").pack(side="left", padx=(14, 0))
        self.key_entry = ttk.Entry(row2, textvariable=self.key_var, width=30)
        self.key_entry.pack(side="left")
        self.key_browse = ttk.Button(row2, text="浏览…", width=7, command=self._browse_key)
        self.key_browse.pack(side="left", padx=(4, 0))
        ttk.Label(row2, text="私钥口令：").pack(side="left", padx=(12, 0))
        self.keypass_entry = ttk.Entry(row2, textvariable=self.key_pass_var, width=12, show="●")
        self.keypass_entry.pack(side="left")

        row2b = ttk.Frame(frame)
        row2b.pack(fill="x", pady=(6, 0))
        ttk.Label(row2b, text="sudo 密码：", width=11).pack(side="left")
        self.sudo_pwd_entry = ttk.Entry(row2b, textvariable=self.sudo_pwd_var,
                                        width=20, show="●")
        self.sudo_pwd_entry.pack(side="left")
        ttk.Label(
            row2b,
            text="非 root 账号必填（密码登录且与 SSH 密码相同可留空；私钥登录时一定要填）",
            foreground="#a05000",
        ).pack(side="left", padx=(10, 0))

        row3 = ttk.Frame(frame)
        row3.pack(fill="x", pady=(10, 0))
        self.connect_btn = ttk.Button(row3, text="连接", width=12,
                                      style="Accent.TButton", command=self.connect)
        self.connect_btn.pack(side="left")
        self.disconnect_btn = ttk.Button(row3, text="断开", width=10,
                                         command=self.disconnect, state="disabled")
        self.disconnect_btn.pack(side="left", padx=6)
        ttk.Button(row3, text="高级设置", width=12,
                   command=self._advanced_dialog).pack(side="left", padx=(10, 0))
        ttk.Button(row3, text="使用帮助", width=12,
                   command=self._help_dialog).pack(side="left", padx=6)
        ttk.Button(row3, text="下载客户端", width=12,
                   command=self._downloads_dialog).pack(side="left")
        self.status_label = ttk.Label(row3, textvariable=self.status_var,
                                      foreground="#b03030")
        self.status_label.pack(side="right")
        self.remember_check = ttk.Checkbutton(
            row3, text="记住密码", variable=self.remember_var,
        )
        self.remember_check.pack(side="right", padx=(0, 14))
        if not sealed_available():
            # 拿不到 DPAPI 就干脆不提供这个选项，免得以为记住了其实没有
            self.remember_var.set(False)
            self.remember_check.configure(state="disabled")
        self._on_auth_change()

        self.adv_conf = tk.StringVar()
        self.adv_iface = tk.StringVar()
        self.adv_endpoint = tk.StringVar()

    def _build_peers(self, frame) -> None:
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="当前服务器：").pack(side="left")
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(bar, textvariable=self.server_var,
                                         state="readonly", width=22)
        self.server_combo.pack(side="left")
        self.server_combo.bind("<<ComboboxSelected>>", self._on_server_selected)
        self.count_var = tk.StringVar(value="共 0 个密钥")
        ttk.Label(bar, textvariable=self.count_var,
                  font=(CN_FONT, 11, "bold")).pack(side="left", padx=(12, 0))
        self.refresh_btn = ttk.Button(bar, text="刷新", width=10, command=self.refresh,
                                      state="disabled")
        self.refresh_btn.pack(side="right", padx=4)
        self.clients_btn = ttk.Button(bar, text="目录", width=6,
                                      command=self._open_clients_dir)
        self.clients_btn.pack(side="right", padx=4)
        self.history_btn = ttk.Button(bar, text="历史", width=8,
                                      command=self.show_history, state="disabled")
        self.history_btn.pack(side="right", padx=4)
        self.client_btn = ttk.Button(bar, text="客户端配置", width=13,
                                     command=self.show_client_conf, state="disabled")
        self.client_btn.pack(side="right", padx=4)
        self.traffic_btn = ttk.Button(bar, text="流量", width=8,
                                      command=self.show_traffic, state="disabled")
        self.traffic_btn.pack(side="right", padx=4)
        self.delete_btn = ttk.Button(bar, text="删除", width=8,
                                     command=self.delete_selected, state="disabled")
        self.delete_btn.pack(side="right", padx=4)
        self.edit_btn = ttk.Button(bar, text="编辑", width=8,
                                   command=self.edit_selected, state="disabled")
        self.edit_btn.pack(side="right", padx=4)
        self.add_btn = ttk.Button(bar, text="＋ 新增密钥", width=14,
                                  style="Accent.TButton", command=self.add_dialog,
                                  state="disabled")
        self.add_btn.pack(side="right", padx=4)

        columns = ("name", "note", "pubkey", "address", "expire", "handshake",
                   "traffic", "endpoint", "status")
        headers = {
            "name": ("名称", 150), "note": ("备注", 130), "pubkey": ("公钥", 120),
            "address": ("VPN 地址", 165), "expire": ("到期", 92),
            "handshake": ("最近握手", 105),
            "traffic": ("流量 (收/发)", 130), "endpoint": ("来源端点", 130),
            "status": ("状态", 70),
        }
        # 过期提示条：平时不占地方，检测到过期/临期才出现
        self.expire_bar = ttk.Frame(frame)
        self.expire_label = ttk.Label(self.expire_bar, text="", foreground="#b03030")
        self.expire_label.pack(side="left")
        self.clean_btn = ttk.Button(self.expire_bar, text="清理过期", width=11,
                                    command=self.clean_expired, state="disabled")
        self.clean_btn.pack(side="left", padx=(10, 0))
        self.auto_clean_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.expire_bar, text="连上时自动清理（仍会确认）",
                        variable=self.auto_clean_var).pack(side="left", padx=(14, 0))

        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        self.tree_body = body
        self.tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            title, width = headers[col]
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=60,
                             anchor="w" if col not in ("status", "expire") else "center")
        self.tree.tag_configure("online", foreground="#0a7a3d")
        self.tree.tag_configure("offline", foreground="#777777")
        self.tree.tag_configure("expired", foreground="#b03030")
        self.tree.tag_configure("expiring", foreground="#a05a00")
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(body, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", lambda _e: self._show_selected_detail())

    def _build_log(self, frame) -> None:
        frame.pack(fill="x", padx=12, pady=(0, 10))
        self.log_text = scrolledtext.ScrolledText(frame, height=8, wrap="word",
                                                  font=("Consolas", 9))
        self.log_text.pack(fill="x")
        self.log_text.configure(state="disabled")

    # ------------------------------------------------------------------ 工具
    def _log(self, msg: str) -> None:
        self.queue.put(("log", str(msg)))

    @staticmethod
    def _entry_host(conn: dict) -> str:
        """服务器标识：宿主、端口、账号，能区分同一 IP 的不同身份。"""
        conn = conn or {}
        if conn.get("demo"):
            return "演示模式"
        if not conn.get("host"):
            return ""
        return f"{conn.get('host')}:{conn.get('port', 22)}/{conn.get('username', '')}"

    def _audit_host(self) -> str:
        """审计日志里的服务器标识，取当前这台。"""
        return self._entry_host(self.conn)

    def _append_log(self, msg: str) -> None:
        import datetime

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "done":
                    result, callback = payload
                    self.busy = False
                    self._set_buttons()
                    try:
                        callback(result)
                    except Exception:
                        self._append_log(traceback.format_exc())
                        messagebox.showerror("操作失败", traceback.format_exc(limit=6),
                                             parent=self.root)
                elif kind == "error":
                    label, exc, tb = payload
                    self.busy = False
                    self._set_buttons()
                    self.status_var.set(f"● {label}失败")
                    self._append_log(tb.strip())
                    messagebox.showerror(label + "失败", str(exc), parent=self.root)
                elif kind == "monitor_ok":
                    key, views = payload
                    self._on_monitor_result(key, views)
                elif kind == "monitor_err":
                    self._monitor_running = False
                    key, exc = payload
                    # 监控失败不弹窗：网络抖一下就弹一次，会把人心态搞崩
                    self._append_log(f"自动刷新失败（{key}）：{exc}")
                elif kind == "update_ok":
                    self._on_update_info(payload)
                elif kind == "update_fail":
                    self._on_update_fail(payload)
                elif kind == "update_progress":
                    self.update_btn.configure(text=f"下载 {payload}%")
                elif kind == "update_downloaded":
                    latest, new_exe = payload
                    self._on_downloaded(latest, new_exe)
                elif kind == "update_download_fail":
                    latest, exc = payload
                    self._on_download_failed(latest, exc)
        except queue.Empty:
            pass
        self._poll_job = self.root.after(120, self._poll)

    def _async(self, label: str, work, done) -> None:
        if self.busy:
            return
        self.busy = True
        self.status_var.set(f"● {label}…")
        self._set_buttons()

        def runner():
            try:
                with self._ssh_lock:
                    result = work()
            except Exception as exc:
                self.queue.put(("error", (label, exc, traceback.format_exc())))
            else:
                self.queue.put(("done", (result, done)))

        threading.Thread(target=runner, daemon=True).start()

    # ------------------------------------------------------------ 检查更新
    def check_update(self) -> None:
        """只查版本，不下东西。结果通过队列回主线程。"""
        self.update_btn.configure(state="disabled", text="检查中…")
        self.update_hint.configure(text="", foreground="#8a8a8a")

        def runner():
            try:
                latest = fetch_latest()
            except UpdateError as exc:
                self.queue.put(("update_fail", str(exc)))
            except Exception as exc:
                self.queue.put(("update_fail", f"{type(exc).__name__}: {exc}"))
            else:
                self.queue.put(("update_ok", latest))

        threading.Thread(target=runner, daemon=True).start()

    def _on_update_fail(self, message: str) -> None:
        self.update_btn.configure(state="normal", text="检查更新")
        self.update_hint.configure(text="检查失败", foreground="#b03030")
        self._append_log("检查更新失败：" + message)
        messagebox.showwarning(
            "检查更新失败",
            message + "\n\n可以手动打开发行版页面下载：\n" + RELEASES_PAGE,
            parent=self.root,
        )

    def _on_update_info(self, latest: Latest) -> None:
        self.update_btn.configure(state="normal", text="检查更新")
        if not is_newer(latest.version, __version__):
            self.update_hint.configure(text="已是最新版本", foreground="#0a7a3d")
            messagebox.showinfo(
                "检查更新",
                f"当前已是最新版本 v{__version__}。",
                parent=self.root,
            )
            return

        self.update_hint.configure(
            text=f"发现新版本 v{latest.version}", foreground="#a05000")
        size_mb = latest.size / 1024 / 1024 if latest.size else 0
        detail = f"当前版本：v{__version__}\n最新版本：v{latest.version}"
        if size_mb:
            detail += f"\n安装包大小：{size_mb:.1f} MB"
        if latest.notes:
            notes = latest.notes.strip().splitlines()
            detail += "\n\n更新说明：\n" + "\n".join(notes[:8])

        if not exe_path():
            # 源码运行没有可替换的 exe，只能提示去下载
            self._append_log("检测到新版本，但当前是源码运行，无法自动替换")
            if messagebox.askyesno(
                "发现新版本",
                detail + "\n\n当前是源码方式运行，不能自动替换。\n"
                "要打开发行版页面手动下载吗？",
                parent=self.root,
            ):
                open_url(latest.page_url)
            return

        if not messagebox.askyesno(
            "发现新版本",
            detail + "\n\n现在下载并安装吗？装完会自动重启。",
            parent=self.root,
        ):
            return
        self._download_update(latest)

    def _download_update(self, latest: Latest) -> None:
        work_dir = update_dir(app_dir())
        cleanup_stale(work_dir)
        dest = os.path.join(work_dir, f"WireGuardManager-{latest.version}.exe")

        def progress(pct, done, total):
            # 频繁刷界面没意义，按 5% 步长报一次就够
            if pct >= getattr(self, "_last_pct", -5) + 5 or pct >= 100:
                self._last_pct = pct
                self.queue.put(("update_progress", pct))

        def work():
            expected = fetch_sha(latest)
            if not expected:
                # 没有 SHA256.txt 也照下，但要在日志里留个记号
                self.queue.put(("log", "警告：这个发行版没有 SHA256.txt，跳过完整性校验"))
            digest = download(latest.exe_url, dest, expected, progress)
            return dest, digest

        self._last_pct = -5
        self.update_btn.configure(state="disabled", text="下载 0%")
        self._append_log(f"开始下载 v{latest.version}…")

        def runner():
            try:
                result = work()
            except Exception as exc:
                self.queue.put(("update_download_fail", (latest, exc)))
            else:
                self.queue.put(("update_downloaded", (latest, result[0])))

        threading.Thread(target=runner, daemon=True).start()

    def _on_downloaded(self, latest: Latest, new_exe: str) -> None:
        self.update_btn.configure(state="normal", text="检查更新")
        self.update_hint.configure(text=f"v{latest.version} 已就绪", foreground="#0a7a3d")
        self._append_log(f"v{latest.version} 下载完成并校验通过：{new_exe}")

        if not messagebox.askyesno(
            "准备安装",
            f"新版 v{latest.version} 已下载并校验通过。\n\n"
            "点「确定」后程序会关闭，自动替换文件并重新启动。\n"
            "替换期间请不要强杀进程或断电。",
            parent=self.root,
        ):
            self._append_log("已取消安装，下载的文件保留在 updates\\ 里，可以稍后再装")
            return

        try:
            apply_update(new_exe, exe_path(), os.path.dirname(new_exe))
        except Exception as exc:
            messagebox.showerror(
                "无法启动更新程序",
                f"{exc}\n\n可以手动把\n{new_exe}\n复制覆盖到\n{exe_path()}",
                parent=self.root,
            )
            return

        self._append_log("正在关闭并重启以完成更新…")
        self.root.after(400, self._quit_for_update)

    def _on_download_failed(self, latest: Latest, exc: Exception) -> None:
        self.update_btn.configure(state="normal", text="检查更新")
        self.update_hint.configure(text="下载失败", foreground="#b03030")
        self._append_log(f"下载 v{latest.version} 失败：{exc}")
        messagebox.showwarning(
            "下载失败",
            f"{exc}\n\n可以手动打开发行版页面下载：\n{latest.page_url}",
            parent=self.root,
        )

    def _quit_for_update(self) -> None:
        try:
            if self.backend:
                self.backend.close()
        except Exception:
            pass
        self.root.destroy()

    def _set_buttons(self, connecting: bool = False) -> None:
        connected = self.service is not None
        enabled = connected and not self.busy
        for btn in (self.refresh_btn, self.add_btn, self.edit_btn,
                    self.delete_btn, self.client_btn, self.history_btn,
                    self.traffic_btn):
            btn.configure(state="normal" if enabled else "disabled")
        # 多服务器下「连接」不再受"已连着一台"限制：随时可以连新的，
        # 只有正在连的时候才临时禁用，避免重复发起。
        self.connect_btn.configure(
            state="disabled" if (self.busy or connecting) else "normal"
        )
        self.disconnect_btn.configure(state="normal" if (connected and not self.busy) else "disabled")

    def _collect_conn(self) -> dict:
        host = self.host_var.get().strip()
        if not self.demo_var.get():
            if not host:
                raise ValueError("请填写服务器 IP")
            try:
                port = int(self.port_var.get().strip() or "22")
            except ValueError:
                raise ValueError("SSH 端口必须是数字")
        else:
            port = 22
        auth = self.auth_var.get()
        if not self.demo_var.get():
            if auth == "password" and not self.password_var.get():
                raise ValueError("请填写 SSH 密码")
            if auth == "key" and not self.key_var.get().strip():
                raise ValueError("请选择私钥文件")
        return {
            "demo": self.demo_var.get(),
            "host": host,
            "port": port,
            "username": self.user_var.get().strip() or "root",
            "auth": auth,
            "password": self.password_var.get() if auth == "password" else "",
            "key_path": self.key_var.get().strip() if auth == "key" else "",
            "key_passphrase": self.key_pass_var.get() if auth == "key" else "",
            "sudo_password": self.sudo_pwd_var.get(),
            "known_hosts_path": KNOWN_HOSTS,
            "conf_path": self.adv_conf.get().strip(),
            "iface": self.adv_iface.get().strip(),
            "endpoint_host": self.adv_endpoint.get().strip(),
        }

    # -------------------------------------------------------------- 连接管理
    def connect(self) -> None:
        try:
            conn = self._collect_conn()
        except ValueError as exc:
            messagebox.showwarning("填写不完整", str(exc), parent=self.root)
            self._refresh_server_combo()   # 下拉回到真实状态，别停在没连上的那项
            return
        self._save_current_profile(conn)
        key = "demo" if conn.get("demo") else _conn_key(conn)

        # 同一台重连：先关掉旧连接，否则会留一个后台会话指着同一台服务器
        old = self.servers.pop(key, None)
        if old:
            self._close_entry(old)
        self.conn = conn

        def work():
            backend = make_backend(conn, log=self._log)
            try:
                target, dep = probe(backend, conn, self._log)
                svc = WGService(target, dep, self._log, history=self.history)
                views = svc.list_peers()
            except ServerMissing as exc:
                # 保留这条连接，装完直接用，不用重新输密码
                return {"kind": "missing", "backend": backend, "error": exc,
                        "key": key, "conn": conn}
            except Exception:
                backend.close()
                raise
            return {"kind": "ok", "backend": backend, "target": target,
                    "dep": dep, "service": svc, "views": views,
                    "key": key, "conn": conn}

        self._async("连接", work, self._on_connected)

    def _on_connected(self, payload) -> None:
        key = payload.get("key", "")
        if payload.get("kind") == "missing":
            self._start_install_flow(payload["backend"], payload["error"],
                                     key, payload.get("conn") or {})
            return

        entry = {
            "conn": payload["conn"],
            "backend": payload["backend"],
            "target": payload["target"],
            "dep": payload["dep"],
            "service": payload["service"],
            "views": payload["views"],
            "label": _server_label(payload["conn"]),
        }
        self.servers[key] = entry
        self._activate(key)
        self._append_log(f"连接成功：{entry['dep'].summary}")
        for note in entry["dep"].notes:
            self._append_log("提示：" + note)
        if entry["dep"].notes:
            messagebox.showinfo(
                "探测提示",
                "检测到以下情况，请留意：\n\n• " + "\n• ".join(entry["dep"].notes),
                parent=self.root,
            )
        # 勾了自动清理就顺手处理掉过期的。clean_expired 自带确认框，
        # 不会静默删东西 —— 删密钥这种操作不该只看一个复选框就执行。
        if self.auto_clean_var.get() and any(v.expired for v in entry["views"]):
            self.root.after(700, self.clean_expired)

    # ------------------------------------------------------------ 多服务器
    def _activate(self, key: str) -> None:
        """把某台服务器切成「当前上下文」。只是换指针，不重连。"""
        entry = self.servers.get(key)
        if not entry:
            return
        self.active = key
        self.conn = entry["conn"]
        self.backend = entry["backend"]
        self.target = entry["target"]
        self.dep = entry["dep"]
        self.service = entry["service"]
        self.views = entry["views"]
        self.info_var.set(entry["dep"].summary)
        self.status_var.set("● 已连接")
        self._fill(entry["views"])
        self._set_buttons()
        self._refresh_server_combo()
        # 切回来的这台可能已经几十分钟没刷过了，立刻查一次
        if self.monitor_var.get():
            self._schedule_monitor(delay=400)

    def _clear_active(self) -> None:
        self.backend = self.target = self.dep = self.service = None
        self.conn = {}
        self.views = []
        self.active = ""
        self._fill([])
        self.info_var.set("尚未连接")
        self.status_var.set("● 未连接")
        self._set_buttons()
        self._refresh_server_combo()

    def _close_entry(self, entry: dict) -> None:
        try:
            entry["backend"].close()
        except Exception:
            pass

    def _on_server_selected(self, _event=None) -> None:
        idx = self.server_combo.current()
        online = getattr(self, "_server_keys", [])
        offline = getattr(self, "_offline_profiles", [])
        if 0 <= idx < len(online):
            self._activate(online[idx])
            self._append_log("已切换到 " + self.servers[online[idx]]["label"])
            return
        j = idx - len(online)
        if 0 <= j < len(offline):
            profile = offline[j]
            self._append_log(f"正在连接 {_server_label(profile)} …")
            self._connect_profile(profile)

    def _connect_profile(self, profile: dict) -> None:
        """从下拉里选了一台还没连的：把表单填好再发起连接。"""
        self.host_var.set(profile.get("host", ""))
        self.port_var.set(str(profile.get("port", 22)))
        self.user_var.set(profile.get("username", "root"))
        self.auth_var.set(profile.get("auth", "password"))
        self.key_var.set(profile.get("key_path", ""))
        self.password_var.set(unprotect(profile.get("password", "")))
        self.key_pass_var.set(unprotect(profile.get("key_passphrase", "")))
        self.sudo_pwd_var.set(unprotect(profile.get("sudo_password", "")))
        self.remember_var.set(
            any(is_sealed(profile.get(k))
                for k in ("password", "key_passphrase", "sudo_password"))
        )
        self._on_auth_change()
        self.connect()

    def _refresh_server_combo(self) -> None:
        """下拉 = 已连接的服务器 + 已保存但还没连的配置。

        做成统一的"服务器列表"，省得用户每次都要先填表单点连接再切换。
        """
        self._server_keys = list(self.servers.keys())
        labels = [self.servers[k]["label"] for k in self._server_keys]
        self._offline_profiles = []
        for profile in _load_profiles():
            if _conn_key(profile) in self.servers:
                continue
            label = _server_label(profile)
            if label in labels:
                continue
            labels.append(label + "（未连接）")
            self._offline_profiles.append(profile)
        if not labels:
            labels = ["（还没有服务器）"]
        self.server_combo["values"] = labels
        if self.active in self._server_keys:
            self.server_combo.current(self._server_keys.index(self.active))
        elif self._server_keys or self._offline_profiles:
            self.server_combo.current(0)
        else:
            self.server_combo.set("（还没有服务器）")

    # ---------------------------------------------------------- 一键装服务端
    def _start_install_flow(self, backend, exc, key: str = "",
                            conn: dict | None = None) -> None:
        self.backend = backend
        self.conn = conn or {}
        # 这条连接还没进 servers（探测就没通过），先把身份记下来，
        # 装完之后 _reprobe 用它注册成一台正常服务器
        self._pending = {"key": key or "pending", "conn": self.conn}
        self.status_var.set("● 已连接，但服务器上没有 WireGuard 服务端")
        self.info_var.set("未安装 WireGuard 服务端")
        self._set_buttons()
        self._append_log("探测：服务器上没有可用的 WireGuard 服务端")

        if not getattr(exc, "installable", True):
            messagebox.showwarning("无法继续", str(exc), parent=self.root)
            self._abort_install(backend)
            return

        host = (self.conn or {}).get("endpoint_host") or (self.conn or {}).get("host", "")

        def work():
            return build_plan(backend, InstallOptions(), host)

        def done(plan):
            dlg = InstallDialog(self.root, plan)
            self.root.wait_window(dlg.top)
            if not dlg.result:
                self._append_log("已取消安装")
                self._abort_install(backend)
                return
            self._run_install(plan, dlg.result)

        self._async("检查安装环境", work, done)

    def _abort_install(self, backend) -> None:
        """安装流程中止：这条连接还没进 servers，得单独关掉，别泄漏会话。"""
        try:
            backend.close()
        except Exception:
            pass
        self.backend = None
        self._pending = {}
        if self.servers:
            self._activate(next(reversed(self.servers)))
        else:
            self._clear_active()

    def _run_install(self, plan, options) -> None:
        backend = self.backend

        def work():
            # 用户可能改过网段/端口，按最终参数重新出方案（都是只读命令，很快）
            fresh = build_plan(backend, options, plan.endpoint_host)
            return run_install(backend, fresh, options, self._log)

        def done(res):
            for note in res.warnings:
                self._append_log("注意：" + note)
            self._append_log(res.message)
            text = (
                f"WireGuard 服务端已装好：\n\n"
                f"接口：{res.iface}\n配置：{res.conf_path}\n"
                f"服务端公钥：{res.public_key}"
            )
            if res.warnings:
                text += "\n\n注意：\n• " + "\n• ".join(res.warnings)
            messagebox.showinfo("安装完成", text, parent=self.root)
            self.audit.record(
                "install", host=self._audit_host(),
                detail=f"接口 {res.iface}，配置 {res.conf_path}",
            )
            self._reprobe()

        self._async("安装 WireGuard 服务端", work, done)

    def _reprobe(self) -> None:
        """安装完重新走一遍探测，成功后就是正常的已连接状态。"""
        backend = self.backend
        conn = self.conn or {}
        pending = getattr(self, "_pending", {}) or {}

        def work():
            target, dep = probe(backend, conn, self._log)
            svc = WGService(target, dep, self._log, history=self.history)
            return {"kind": "ok", "backend": backend, "target": target,
                    "dep": dep, "service": svc, "views": svc.list_peers(),
                    "key": pending.get("key", ""),
                    "conn": pending.get("conn") or conn}

        self._async("重新探测", work, self._on_connected)

    def disconnect(self) -> None:
        """断开当前这台。还有别的连着就自动切过去，否则回到未连接状态。"""
        if not self.active:
            return
        entry = self.servers.pop(self.active, None)
        label = entry["label"] if entry else ""
        if entry:
            self._close_entry(entry)
        self._append_log(f"已断开 {label}")
        if self.servers:
            self._activate(next(reversed(self.servers)))
        else:
            self._clear_active()

    # ---------------------------------------------------------------- 列表
    def _fill(self, views) -> None:
        self.views = views or []
        # 同步回这台服务器自己的槽位，否则切走再切回来还是旧的列表
        if self.active and self.active in self.servers:
            self.servers[self.active]["views"] = self.views
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.row_keys.clear()
        for view in self.views:
            iid = self.tree.insert(
                "", "end",
                values=(
                    view.name, view.note, view.pubkey[:14] + "…", view.address,
                    view.expire_text or "—",
                    view.handshake, view.traffic, view.endpoint,
                    "在线" if view.online else "离线/从未",
                ),
                tags=(self._row_tag(view),),
            )
            self.row_keys[iid] = view.pubkey
        online = sum(1 for v in self.views if v.online)
        self.count_var.set(f"共 {len(self.views)} 个密钥（在线 {online}）")
        self._update_expire_bar(self.views)
        self._update_tray_state(self.views)

    @staticmethod
    def _row_tag(view) -> str:
        """过期最要紧，其次是临期，然后再看在线状态。"""
        if view.expired:
            return "expired"
        if view.expire_days is not None and view.expire_days <= 3:
            return "expiring"
        return "online" if view.online else "offline"

    def _update_expire_bar(self, views) -> None:
        expired = [v for v in views if v.expired]
        soon = [v for v in views
                if not v.expired and v.expire_days is not None and v.expire_days <= 3]
        if not expired and not soon:
            if self.expire_bar.winfo_manager():
                self.expire_bar.pack_forget()
            return
        parts = []
        if expired:
            parts.append(f"{len(expired)} 个密钥已过期")
        if soon:
            parts.append(f"{len(soon)} 个 3 天内到期")
        self.expire_label.configure(text=" · ".join(parts))
        self.clean_btn.configure(state="normal" if expired else "disabled")
        if not self.expire_bar.winfo_manager():
            self.expire_bar.pack(fill="x", pady=(0, 6), before=self.tree_body)

    def clean_expired(self) -> None:
        if not self.service:
            return
        targets = [v for v in self.views if v.expired]
        if not targets:
            return
        listing = "\n".join(f"· {v.name}（{v.address or '-'}）" for v in targets[:15])
        if len(targets) > 15:
            listing += f"\n… 还有 {len(targets) - 15} 个"
        if not messagebox.askyesno(
            "清理过期密钥",
            f"从服务器上删除这 {len(targets)} 个已过期的密钥？\n\n{listing}\n\n"
            "删除前会自动备份，删错了可以从「历史记录」里还原。",
            icon="warning", parent=self.root,
        ):
            return

        def done(names):
            for v in targets:
                self.vault.drop(v.pubkey)
                self.audit.record("expire", host=self._audit_host(), name=v.name,
                                  pubkey=v.pubkey, detail=f"到期日 {v.expire}")
            self._append_log("已清理过期密钥：" + "、".join(names))
            self.refresh()

        self._async("清理过期密钥", self.service.remove_expired, done)

    # ------------------------------------------------------ 在线状态监控
    def _on_monitor_toggle(self) -> None:
        if self.monitor_var.get():
            self._append_log(
                f"已开启自动刷新：每 {self.monitor_interval // 1000} 秒查一次当前服务器")
            self._schedule_monitor(delay=800)
        else:
            self._cancel_monitor()
            self._append_log("已关闭自动刷新，点「刷新」手动更新")

    def _schedule_monitor(self, delay: int | None = None) -> None:
        self._cancel_monitor()
        self._monitor_job = self.root.after(
            self.monitor_interval if delay is None else delay, self._monitor_tick)

    def _cancel_monitor(self) -> None:
        if self._monitor_job is not None:
            try:
                self.root.after_cancel(self._monitor_job)
            except Exception:
                pass
            self._monitor_job = None

    def _monitor_tick(self) -> None:
        self._monitor_job = None
        if not self.monitor_var.get():
            return
        svc, key = self.service, self.active
        # 上一轮还没回来（SSH 卡住），但别让监控就此永久停摆
        if (self._monitor_running
                and time.monotonic() - self._monitor_started > 180):
            self._monitor_running = False
        # 有别的事在跑就不插队：一次 list_peers 要 SSH 往返，
        # 跟写配置挤一块容易撞上超时
        if svc is None or self.busy or self._monitor_running:
            self._schedule_monitor()
            return
        self._monitor_running = True
        self._monitor_started = time.monotonic()

        def runner():
            try:
                with self._ssh_lock:
                    views = svc.list_peers()
            except Exception as exc:
                self.queue.put(("monitor_err", (key, exc)))
            else:
                self.queue.put(("monitor_ok", (key, views)))

        threading.Thread(target=runner, daemon=True).start()
        self._schedule_monitor()

    def _on_monitor_result(self, key: str, views) -> None:
        self._monitor_running = False
        entry = self.servers.get(key)
        if entry is None:
            return
        prev = {v.pubkey: v.online for v in (entry.get("views") or [])}
        entry["views"] = views
        if key == self.active:
            self.views = views
            self._refresh_live_cells(views)
        self._note_transitions(entry.get("label", key), prev, views)
        self._sample_traffic(entry, views)

    def _sample_traffic(self, entry: dict, views) -> None:
        """把这一轮的累计流量存下来。

        轮询一分钟一次，但采样五分钟一次就够 —— 图上点太密看不出东西，
        库还能小到 1/5。这里用独立节流，不跟着轮询频率走。
        """
        now = time.time()
        if now - self._last_sample < 300:
            return
        self._last_sample = now
        points = [(v.pubkey, v.rx, v.tx) for v in views if v.rx or v.tx]
        if not points:
            return
        self.traffic.record(self._entry_host(entry.get("conn") or {}), points, now)

    def _note_transitions(self, label: str, prev: dict, views) -> None:
        """只在状态翻转时说话 —— 每分钟把所有人报一遍没人受得了。"""
        if not prev:
            return  # 第一轮没有基线，不能把所有人都当成"刚上线"
        for v in views:
            if v.pubkey not in prev:
                self._append_log(f"{label} 上多了一个密钥：{v.name}")
                continue
            was = prev[v.pubkey]
            if was and not v.online:
                self._append_log(f"「{v.name}」离线了（最后握手：{v.handshake}）")
            elif not was and v.online:
                self._append_log(f"「{v.name}」上线了")

    def _refresh_live_cells(self, views) -> None:
        """就地改几列，不重建列表 —— 重建会打断选中和滚动位置。"""
        items = self.tree.get_children()
        if len(items) != len(views):
            self._fill(views)  # 数量对不上，说明有人增删了，老实重建
            return
        by_key = {v.pubkey: v for v in views}
        for iid in items:
            v = by_key.get(self.row_keys.get(iid, ""))
            if v is None:
                self._fill(views)
                return
            for col, val in (
                ("handshake", v.handshake), ("traffic", v.traffic),
                ("endpoint", v.endpoint),
                ("expire", v.expire_text or "—"),
                ("status", "在线" if v.online else "离线/从未"),
            ):
                if str(self.tree.set(iid, col)) != str(val):
                    self.tree.set(iid, col, val)
            want = self._row_tag(v)
            cur = self.tree.item(iid, "tags")
            if not cur or cur[0] != want:
                self.tree.item(iid, tags=(want,))
        online = sum(1 for v in views if v.online)
        self.count_var.set(f"共 {len(views)} 个密钥（在线 {online}）")
        self._update_expire_bar(views)
        self._update_tray_state(views)

    def refresh(self) -> None:
        if not self.service:
            return
        self._async("刷新", lambda: self.service.list_peers(), self._fill)

    # ---------------------------------------------------------------- 新增
    def add_dialog(self) -> None:
        if not self.service:
            return
        dlg = AddDialog(self.root, self.dep, any(v.has_psk for v in self.views))
        self.root.wait_window(dlg.top)
        if not dlg.result:
            return
        params, save_file = dlg.result

        def work():
            return self.service.add_peer(**params)

        def done(result):
            path = ""
            file_name = ""
            if save_file:
                file_name = f"{safe_filename(result.name)}.conf"
                path = os.path.join(CLIENTS_DIR, file_name)
                try:
                    os.makedirs(CLIENTS_DIR, exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="\n") as f:
                        f.write(result.client_conf)
                except Exception as exc:
                    self._append_log(f"保存客户端配置失败：{exc}")
                    path = ""
            # 加密留一份：之后才能重看二维码、重新导出、换 IP 后重建配置
            if self.vault.put(result.public_key, result.name,
                              result.client_conf, file_name):
                self._append_log("客户端配置已加密保存，之后可随时重看二维码或重新导出")
            else:
                self._append_log("客户端配置没能加密保存 —— 关掉这个窗口就找不回了，"
                                 "请务必点「另存为」把 .conf 存下来")
            ClientConfDialog(self.root, result, path, self._append_log)
            self._append_log(f"服务器备份：{result.backup}")
            self._append_log(result.reload_msg)
            self.audit.record(
                "add", host=self._audit_host(), name=result.name,
                pubkey=result.public_key,
                detail=f"分配地址 {'、'.join(result.addresses)}",
                backup=result.backup,
            )
            self.refresh()

        self._async("新增密钥", work, done)

    # ---------------------------------------------------------------- 删除
    def delete_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("未选择", "请先在列表里选中要删除的密钥（可按住 Ctrl 多选）",
                                parent=self.root)
            return
        keys = {self.row_keys[i] for i in selected if i in self.row_keys}
        targets = [v for v in self.views if v.pubkey in keys]
        listing = "\n".join(
            f"  • {v.name}    {v.pubkey[:16]}…    {v.address}" for v in targets
        )
        if not messagebox.askyesno(
            "确认删除",
            f"即将从服务器删除 {len(targets)} 个密钥：\n\n{listing}\n\n"
            "这些客户端会立即失去 VPN 连接，且不可撤销（服务器会留一份配置备份）。\n确定继续吗？",
            icon="warning",
            parent=self.root,
        ):
            return

        def work():
            return self.service.remove_peers(keys)

        def done(names):
            # 密钥已经从服务器删掉，客户端配置再用不上了，顺手清掉免得越积越多
            for k in keys:
                self.vault.drop(k)
            self._append_log("已删除：" + "、".join(names))
            for view in targets:
                self.audit.record(
                    "delete", host=self._audit_host(), name=view.name,
                    pubkey=view.pubkey, detail=f"地址 {view.address or '-'}",
                )
            self.refresh()

        self._async("删除密钥", work, done)

    # ---------------------------------------------------------------- 编辑
    def edit_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("未选择", "请先在列表里选中要修改的密钥", parent=self.root)
            return
        if len(selected) > 1:
            messagebox.showinfo("只能改一个", "一次只能编辑一个密钥，请只选中一行",
                                parent=self.root)
            return
        key = self.row_keys.get(selected[0])
        view = next((v for v in self.views if v.pubkey == key), None)
        if not view:
            return

        dlg = EditDialog(self.root, view)
        self.root.wait_window(dlg.top)
        if not dlg.result:
            return
        params = dlg.result

        def work():
            return self.service.update_peer(view.pubkey, **params)

        def done(res):
            if not res.changed:
                self._append_log(f"「{view.name}」没有变化")
                return
            self._append_log(f"已修改「{res.name}」：{'、'.join(res.changed)}")
            self.vault.rename(res.public_key, res.name)
            self.audit.record(
                "edit", host=self._audit_host(), name=res.name,
                pubkey=res.public_key, detail="修改 " + "、".join(res.changed),
                backup=res.backup,
            )
            if res.backup:
                self._append_log(f"服务器备份：{res.backup}")
            if res.reload_msg:
                self._append_log(res.reload_msg)
            for note in res.warnings:
                self._append_log("注意：" + note)
            if res.address_changed:
                self._after_address_change(view, res)
            self.refresh()

        self._async("保存修改", work, done)

    def _after_address_change(self, view, res) -> None:
        """地址变了：提示客户端必须同步改，本地若有对应 .conf 就顺便改掉。"""
        new_addr = ", ".join(res.addresses) or res.new_allowed_ips
        lines = [
            f"「{res.name}」的 VPN 地址已改为：{new_addr}",
            f"（原来是 {res.old_allowed_ips}）",
            "",
            "这个客户端会立刻断线。需要在它的配置文件里把 Address 改成同样的值，",
            "保存后重新连接才能恢复。",
        ]
        for note in res.warnings:
            if "VPN 网段" in note:
                lines += ["", "⚠ " + note]

        candidates = []
        for label in {view.name, res.name}:
            path = os.path.join(CLIENTS_DIR, f"{safe_filename(label)}.conf")
            if os.path.isfile(path) and path not in candidates:
                candidates.append(path)

        if candidates:
            local = candidates[0]
            lines += ["", f"发现本机有它导出的配置：{local}"]
            if messagebox.askyesno(
                "地址已修改", "\n".join(lines) + "\n\n要顺便把该文件的 Address 行改掉吗？",
                icon="question", parent=self.root,
            ):
                try:
                    with open(local, encoding="utf-8") as f:
                        text = f.read()
                    patched = patch_client_conf(text, res.addresses)
                    with open(local, "w", encoding="utf-8", newline="\n") as f:
                        f.write(patched)
                    self._append_log(f"已同步修改本地配置：{local}")
                except Exception as exc:
                    self._append_log(f"修改本地配置失败：{exc}")
                    messagebox.showwarning(
                        "本地配置没改成",
                        f"{exc}\n\n请手工把 {local} 里的 Address 改成 {new_addr}",
                        parent=self.root,
                    )
            else:
                self._append_log(f"未修改本地配置 {local}，记得手工把 Address 改成 {new_addr}")
            return

        messagebox.showinfo(
            "地址已修改",
            "\n".join(lines) + "\n\n本机没有找到该客户端的 .conf（配置可能在别的设备上），"
            "请直接在那个设备上改。",
            parent=self.root,
        )

    # ------------------------------------------------------ 客户端配置保险箱
    def show_client_conf(self) -> None:
        """读取当初加密保存的客户端配置，重看二维码 / 重新导出 .conf。"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("未选择", "请先在列表里选中一条密钥", parent=self.root)
            return
        key = self.row_keys.get(selected[0])
        view = next((v for v in self.views if v.pubkey == key), None)
        if not view:
            return
        entry = self.vault.get(view.pubkey)
        if not entry:
            messagebox.showinfo(
                "本机没有它的客户端配置",
                f"「{view.name}」的客户端配置不在本机保险箱里。\n\n"
                "可能的原因：\n"
                "• 这条密钥不是本工具生成的（比如在服务器上手工加的）\n"
                "• 生成的那次加密保存失败了\n"
                "• 保险箱是在别的机器 / 别的 Windows 账号下建的，解不开\n\n"
                "服务端只存公钥，私钥拿不回来 —— 想重新给这个客户端配，"
                "只能删掉它再新增一条。",
                parent=self.root,
            )
            return
        SavedConfDialog(self.root, view.name, entry, self._append_log, note=view.note)

    # ---------------------------------------------------------------- 配置历史
    def show_history(self) -> None:
        if not self.service:
            messagebox.showinfo("还没连上", "先连上服务器，才能查看和还原配置历史",
                                parent=self.root)
            return
        host = (self.conn or {}).get("endpoint_host") or (self.conn or {}).get("host", "")
        HistoryDialog(self.root, self.history, host, self._append_log,
                      self._restore_snapshot,
                      open_dir=self.history.root, audit=self.audit)

    def show_traffic(self) -> None:
        if not self.service:
            messagebox.showinfo("还没连上", "先连上服务器，才能看流量趋势",
                                parent=self.root)
            return
        current = ""
        selected = self.tree.selection()
        if selected and selected[0] in self.row_keys:
            current = self.row_keys[selected[0]]
        TrafficDialog(self.root, self.traffic, self._entry_host(self.conn),
                      self.views, current)

    def _restore_snapshot(self, text: str, entry: dict) -> None:
        """把选中的快照写回服务器。走 service.restore，和普通改动同一套安全流程。"""
        def work():
            return self.service.restore(text, label=f"恢复到 {entry['time']} 的状态")

        def done(res):
            self._append_log(
                f"配置已还原到 {entry['time']} 的状态（{entry['action']}之前的快照）")
            if res.backup:
                self._append_log(f"还原前的状态也备份了一份：{res.backup}")
            if res.reload_msg:
                self._append_log(res.reload_msg)
            self.audit.record(
                "restore", host=self._audit_host(),
                detail=f"还原到 {entry['time']} 的快照（{entry['action']}之前）",
                backup=res.backup,
            )
            self.refresh()

        self._async("还原配置", work, done)

    # ---------------------------------------------------------------- 其它
    def _show_selected_detail(self) -> None:
        selected = self.tree.selection()
        if not selected or not self.views:
            return
        key = self.row_keys.get(selected[0])
        view = next((v for v in self.views if v.pubkey == key), None)
        if not view:
            return
        DetailDialog(self.root, view)

    def _open_clients_dir(self) -> None:
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        try:
            os.startfile(CLIENTS_DIR)  # noqa: S606 - Windows only
        except Exception:
            messagebox.showinfo("客户端配置目录", CLIENTS_DIR, parent=self.root)

    def _show_diagnostics(self) -> None:
        if not self.dep:
            messagebox.showinfo("探测详情", "尚未连接服务器", parent=self.root)
            return
        text = "自动探测结果：\n\n  • " + "\n  • ".join(self.dep.diagnostics)
        text += "\n\n服务端公钥：" + (self.dep.server_public_key or "未识别")
        text += f"\nDNS：{', '.join(self.dep.dns)}"
        text += f"\n接口状态：{'运行中' if self.dep.interface_up else '未启动'}"
        text += f"\nSaveConfig：{'开启（有风险）' if self.dep.save_config else '关闭'}"
        if self.dep.notes:
            text += "\n\n提示：\n  • " + "\n  • ".join(self.dep.notes)
        messagebox.showinfo("探测详情", text, parent=self.root)

    def _advanced_dialog(self) -> None:
        AdvancedDialog(self.root, self.adv_conf, self.adv_iface, self.adv_endpoint)

    def _help_dialog(self) -> None:
        messagebox.showinfo("使用帮助", HELP_TEXT, parent=self.root)

    def _downloads_dialog(self) -> None:
        DownloadDialog(self.root)

    def _on_auth_change(self) -> None:
        if self.demo_var.get():
            return
        pwd = self.auth_var.get() == "password"
        self.pwd_entry.configure(state="normal" if pwd else "disabled")
        self.key_entry.configure(state="disabled" if pwd else "normal")
        self.key_browse.configure(state="disabled" if pwd else "normal")
        self.keypass_entry.configure(state="disabled" if pwd else "normal")

    def _on_demo_toggle(self) -> None:
        demo = self.demo_var.get()
        state = "disabled" if demo else "normal"
        for widget in (self.host_entry, self.port_entry, self.user_entry,
                       self.pwd_entry, self.key_entry, self.key_browse,
                       self.keypass_entry, self.sudo_pwd_entry,
                       self.rb_pwd, self.rb_key):
            widget.configure(state=state)
        if not demo:
            self._on_auth_change()
        self._append_log("演示模式已" + ("开启：所有操作只作用于本机内存中的模拟服务器" if demo else "关闭"))

    def _browse_key(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 SSH 私钥文件",
            filetypes=[("所有文件", "*.*"), ("PEM/OpenSSH 私钥", "*.pem;*.key;*.ppk")],
        )
        if path:
            self.key_var.set(path)

    def _save_current_profile(self, conn: dict) -> None:
        if conn.get("demo"):
            return
        remember = bool(self.remember_var.get())
        profile = {
            "host": conn["host"], "port": conn["port"],
            "username": conn["username"], "auth": conn["auth"],
            "key_path": conn.get("key_path", ""),
        }
        if remember:
            # 只存加密后的口令，密码本身绝不明文落盘。protect() 失败会返回空串，
            # 那就等于没存 —— 降级成"每次重输"，绝不退回明文。
            for field in ("password", "key_passphrase", "sudo_password"):
                sealed = protect(conn.get(field, ""))
                if sealed:
                    profile[field] = sealed
        key = _profile_key(profile)
        profiles = [p for p in _load_profiles() if _profile_key(p) != key]
        profiles.insert(0, profile)
        _save_profiles(profiles)
        self._refresh_profile_combo()
        self._refresh_server_combo()
        if remember and not getattr(self, "_sealed_hint_done", False):
            self._sealed_hint_done = True
            self._log("口令已加密保存在 connections.json（Windows DPAPI，"
                      "换机器或换 Windows 账号后需要重新输入）。")

    def _refresh_profile_combo(self) -> None:
        profiles = _load_profiles()
        self._profiles = profiles
        # 带上端口：同一个 IP 用不同端口/账号是两条配置，只显示 IP 会分不清
        self.profile_combo["values"] = [
            f"{p.get('host', '')}:{p.get('port', 22)} ({p.get('username', '')})"
            for p in profiles
        ]

    def _on_profile_selected(self, _event=None) -> None:
        idx = self.profile_combo.current()
        if idx < 0 or idx >= len(getattr(self, "_profiles", [])):
            return
        p = self._profiles[idx]
        self.host_var.set(p.get("host", ""))
        self.port_var.set(str(p.get("port", 22)))
        self.user_var.set(p.get("username", "root"))
        self.auth_var.set(p.get("auth", "password"))
        self.key_var.set(p.get("key_path", ""))
        # 解不开就是空串（换机器/换账号/文件被改），让用户重输即可，
        # 不弹错误框打断 —— 这只是"没记住"，不是故障。
        self.password_var.set(unprotect(p.get("password", "")))
        self.key_pass_var.set(unprotect(p.get("key_passphrase", "")))
        self.sudo_pwd_var.set(unprotect(p.get("sudo_password", "")))
        self.remember_var.set(
            any(is_sealed(p.get(k)) for k in ("password", "key_passphrase", "sudo_password"))
        )
        self._on_auth_change()

    def _on_close(self) -> None:
        """点窗口的 ×：托盘在跑就藏起来，否则真的退出。"""
        if (self.tray and self.tray.running
                and self.settings.get("minimize_to_tray", True)):
            self.root.withdraw()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.notify("程序还在后台运行，右键托盘图标可以退出",
                                 "已最小化到托盘")
            return
        self._really_quit()

    def _really_quit(self) -> None:
        self._cancel_monitor()
        # 事件泵也要停：窗口销毁后这个 after 还在队列里，
        # 触发时会报 invalid command name "..._poll"
        if self._poll_job is not None:
            try:
                self.root.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None
        if self.tray is not None:
            self.tray.stop()
            self.tray = None
        for entry in list(self.servers.values()):
            self._close_entry(entry)
        # 安装流程里那条连接还没注册进 servers，单独关一次
        if self.backend and self.backend not in [
            e["backend"] for e in self.servers.values()
        ]:
            try:
                self.backend.close()
            except Exception:
                pass
        self.root.destroy()

    # ------------------------------------------------------ 托盘 / 设置
    def show_settings(self) -> None:
        SettingsDialog(self.root, self)

    def show_window(self) -> None:
        """托盘菜单「显示主窗口」：从最小化状态恢复并提到最前。"""
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def _start_tray_if_enabled(self) -> None:
        """启动后延迟开托盘：先让主窗口出来，别让托盘抢在前面。"""
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return
        self._apply_tray(True)

    def _apply_tray(self, enable: bool) -> None:
        if enable:
            if self.tray is None:
                if not tray_mod.available():
                    self._append_log("托盘不可用：缺少 pystray 或 Pillow")
                    self.settings.set("tray_enabled", False)
                    return
                self.tray = tray_mod.Tray(
                    self.root,
                    on_show=self.show_window,
                    on_quit=self._really_quit,
                    on_check_update=self.check_update,
                )
            if not self.tray.start():
                self._append_log("托盘启动失败，关闭窗口将直接退出")
                self.tray = None
                self.settings.set("tray_enabled", False)
                return
            self._append_log("已启用系统托盘，关掉窗口会最小化到这里")
        else:
            if self.tray is not None:
                self.tray.stop()
                self.tray = None
                self._append_log("已关闭系统托盘")
            self.show_window()
        self.settings.set("tray_enabled", enable)

    def _update_tray_state(self, views) -> None:
        if not (self.tray and self.tray.running):
            return
        urgent = any(
            v.expired or (v.expire_days is not None and v.expire_days <= 0)
            for v in (views or [])
        )
        self.tray.set_state("alert" if urgent else "ok")

    def run(self) -> None:
        self.root.mainloop()


# ------------------------------------------------------------------------ 对话框


class AddDialog:
    def __init__(self, parent, dep, default_psk: bool):
        self.result = None
        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("新增密钥")
        top.resizable(False, False)

        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)

        self.name = tk.StringVar()
        self.note = tk.StringVar()
        self.allowed = tk.StringVar(value="0.0.0.0/0, ::/0")
        self.dns = tk.StringVar(value=", ".join(dep.dns))
        self.endpoint = tk.StringVar(value=f"{dep.endpoint_host}:{dep.listen_port}")
        self.vpn_addresses = tk.StringVar()
        self.expire = tk.StringVar()
        self.psk = tk.BooleanVar(value=default_psk)
        self.save_file = tk.BooleanVar(value=True)

        rows = [
            ("密钥名称 *：", self.name, "例如 张三-手机，必填，方便以后知道该删哪个"),
            ("备注：", self.note, "选填，例如 研发部 / 2026年入职领用"),
            ("客户端 AllowedIPs：", self.allowed, "0.0.0.0/0, ::/0 = 全部流量走 VPN"),
            ("DNS：", self.dns, "客户端使用的 DNS"),
            ("服务端 Endpoint：", self.endpoint, "客户端连哪个地址，默认用 SSH 的 IP"),
            ("指定 VPN 地址：", self.vpn_addresses, "留空 = 自动分配空闲地址（推荐）"),
            ("有效期至：", self.expire, "YYYY-MM-DD，留空 = 永久"),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(frame, text=label, width=20, anchor="e").grid(row=i, column=0, sticky="e", pady=4)
            ttk.Entry(frame, textvariable=var, width=46).grid(row=i, column=1, sticky="w", pady=2)
            ttk.Label(frame, text=hint, foreground="#777777").grid(
                row=i, column=2, sticky="w", padx=(10, 0)
            )

        checks = ttk.Frame(frame)
        checks.grid(row=len(rows), column=1, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Checkbutton(checks, text="使用预共享密钥 PresharedKey", variable=self.psk).pack(anchor="w")
        ttk.Checkbutton(checks, text="同时把客户端 .conf 保存到 clients/ 目录（强烈建议）",
                        variable=self.save_file).pack(anchor="w", pady=(4, 0))
        quick = ttk.Frame(checks)
        quick.pack(anchor="w", pady=(8, 0))
        ttk.Label(quick, text="有效期快捷键：", foreground="#777777").pack(side="left")
        for text, days in (("7 天", 7), ("30 天", 30), ("90 天", 90)):
            ttk.Button(quick, text=text, width=6,
                       command=lambda d=days: self._set_expire(d)).pack(
                side="left", padx=(4, 0))
        ttk.Button(quick, text="永久", width=6,
                   command=lambda: self.expire.set("")).pack(side="left", padx=(4, 0))
        ttk.Label(
            frame,
            text="注意：客户端私钥只会在生成时出现这一次，服务端只保存公钥，之后无法重新导出，请务必保存 .conf。",
            foreground="#a05000", wraplength=560, justify="left",
        ).grid(row=len(rows) + 1, column=0, columnspan=3, sticky="w", pady=(12, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 2, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(buttons, text="生成密钥", width=14, style="Accent.TButton",
                   command=self._ok).pack(side="right", padx=4)
        ttk.Button(buttons, text="取消", width=10, command=top.destroy).pack(side="right", padx=4)
        top.bind("<Return>", lambda _e: self._ok())
        top.bind("<Escape>", lambda _e: top.destroy())
        show_dialog(top, parent, modal=True)

    def _set_expire(self, days: int) -> None:
        self.expire.set((dt.date.today() + dt.timedelta(days=days)).strftime("%Y-%m-%d"))

    def _ok(self) -> None:
        if not self.name.get().strip():
            messagebox.showwarning("缺少名称", "请填写密钥名称", parent=self.top)
            return
        expire = self.expire.get().strip()
        if expire and not parse_expire_date(expire):
            messagebox.showwarning("日期格式不对",
                                   "有效期请写成 2026-11-12 这种格式，或点下面的快捷键",
                                   parent=self.top)
            return
        params = {
            "name": self.name.get().strip(),
            "note": self.note.get().strip(),
            "client_allowed_ips": self.allowed.get().strip() or "0.0.0.0/0, ::/0",
            "dns": [d.strip() for d in self.dns.get().split(",") if d.strip()],
            "endpoint": self.endpoint.get().strip(),
            "use_psk": self.psk.get(),
            "vpn_addresses": self.vpn_addresses.get().strip(),
            "expire": expire,
        }
        self.result = (params, self.save_file.get())
        self.top.destroy()


class EditDialog:
    """修改已有密钥：名称 / 备注 / VPN 地址。

    公钥和预共享密钥不允许改——前者是身份，后者改了等于重发密钥，
    真要换只能删掉重建。
    """

    def __init__(self, parent, view):
        self.result = None
        self.view = view
        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("编辑密钥")
        top.resizable(False, False)

        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)

        self.name = tk.StringVar(value=view.raw_name)
        self.note = tk.StringVar(value=view.note)
        self.addr = tk.StringVar(value=view.allowed_ips)
        self.expire = tk.StringVar(value=view.expire)

        rows = [
            ("名称 *：", self.name, "只影响显示，不动密钥本身"),
            ("备注：", self.note, "选填，例如 研发部 / 张三的手机"),
            ("VPN 地址：", self.addr, "多个用逗号分隔，如 10.8.0.9/32, fd08::9/128"),
            ("有效期至：", self.expire, "YYYY-MM-DD，留空 = 永久"),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(frame, text=label, width=13, anchor="e").grid(
                row=i, column=0, sticky="e", pady=4
            )
            ttk.Entry(frame, textvariable=var, width=46).grid(
                row=i, column=1, sticky="w", pady=2
            )
            ttk.Label(frame, text=hint, foreground="#777777").grid(
                row=i, column=2, sticky="w", padx=(10, 0)
            )

        key_row = ttk.Frame(frame)
        key_row.grid(row=len(rows), column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(key_row, text="公钥：", width=13, anchor="e").pack(side="left")
        ttk.Label(key_row, text=view.pubkey, font=("Consolas", 9)).pack(side="left")
        ttk.Label(key_row, text="（不可修改）", foreground="#777777").pack(side="left", padx=(6, 0))

        quick = ttk.Frame(frame)
        quick.grid(row=len(rows) + 1, column=1, sticky="w", pady=(4, 0))
        ttk.Label(quick, text="有效期快捷键：", foreground="#777777").pack(side="left")
        for text, days in (("7 天", 7), ("30 天", 30), ("90 天", 90)):
            ttk.Button(quick, text=text, width=6,
                       command=lambda d=days: self._set_expire(d)).pack(
                side="left", padx=(4, 0))
        ttk.Button(quick, text="永久", width=6,
                   command=lambda: self.expire.set("")).pack(side="left", padx=(4, 0))

        ttk.Label(
            frame,
            text="改名称、备注、有效期只动配置文件里的注释，对已连接的隧道没有影响；\n"
                 "改 VPN 地址会让该客户端立即断线，必须同步修改客户端配置里的 Address。",
            foreground="#a05000", wraplength=620, justify="left",
        ).grid(row=len(rows) + 2, column=0, columnspan=3, sticky="w", pady=(12, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 3, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(buttons, text="保存修改", width=14, style="Accent.TButton",
                   command=self._ok).pack(side="right", padx=4)
        ttk.Button(buttons, text="取消", width=10, command=top.destroy).pack(side="right", padx=4)
        top.bind("<Return>", lambda _e: self._ok())
        top.bind("<Escape>", lambda _e: top.destroy())
        show_dialog(top, parent, modal=True)

    def _set_expire(self, days: int) -> None:
        self.expire.set((dt.date.today() + dt.timedelta(days=days)).strftime("%Y-%m-%d"))

    def _ok(self) -> None:
        name = self.name.get().strip()
        if not name:
            messagebox.showwarning("缺少名称", "请填写密钥名称", parent=self.top)
            return
        try:
            addr = normalize_allowed_ips(self.addr.get())
        except ValueError as exc:
            messagebox.showwarning("地址格式不对", str(exc), parent=self.top)
            return

        expire = self.expire.get().strip()
        if expire and not parse_expire_date(expire):
            messagebox.showwarning("日期格式不对",
                                   "有效期请写成 2026-11-12 这种格式，或点下面的快捷键",
                                   parent=self.top)
            return

        self.addr.set(addr)
        if (
            name == (self.view.raw_name or "")
            and self.note.get().strip() == (self.view.note or "")
            and addr == (self.view.allowed_ips or "")
            and expire == (self.view.expire or "")
        ):
            self.top.destroy()  # 一个字都没改，直接关掉
            return

        self.result = {
            "name": name,
            "note": self.note.get().strip(),
            "allowed_ips": addr,
            "expire": expire,
        }
        self.top.destroy()


def _save_card(parent, conf_text: str, name: str, note: str, log,
               expire: str = "") -> None:
    """生成可发微信的分发卡片（二维码 + 名称 + 服务器 + 备注合成一张图）。"""
    path = filedialog.asksaveasfilename(
        parent=parent, title="保存分发卡片",
        initialfile=f"{safe_filename(name)}-卡片.png",
        defaultextension=".png",
        filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")],
    )
    if not path:
        return
    try:
        from .card import endpoint_of, render_card

        # 服务器地址直接从配置里取，省得调用方还得单独传一遍
        render_card(conf_text, name=name, note=note,
                    endpoint=endpoint_of(conf_text), expire=expire,
                    out_path=path)
    except Exception as exc:
        messagebox.showwarning(
            "生成卡片失败",
            f"{exc}\n\n可以直接用「生成二维码」代替。",
            parent=parent,
        )
        return
    log(f"分发卡片已保存到 {path}")


class ClientConfDialog:
    def __init__(self, parent, result, saved_path: str, log):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title(f"密钥「{result.name}」已创建")
        frame = ttk.Frame(top, padding=14)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text=f"名称：{result.name}    VPN 地址：{', '.join(result.addresses)}\n"
                 f"公钥：{result.public_key}\n服务器备份：{result.backup}",
            justify="left", wraplength=640,
        ).pack(fill="x", pady=(0, 8))
        ttk.Label(frame, text="客户端配置（含私钥，请妥善保管）：",
                  foreground="#a05000").pack(anchor="w")
        text = scrolledtext.ScrolledText(frame, height=16, font=("Consolas", 10))
        text.pack(fill="both", expand=True, pady=6)
        text.insert("1.0", result.client_conf)
        text.configure(state="disabled")

        if saved_path:
            ttk.Label(frame, text=f"已自动保存到：{saved_path}",
                      foreground="#0a7a3d").pack(anchor="w")

        link = ttk.Label(frame, text="还没装 WireGuard 客户端？点这里下载（安卓 / iOS / Windows）",
                         foreground="#0a5bd3", cursor="hand2")
        link.pack(anchor="w", pady=(6, 0))
        link.bind("<Button-1>", lambda _e: DownloadDialog(top))

        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(8, 0))

        def copy_all():
            top.clipboard_clear()
            top.clipboard_append(result.client_conf)
            log("客户端配置已复制到剪贴板")

        def save_as():
            path = filedialog.asksaveasfilename(
                parent=top, title="保存客户端配置",
                initialfile=f"{safe_filename(result.name)}.conf",
                defaultextension=".conf",
                filetypes=[("WireGuard 配置", "*.conf"), ("所有文件", "*.*")],
            )
            if path:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(result.client_conf)
                log(f"客户端配置已另存为 {path}")

        ttk.Button(bar, text="复制全部", width=12, command=copy_all).pack(side="left")
        ttk.Button(bar, text="另存为…", width=12, command=save_as).pack(side="left", padx=6)
        ttk.Button(bar, text="生成二维码", width=12, style="Accent.TButton",
                   command=lambda: QrDialog(
                       top, f"「{result.name}」的二维码", result.client_conf,
                       safe_filename(result.name), log,
                   )).pack(side="left")
        ttk.Button(bar, text="生成卡片", width=12,
                   command=lambda: _save_card(
                       top, result.client_conf, result.name,
                       getattr(result, "note", ""), log,
                       getattr(result, "expire", ""),
                   )).pack(side="left", padx=6)
        ttk.Button(bar, text="关闭", width=10, command=top.destroy).pack(side="right")
        show_dialog(top, parent, width=700, height=520)


class SavedConfDialog:
    """展示保险箱里存着的客户端配置 —— 生成那次没另存 .conf 也能重来一遍。"""

    def __init__(self, parent, name: str, entry: dict, log, note: str = ""):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title(f"「{name}」的客户端配置")
        frame = ttk.Frame(top, padding=14)
        frame.pack(fill="both", expand=True)

        created = (entry.get("created") or "").replace("T", " ")
        ttk.Label(
            frame,
            text=f"名称：{name}    保存于：{created or '未知'}\n"
                 "以下内容含客户端私钥，可直接导入手机 / 电脑的 WireGuard 客户端，别外传。",
            justify="left", wraplength=640,
        ).pack(fill="x", pady=(0, 8))

        text = scrolledtext.ScrolledText(frame, height=16, font=("Consolas", 10))
        text.pack(fill="both", expand=True, pady=6)
        text.insert("1.0", entry["conf"])
        text.configure(state="disabled")

        link = ttk.Label(frame, text="还没装 WireGuard 客户端？点这里下载（安卓 / iOS / Windows）",
                         foreground="#0a5bd3", cursor="hand2")
        link.pack(anchor="w", pady=(6, 0))
        link.bind("<Button-1>", lambda _e: DownloadDialog(top))

        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(8, 0))

        def copy_all():
            top.clipboard_clear()
            top.clipboard_append(entry["conf"])
            log("客户端配置已复制到剪贴板")

        def save_as():
            path = filedialog.asksaveasfilename(
                parent=top, title="保存客户端配置",
                initialfile=f"{safe_filename(name)}.conf",
                defaultextension=".conf",
                filetypes=[("WireGuard 配置", "*.conf"), ("所有文件", "*.*")],
            )
            if path:
                try:
                    with open(path, "w", encoding="utf-8", newline="\n") as f:
                        f.write(entry["conf"])
                except Exception as exc:
                    messagebox.showwarning("保存失败", str(exc), parent=top)
                    return
                log(f"客户端配置已另存为 {path}")

        ttk.Button(bar, text="复制全部", width=12, command=copy_all).pack(side="left")
        ttk.Button(bar, text="另存为…", width=12, command=save_as).pack(side="left", padx=6)
        ttk.Button(bar, text="生成二维码", width=12, style="Accent.TButton",
                   command=lambda: QrDialog(
                       top, f"「{name}」的二维码", entry["conf"],
                       safe_filename(name), log,
                   )).pack(side="left")
        ttk.Button(bar, text="生成卡片", width=12,
                   command=lambda: _save_card(
                       top, entry["conf"], name, note, log,
                   )).pack(side="left", padx=6)
        ttk.Button(bar, text="关闭", width=10, command=top.destroy).pack(side="right")
        show_dialog(top, parent, width=700, height=520)


class HistoryDialog:
    """历史记录：配置快照可还原，操作日志可追溯。

    两件事都是「回溯过去发生了什么」，放同一个窗口的两个标签页，
    省得工具栏再挤一个按钮 —— 那排已经排满了。
    """

    def __init__(self, parent, history, host: str, log, restore_cb,
                 open_dir: str = "", audit=None):
        self.history = history
        self.host = host
        self.log = log
        self.restore_cb = restore_cb
        self.audit = audit
        self.dir_path = open_dir or getattr(history, "root", "")
        self._rows: dict[str, dict] = {}
        self._current: tuple[str, dict] | None = None
        self._audit_rows: list[dict] = []

        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("历史记录")
        frame = ttk.Frame(top, padding=12)
        frame.pack(fill="both", expand=True)

        self.nb = ttk.Notebook(frame)
        self.nb.pack(fill="both", expand=True)

        snap = ttk.Frame(self.nb, padding=(0, 8, 0, 0))
        self.nb.add(snap, text="   配置快照   ")
        self._build_snapshot(snap)

        rec = ttk.Frame(self.nb, padding=(0, 8, 0, 0))
        self.nb.add(rec, text="   操作记录   ")
        self._build_records(rec)

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Button(bottom, text="关闭", width=10,
                   command=top.destroy).pack(side="right")

        self._load()
        if self.audit:
            self.rec_host_combo["values"] = ["全部"] + self.audit.hosts()
        self._load_records()
        show_dialog(top, parent, width=940, height=620)

    # ------------------------------------------------------------ 配置快照
    def _build_snapshot(self, parent) -> None:
        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body)
        left.pack(side="left", fill="y")
        cols = ("time", "action", "summary", "peers")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=15)
        for col, title, width in (
            ("time", "时间", 132), ("action", "操作", 82),
            ("summary", "摘要", 225), ("peers", "密钥数", 58),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=48, anchor="w")
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="y", expand=True)
        vsb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.preview = scrolledtext.ScrolledText(right, height=15, wrap="none",
                                                 font=("Consolas", 9))
        self.preview.pack(fill="both", expand=True)
        self.preview.configure(state="disabled")

        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(10, 0))
        self.restore_btn = ttk.Button(bar, text="还原到此版本", width=15,
                                      style="Accent.TButton", command=self._restore,
                                      state="disabled")
        self.restore_btn.pack(side="left")
        ttk.Button(bar, text="打开历史目录", width=14,
                   command=self._open_dir).pack(side="left", padx=6)
        self.hint = ttk.Label(bar, text="", foreground="#8a8a8a")
        self.hint.pack(side="right", padx=10)

    def _load(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._rows = {}
        entries = self.history.entries(self.host)
        for entry in entries:
            iid = self.tree.insert("", "end", values=(
                (entry.get("time") or "").replace("T", " "),
                entry.get("action", ""),
                entry.get("summary", ""),
                entry.get("peers", 0),
            ))
            self._rows[iid] = entry
        self.hint.configure(text=f"共 {len(entries)} 条快照")

    def _on_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        entry = self._rows.get(selected[0])
        if not entry:
            return
        text = self.history.read(entry["id"])
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text or "（这份快照的文件已经不在了）")
        self.preview.configure(state="disabled")
        self._current = (text, entry)
        self.restore_btn.configure(state="normal" if text else "disabled")

    def _restore(self) -> None:
        if not self._current:
            return
        text, entry = self._current
        when = (entry.get("time") or "").replace("T", " ")
        if not messagebox.askyesno(
            "确认还原",
            f"把服务器配置还原到 {when} 的状态？\n\n"
            f"那份快照里有 {entry.get('peers', 0)} 个密钥，"
            "还原后服务器上就是这个数量。\n\n"
            "还原前会先备份当前配置，替换后自动热加载。\n"
            "还原错了也没关系 —— 当前状态同样会进历史，可以再退回来。",
            icon="question", parent=self.top,
        ):
            return
        self.top.destroy()
        self.restore_cb(text, entry)

    def _open_dir(self) -> None:
        try:
            os.startfile(self.dir_path)  # noqa: S606 - Windows only
        except Exception:
            messagebox.showinfo("历史目录", self.dir_path, parent=self.top)

    # ------------------------------------------------------------ 操作记录
    def _build_records(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        ttk.Label(bar, text="服务器：").pack(side="left")
        self.rec_host = tk.StringVar(value="全部")
        self.rec_host_combo = ttk.Combobox(bar, textvariable=self.rec_host,
                                           state="readonly", width=26,
                                           values=["全部"])
        self.rec_host_combo.pack(side="left")
        self.rec_host_combo.bind("<<ComboboxSelected>>",
                                 lambda _e: self._load_records())

        ttk.Label(bar, text="动作：").pack(side="left", padx=(12, 0))
        self.rec_action = tk.StringVar(value="全部")
        self.rec_action_combo = ttk.Combobox(
            bar, textvariable=self.rec_action, state="readonly", width=11,
            values=["全部"] + list(ACTION_LABELS.values()))
        self.rec_action_combo.pack(side="left")
        self.rec_action_combo.bind("<<ComboboxSelected>>",
                                   lambda _e: self._load_records())

        ttk.Label(bar, text="搜索：").pack(side="left", padx=(12, 0))
        self.rec_kw = tk.StringVar()
        kw = ttk.Entry(bar, textvariable=self.rec_kw, width=16)
        kw.pack(side="left")
        kw.bind("<Return>", lambda _e: self._load_records())
        ttk.Button(bar, text="筛选", width=7,
                   command=self._load_records).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="重置", width=7,
                   command=self._reset_records).pack(side="left", padx=(4, 0))

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, pady=(8, 0))
        cols = ("time", "action", "host", "name", "detail", "result", "user")
        self.rec_tree = ttk.Treeview(body, columns=cols, show="headings", height=15)
        for col, title, width in (
            ("time", "时间", 142), ("action", "动作", 78),
            ("host", "服务器", 185), ("name", "密钥", 118),
            ("detail", "详情", 230), ("result", "结果", 54),
            ("user", "操作者", 70),
        ):
            self.rec_tree.heading(col, text=title)
            self.rec_tree.column(col, width=width, minwidth=44, anchor="w")
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.rec_tree.yview)
        self.rec_tree.configure(yscrollcommand=vsb.set)
        self.rec_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        foot = ttk.Frame(parent)
        foot.pack(fill="x", pady=(10, 0))
        ttk.Button(foot, text="导出 CSV", width=12,
                   command=self._export).pack(side="left")
        self.rec_hint = ttk.Label(foot, text="", foreground="#8a8a8a")
        self.rec_hint.pack(side="right", padx=10)

    def _load_records(self) -> None:
        for iid in self.rec_tree.get_children():
            self.rec_tree.delete(iid)
        self._audit_rows = []
        if not self.audit:
            self.rec_hint.configure(text="未启用操作记录")
            return
        label = self.rec_action.get()
        rows = self.audit.rows(
            limit=1000,
            host="" if self.rec_host.get() == "全部" else self.rec_host.get(),
            action="" if label == "全部" else _ACTION_BY_LABEL.get(label, ""),
            keyword=self.rec_kw.get().strip(),
        )
        self._audit_rows = rows
        for r in rows:
            self.rec_tree.insert("", "end", values=(
                r.get("ts", ""),
                ACTION_LABELS.get(r.get("action", ""), r.get("action", "")),
                r.get("host", ""),
                r.get("name", "") or "—",
                r.get("detail", ""),
                "成功" if r.get("result") == "ok" else "失败",
                r.get("user", ""),
            ))
        self.rec_hint.configure(text=f"共 {len(rows)} 条")

    def _reset_records(self) -> None:
        self.rec_host.set("全部")
        self.rec_action.set("全部")
        self.rec_kw.set("")
        self._load_records()

    def _export(self) -> None:
        if not self._audit_rows:
            messagebox.showinfo("没有记录", "当前筛选条件下没有可导出的记录",
                                parent=self.top)
            return
        default = f"操作记录-{dt.datetime.now():%Y%m%d-%H%M}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.top, defaultextension=".csv", initialfile=default,
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            n = export_csv(self._audit_rows, path)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc), parent=self.top)
            return
        self.rec_hint.configure(text=f"已导出 {n} 条到 {os.path.basename(path)}")
        self.log(f"操作记录已导出：{path}")


TRAFFIC_RANGES = [
    ("最近 1 小时", 3600),
    ("最近 6 小时", 6 * 3600),
    ("最近 24 小时", 86400),
    ("最近 7 天", 7 * 86400),
]
TRAFFIC_DOWN = "#1f8a4c"
TRAFFIC_UP = "#c26a00"


class TrafficDialog:
    """单个密钥的流量趋势。

    数据来自后台每 5 分钟一次的采样 —— `wg show transfer` 只有累计值，
    速率是相邻两次做差算出来的。所以工具没运行的那段时间没有数据，
    图上会是空的，这不是 bug。
    """

    def __init__(self, parent, store, host: str, views, current_pubkey: str = ""):
        self.store = store
        self.host = host
        self.views = list(views or [])
        self.pubkeys = [v.pubkey for v in self.views]
        self.name_of = {v.pubkey: v.name for v in self.views}
        labels = [f"{v.name} · {v.address or '无地址'}" for v in self.views]
        self.labels = labels
        self._geom = None
        self._points: list[tuple] = []

        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("流量趋势")
        frame = ttk.Frame(top, padding=12)
        frame.pack(fill="both", expand=True)

        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="密钥：").pack(side="left")
        self.peer_var = tk.StringVar()
        self.peer_combo = ttk.Combobox(
            bar, textvariable=self.peer_var, state="readonly", width=34,
            values=labels or ["（没有密钥）"])
        self.peer_combo.pack(side="left")
        self.peer_combo.bind("<<ComboboxSelected>>", lambda _e: self._redraw())

        ttk.Label(bar, text="范围：").pack(side="left", padx=(14, 0))
        self.range_var = tk.StringVar(value=TRAFFIC_RANGES[2][0])
        self.range_combo = ttk.Combobox(
            bar, textvariable=self.range_var, state="readonly", width=12,
            values=[r[0] for r in TRAFFIC_RANGES])
        self.range_combo.pack(side="left")
        self.range_combo.bind("<<ComboboxSelected>>", lambda _e: self._redraw())
        ttk.Button(bar, text="刷新", width=8,
                   command=self._redraw).pack(side="left", padx=(10, 0))

        self.canvas = tk.Canvas(frame, height=300, background="#ffffff",
                                highlightthickness=1,
                                highlightbackground="#d8d8d8")
        self.canvas.pack(fill="both", expand=True, pady=(10, 6))
        self.canvas.bind("<Configure>", lambda _e: self._redraw())
        self.canvas.bind("<Motion>", self._on_hover)
        self.canvas.bind("<Leave>", lambda _e: self.canvas.delete("hover"))

        foot = ttk.Frame(frame)
        foot.pack(fill="x")
        for color, text in ((TRAFFIC_DOWN, "下行"), (TRAFFIC_UP, "上行")):
            box = ttk.Frame(foot)
            box.pack(side="left", padx=(0, 14))
            tk.Canvas(box, width=16, height=4, background=color,
                      highlightthickness=0).pack(side="left", pady=8)
            ttk.Label(box, text=text).pack(side="left", padx=(5, 0))
        ttk.Button(foot, text="关闭", width=10,
                   command=top.destroy).pack(side="right")
        self.stats = ttk.Label(foot, text="", foreground="#555555")
        self.stats.pack(side="right", padx=(0, 14))

        self.hint = ttk.Label(frame, text="", foreground="#8a8a8a",
                              wraplength=780, justify="left")
        self.hint.pack(fill="x", pady=(6, 0))

        if current_pubkey in self.pubkeys:
            self.peer_combo.current(self.pubkeys.index(current_pubkey))
        elif labels:
            self.peer_combo.current(0)
        else:
            self.peer_var.set("（没有密钥）")

        show_dialog(top, parent, width=840, height=540)
        # 窗口刚映射时 winfo_width 还是 1，等布局稳定再画一次
        top.after(80, self._redraw)
        self._redraw()

    # ------------------------------------------------------------ 绘制
    def _range_seconds(self) -> int:
        label = self.range_var.get()
        for text, secs in TRAFFIC_RANGES:
            if text == label:
                return secs
        return 86400

    def _empty(self, message: str) -> None:
        self._points = []
        self._geom = None
        self.canvas.delete("all")
        w = max(self.canvas.winfo_width(), 200)
        h = max(self.canvas.winfo_height(), 150)
        self.canvas.create_text(w / 2, h / 2, text=message, fill="#999999",
                                justify="center", width=max(w - 60, 160),
                                font=(CN_FONT, 10))
        self.stats.configure(text="")
        self.hint.configure(text="")

    def _redraw(self) -> None:
        self.canvas.delete("all")
        idx = self.peer_combo.current()
        if idx < 0 or idx >= len(self.pubkeys):
            self._empty("还没有可选的密钥")
            return
        pubkey = self.pubkeys[idx]
        name = self.name_of.get(pubkey, "")
        span = self.store.span(self.host, pubkey)
        if not span:
            self._empty(f"「{name}」还没有采样数据\n\n"
                        "工具每 5 分钟采一次，连上服务器后放着不动就会慢慢积累。")
            return

        seconds = self._range_seconds()
        now = time.time()
        since = now - seconds
        points = self.store.rates(self.host, pubkey, since=since)
        if not points:
            self._empty(f"「{name}」在「{self.range_var.get()}」内没有有效采样\n\n"
                        "换一个更长的时间范围试试。")
            return

        self._points = points
        w = max(self.canvas.winfo_width(), 240)
        h = max(self.canvas.winfo_height(), 180)
        pad_l, pad_r, pad_t, pad_b = 78, 18, 16, 30
        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b
        if plot_w < 60 or plot_h < 40:
            return

        peak = max(max(p[1] for p in points), max(p[2] for p in points), 1.0)
        ymax = nice_rate_ceiling(peak)
        t0, t1 = since, now
        self._geom = (pad_l, plot_w, t0, t1, ymax, pad_t, plot_h)

        # 横向网格 + Y 轴刻度
        for i in range(5):
            y = pad_t + plot_h * i / 4
            self.canvas.create_line(pad_l, y, pad_l + plot_w, y, fill="#ededed")
            self.canvas.create_text(pad_l - 8, y, anchor="e", fill="#888888",
                                    font=(CN_FONT, 8),
                                    text=human_rate(ymax * (1 - i / 4)))

        # X 轴时间标签
        for i in range(5):
            ts = t0 + (t1 - t0) * i / 4
            x = pad_l + plot_w * i / 4
            fmt = "%H:%M" if seconds <= 86400 else "%m-%d"
            self.canvas.create_text(x, pad_t + plot_h + 12, anchor="n",
                                    fill="#888888", font=(CN_FONT, 8),
                                    text=time.strftime(fmt, time.localtime(ts)))

        def xy(ts, val):
            x = pad_l + (ts - t0) / max(t1 - t0, 1) * plot_w
            y = pad_t + plot_h * (1 - min(val, ymax) / ymax)
            return x, y

        for which, color in ((1, TRAFFIC_DOWN), (2, TRAFFIC_UP)):
            coords = []
            for p in points:
                coords.extend(xy(p[0], p[which]))
            if len(coords) >= 4:
                self.canvas.create_line(*coords, fill=color, width=2)
            elif coords:
                x, y = coords[0], coords[1]
                self.canvas.create_oval(x - 3, y - 3, x + 3, y + 3,
                                        fill=color, outline="")

        downs = [p[1] for p in points]
        ups = [p[2] for p in points]
        self.stats.configure(
            text=f"共 {len(points)} 点   "
                 f"峰值 ↓{human_rate(max(downs))} ↑{human_rate(max(ups))}   "
                 f"均值 ↓{human_rate(sum(downs) / len(downs))} "
                 f"↑{human_rate(sum(ups) / len(ups))}")

        first = time.strftime("%m-%d %H:%M", time.localtime(span[0]))
        self.hint.configure(
            text=f"采样从 {first} 开始，目前共 {self.store.count()} 个点（全服务器合计）。"
                 "只在工具开着并连着服务器时才采；两次采样间隔超过 15 分钟、"
                 "或累计值变小（服务重启）的那一段会被丢弃，不会画成负值。")

    def _on_hover(self, event) -> None:
        self.canvas.delete("hover")
        if not self._geom or not self._points:
            return
        pad_l, plot_w, t0, t1, _ymax, pad_t, plot_h = self._geom
        if not (pad_l <= event.x <= pad_l + plot_w):
            return

        def x_of(ts):
            return pad_l + (ts - t0) / max(t1 - t0, 1) * plot_w

        best = min(self._points, key=lambda p: abs(x_of(p[0]) - event.x))
        x = x_of(best[0])
        self.canvas.create_line(x, pad_t, x, pad_t + plot_h, fill="#bbbbbb",
                                dash=(2, 3), tags="hover")
        text = (f"{time.strftime('%m-%d %H:%M', time.localtime(best[0]))}\n"
                f"↓ {human_rate(best[1])}\n↑ {human_rate(best[2])}")
        anchor = "nw" if x < pad_l + plot_w * 0.7 else "ne"
        item = self.canvas.create_text(
            x + (8 if anchor == "nw" else -8), pad_t + 6, text=text,
            anchor=anchor, justify="left", fill="#333333",
            font=(CN_FONT, 8), tags="hover")
        bbox = self.canvas.bbox(item)
        if bbox:
            rect = self.canvas.create_rectangle(
                bbox[0] - 4, bbox[1] - 2, bbox[2] + 4, bbox[3] + 2,
                fill="#fffdf0", outline="#dddddd", tags="hover")
            self.canvas.tag_lower(rect, item)


class QrDialog:
    """把客户端配置渲染成二维码，手机 WireGuard App 扫码即可导入。

    客户端私钥只在生成那一刻出现，服务端只存公钥。事后还能重看，是因为生成时
    把整份 .conf 加密存进了 clients.vault.json（见 vault.py），不是从服务器读的。
    """

    def __init__(self, parent, title: str, payload: str, filename_hint: str, log):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title(title)
        top.resizable(False, False)
        frame = ttk.Frame(top, padding=14)
        frame.pack(fill="both", expand=True)

        try:
            png, version = qr_png(payload)
        except Exception as exc:
            ttk.Label(frame, text="生成二维码失败：\n" + str(exc), wraplength=460,
                      justify="left", foreground="#a00000").pack(pady=10)
            ttk.Button(frame, text="关闭", width=12, command=top.destroy).pack(pady=(10, 0))
            show_dialog(top, parent, width=540, height=220)
            return

        # PhotoImage 必须留引用，否则会被垃圾回收、界面留白。
        # 注意只挂 self.image 不够：QrDialog 是回调里临时 new 出来、没人持有实例，
        # 构造函数一返回整个对象就被回收。必须把引用挂到 Toplevel 上，
        # 窗口活多久图片就活多久。
        img = tk.PhotoImage(data=base64.b64encode(png).decode("ascii"))
        self.image = img
        top.image = img
        holder = ttk.Frame(frame, borderwidth=1, relief="solid")
        holder.pack(pady=(0, 10))
        ttk.Label(holder, image=img).pack(padx=6, pady=6)
        ttk.Label(
            frame,
            text="用手机 WireGuard App 的「扫描二维码」导入。\n"
                 "码里含客户端私钥，扫完别截图外传。",
            justify="center", foreground="#a05000",
        ).pack()
        log(f"已生成二维码（QR 版本 {version}，{len(png)} 字节）")

        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(12, 0))

        def save_png():
            path = filedialog.asksaveasfilename(
                parent=top, title="保存二维码",
                initialfile=f"{filename_hint}-qr.png",
                defaultextension=".png",
                filetypes=[("PNG 图片", "*.png"), ("所有文件", "*.*")],
            )
            if path:
                try:
                    with open(path, "wb") as f:
                        f.write(png)
                except Exception as exc:
                    messagebox.showwarning("保存失败", str(exc), parent=top)
                    return
                log(f"二维码已保存到 {path}")

        ttk.Button(bar, text="保存为 PNG", width=14, command=save_png).pack(side="left")
        ttk.Button(bar, text="关闭", width=12, command=top.destroy).pack(side="right")
        show_dialog(top, parent)


class DownloadDialog:
    """官方 WireGuard 客户端下载入口（Windows / Android / iOS / macOS / Linux）。"""

    def __init__(self, parent):
        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("下载 WireGuard 客户端")
        top.resizable(False, False)
        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="密钥配置有了，客户端还没装的话从这里下（均为官方地址）：",
                  font=(CN_FONT, 10, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        for i, item in enumerate(CLIENTS, start=1):
            ttk.Label(frame, text=item["platform"], width=13, anchor="w",
                      font=(CN_FONT, 10, "bold")).grid(row=i, column=0, sticky="w", pady=5)
            ttk.Label(frame, text=item["hint"], wraplength=380, justify="left",
                      foreground="#555555").grid(row=i, column=1, sticky="w", padx=(8, 14))
            ttk.Button(frame, text=item["action"], width=8,
                       command=lambda u=item["url"]: self._open(u)).grid(
                row=i, column=2, sticky="e")

        last = len(CLIENTS) + 1
        ttk.Separator(frame, orient="horizontal").grid(
            row=last, column=0, columnspan=3, sticky="ew", pady=(14, 10))
        ttk.Label(
            frame,
            text="注意：中国区 App Store 搜不到 WireGuard（链接只会跳到 App Store 首页），"
                 "需要非中国区 Apple ID；Google Play 在国内也打不开，"
                 "安卓可以在官方安装页下载 APK。\n"
                 "版本和链接一直在变，拿不准就以官方安装页为准。",
            foreground="#a05000", justify="left", wraplength=580,
        ).grid(row=last + 1, column=0, columnspan=3, sticky="w")

        bar = ttk.Frame(frame)
        bar.grid(row=last + 2, column=0, columnspan=3, sticky="ew", pady=(14, 0))
        ttk.Button(bar, text="打开官方安装页", width=16,
                   command=lambda: self._open(OFFICIAL_INSTALL_PAGE)).pack(side="left")
        ttk.Button(bar, text="关闭", width=12, command=top.destroy).pack(side="right")
        show_dialog(top, parent)

    def _open(self, url: str) -> None:
        if not open_url(url):
            messagebox.showwarning(
                "打不开浏览器",
                "没能自动打开浏览器，请手动复制这个地址：\n\n" + url,
                parent=self.top,
            )


class SettingsDialog:
    """界面设置：托盘、开机自启、刷新间隔。

    这里的开关都即时生效，没有「确定 / 取消」——
    省得用户改完点了 × 以为保存了、其实没保存。
    """

    def __init__(self, parent, app):
        self.app = app
        self.settings = app.settings
        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("设置")
        top.resizable(False, False)

        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)

        # ---------------------------------------------------------- 托盘
        self.tray_var = tk.BooleanVar(
            value=bool(self.settings.get("tray_enabled", True)))
        tray_ok = tray_mod.available()
        self.tray_check = ttk.Checkbutton(
            frame, text="启用系统托盘（关掉窗口时缩到托盘，后台继续刷新状态）",
            variable=self.tray_var, command=self._on_tray)
        self.tray_check.pack(anchor="w")
        if not tray_ok:
            self.tray_check.configure(state="disabled")
            ttk.Label(frame, text="pystray 或 Pillow 不可用，这个选项用不了",
                      foreground="#b03030").pack(anchor="w", padx=(20, 0))

        self.min_var = tk.BooleanVar(
            value=bool(self.settings.get("minimize_to_tray", True)))
        ttk.Checkbutton(
            frame, text="点 × 时最小化到托盘（不勾则直接退出程序）",
            variable=self.min_var, command=self._on_minimize,
        ).pack(anchor="w", padx=(20, 0), pady=(4, 0))

        ttk.Separator(frame).pack(fill="x", pady=12)

        # ---------------------------------------------------------- 开机自启
        ok, reason = autostart_mod.supported()
        self.auto_var = tk.BooleanVar(value=autostart_mod.is_enabled())
        self.auto_check = ttk.Checkbutton(
            frame, text="开机自动启动（登录 Windows 后自动打开并缩到托盘）",
            variable=self.auto_var, command=self._on_autostart)
        self.auto_check.pack(anchor="w")
        if ok:
            current = autostart_mod.current_target()
            ttk.Label(frame, text=("当前注册路径：" + current) if current else "目前没有设置",
                      foreground="#8a8a8a", wraplength=520,
                      justify="left").pack(anchor="w", padx=(20, 0))
        else:
            self.auto_check.configure(state="disabled")
            ttk.Label(frame, text=reason, foreground="#8a8a8a", wraplength=520,
                      justify="left").pack(anchor="w", padx=(20, 0))

        ttk.Separator(frame).pack(fill="x", pady=12)

        # ---------------------------------------------------------- 刷新间隔
        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Label(row, text="自动刷新间隔：").pack(side="left")
        self._intervals = [("30 秒", 30), ("60 秒", 60), ("2 分钟", 120),
                           ("5 分钟", 300)]
        current_secs = int(self.settings.get("monitor_interval", 60))
        label = next((t for t, s in self._intervals if s == current_secs), "60 秒")
        self.interval_var = tk.StringVar(value=label)
        combo = ttk.Combobox(row, textvariable=self.interval_var, state="readonly",
                             width=10, values=[t for t, _ in self._intervals])
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda _e: self._on_interval())
        ttk.Label(row, text="掉线 / 上线只在状态翻转时记一条日志",
                  foreground="#8a8a8a").pack(side="left", padx=(10, 0))

        ttk.Label(
            frame,
            text="自动刷新和流量采样都依赖工具开着。关掉程序后不会再采任何数据；\n"
                 "但已经建立的隧道不受影响 —— 它们在服务器上独立运行。",
            foreground="#777777", justify="left",
        ).pack(anchor="w", pady=(14, 0))

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(16, 0))
        ttk.Button(buttons, text="关闭", width=10,
                   command=top.destroy).pack(side="right")
        ttk.Button(buttons, text="打开数据目录", width=13,
                   command=self._open_dir).pack(side="left")

        show_dialog(top, parent, width=620, height=380)

    def _on_tray(self) -> None:
        self.app._apply_tray(self.tray_var.get())
        self.tray_var.set(bool(self.settings.get("tray_enabled", True)))

    def _on_minimize(self) -> None:
        self.settings.set("minimize_to_tray", self.min_var.get())

    def _on_autostart(self) -> None:
        if self.auto_var.get():
            ok, msg = autostart_mod.enable()
            if not ok:
                messagebox.showwarning("设置失败", msg, parent=self.top)
                self.auto_var.set(False)
                return
            self.settings.set("autostart", True)
            self.app._append_log(f"已设置开机自启：{msg}")
        else:
            ok, msg = autostart_mod.disable()
            if not ok:
                messagebox.showwarning("取消失败", msg, parent=self.top)
                self.auto_var.set(True)
                return
            self.settings.set("autostart", False)
            self.app._append_log(msg)

    def _on_interval(self) -> None:
        secs = next((s for t, s in self._intervals
                     if t == self.interval_var.get()), 60)
        self.settings.set("monitor_interval", secs)
        self.app.monitor_interval = secs * 1000
        if self.app.monitor_var.get():
            self.app._schedule_monitor(delay=500)
        self.app._append_log(f"自动刷新间隔改为 {self.interval_var.get()}")

    def _open_dir(self) -> None:
        try:
            os.startfile(APP_DIR)  # noqa: S606 - Windows only
        except Exception:
            messagebox.showinfo("数据目录", APP_DIR, parent=self.top)


class DetailDialog:
    def __init__(self, parent, view):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title("密钥详情")
        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)
        lines = [
            ("名称", view.name), ("备注", view.note or "-"),
            ("创建时间", view.created or "-"),
            ("有效期", (view.expire or "永久")
             + (f"（{view.expire_text}）" if view.expire_text else "")),
            ("公钥", view.pubkey),
            ("AllowedIPs", view.allowed_ips), ("VPN 地址", view.address),
            ("最近握手", view.handshake), ("流量", view.traffic),
            ("来源端点", view.endpoint), ("预共享密钥", "有" if view.has_psk else "无"),
        ]
        for i, (k, v) in enumerate(lines):
            ttk.Label(frame, text=k + "：", width=14, anchor="e",
                      font=(CN_FONT, 10, "bold")).grid(row=i, column=0, sticky="ne", pady=3)
            ttk.Label(frame, text=str(v), wraplength=440, justify="left").grid(
                row=i, column=1, sticky="w", pady=3
            )
        ttk.Button(frame, text="复制公钥", command=lambda: (
            top.clipboard_clear(), top.clipboard_append(view.pubkey)
        )).grid(row=len(lines), column=1, sticky="w", pady=(12, 0))
        ttk.Button(frame, text="关闭", command=top.destroy).grid(
            row=len(lines), column=1, sticky="e", pady=(12, 0)
        )
        show_dialog(top, parent, width=620, height=380)


class InstallDialog:
    """服务器上没有 WireGuard 服务端时，展示安装方案并收集选项。

    这里只收集参数，不执行任何命令；点「开始安装」之后才真正动服务器。
    """

    def __init__(self, parent, plan):
        self.result = None
        self.plan = plan
        self.top = top = tk.Toplevel(parent)
        top.withdraw()
        top.title("一键安装 WireGuard 服务端")
        top.resizable(False, False)
        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=f"检测到 {plan.platform.label}，服务器上还没有 WireGuard 服务端",
                  font=(CN_FONT, 11, "bold")).grid(
            row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(frame, text="下面这些操作会修改服务器系统，确认后才会执行。",
                  foreground="#a05000").grid(
            row=1, column=0, columnspan=4, sticky="w", pady=(4, 10))

        self.subnet = tk.StringVar(value=plan.subnet)
        self.port = tk.StringVar(value=str(plan.listen_port))
        self.nat = tk.BooleanVar(value=bool(plan.nat_method))
        self.forward = tk.BooleanVar(value=True)
        self.firewall = tk.BooleanVar(value=False)

        ttk.Label(frame, text="VPN 网段：", anchor="e", width=12).grid(
            row=2, column=0, sticky="e", pady=4)
        ttk.Entry(frame, textvariable=self.subnet, width=22).grid(
            row=2, column=1, sticky="w", pady=4)
        ttk.Label(frame, text="服务端会占 .1，客户端从这里分配", foreground="#777777").grid(
            row=2, column=2, columnspan=2, sticky="w", padx=(10, 0))

        ttk.Label(frame, text="监听端口：", anchor="e", width=12).grid(
            row=3, column=0, sticky="e", pady=4)
        ttk.Entry(frame, textvariable=self.port, width=22).grid(
            row=3, column=1, sticky="w", pady=4)
        ttk.Label(frame, text="UDP，默认 51820", foreground="#777777").grid(
            row=3, column=2, columnspan=2, sticky="w", padx=(10, 0))

        ttk.Label(frame, text="出口网卡：", anchor="e", width=12).grid(
            row=4, column=0, sticky="e", pady=4)
        ttk.Label(frame, text=plan.default_iface or "（未识别）").grid(
            row=4, column=1, sticky="w", pady=4)
        if plan.firewall:
            ttk.Label(frame, text=f"已启用 {plan.firewall}", foreground="#a05000").grid(
                row=4, column=2, columnspan=2, sticky="w", padx=(10, 0))

        nat_text = {
            "iptables": "允许客户端通过本机上网（写 iptables NAT 规则）",
            "firewalld": "允许客户端通过本机上网（在 firewalld 开启 masquerade）",
        }.get(plan.nat_method, "允许客户端通过本机上网（未检测到 iptables，需自行配置 NAT）")

        checks = ttk.Frame(frame)
        checks.grid(row=5, column=0, columnspan=4, sticky="w", pady=(10, 0))
        ttk.Checkbutton(checks, text=nat_text,
                        variable=self.nat, command=self._refresh_steps,
                        state="normal" if plan.nat_method else "disabled").pack(anchor="w")
        ttk.Checkbutton(checks, text="开启 IP 转发（net.ipv4.ip_forward=1，持久化）",
                        variable=self.forward, command=self._refresh_steps).pack(
            anchor="w", pady=(2, 0))
        if plan.firewall:
            ttk.Checkbutton(
                checks,
                text=f"在 {plan.firewall} 放行 UDP {plan.listen_port}（不开的话客户端可能连不上）",
                variable=self.firewall, command=self._refresh_steps,
            ).pack(anchor="w", pady=(2, 0))

        ttk.Label(frame, text="即将执行：").grid(
            row=6, column=0, columnspan=4, sticky="w", pady=(12, 4))
        self.steps = scrolledtext.ScrolledText(frame, height=8, width=76,
                                               font=(CN_FONT, 9), wrap="word")
        self.steps.grid(row=7, column=0, columnspan=4, sticky="ew")
        self.steps.configure(state="disabled")

        if plan.notes:
            ttk.Label(frame, text="注意：\n• " + "\n• ".join(plan.notes),
                      foreground="#a05000", justify="left", wraplength=600).grid(
                row=8, column=0, columnspan=4, sticky="w", pady=(10, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=9, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        ttk.Button(buttons, text="开始安装", width=14, style="Accent.TButton",
                   command=self._ok).pack(side="right", padx=4)
        ttk.Button(buttons, text="取消", width=10,
                   command=top.destroy).pack(side="right", padx=4)

        self._refresh_steps()
        top.bind("<Escape>", lambda _e: top.destroy())
        show_dialog(top, parent, modal=True)

    def _refresh_steps(self) -> None:
        net = self.subnet.get().strip() or self.plan.subnet
        port = self.port.get().strip() or str(self.plan.listen_port)
        index = 1
        lines = [
            f"{index}. 安装 WireGuard（{self.plan.platform.label}）",
        ]
        index += 1
        lines.append(f"{index}. 生成服务端密钥对（私钥只写进配置文件，不进日志）")
        index += 1
        lines.append(f"{index}. 写入 {self.plan.conf_path}：网段 {net}，UDP {port}，权限 600")
        index += 1
        if self.nat.get():
            if self.plan.nat_method == "iptables" and self.plan.default_iface:
                lines.append(
                    f"{index}. 写 NAT 规则（iptables）：客户端流量经 "
                    f"{self.plan.default_iface} 转发出去"
                )
            elif self.plan.nat_method == "firewalld":
                lines.append(f"{index}. 在 firewalld 开启 masquerade（实现 NAT）")
            else:
                lines.append(f"{index}. 未检测到 iptables，跳过 NAT（客户端只能访问本机）")
            index += 1
        if self.forward.get() and not self.plan.forward_enabled:
            lines.append(f"{index}. 开启 IP 转发并持久化到 /etc/sysctl.d/99-wireguard.conf")
            index += 1
        lines.append(f"{index}. 启用并启动 wg-quick@{self.plan.iface}")
        index += 1
        if self.firewall.get() and self.plan.firewall:
            lines.append(f"{index}. 在 {self.plan.firewall} 放行 UDP {port}")
        lines.append("")
        lines.append("安装完成后会自动重新连接并进入管理界面。")

        self.steps.configure(state="normal")
        self.steps.delete("1.0", "end")
        self.steps.insert("1.0", "\n".join(lines))
        self.steps.configure(state="disabled")

    def _ok(self) -> None:
        try:
            net = ipaddress.ip_network(self.subnet.get().strip(), strict=False)
        except ValueError:
            messagebox.showwarning("网段不对", "VPN 网段填写有误，例如 10.8.0.0/24", parent=self.top)
            return
        if net.version != 4:
            messagebox.showwarning("只支持 IPv4", "目前只支持用 IPv4 网段做 VPN 内网", parent=self.top)
            return
        if net.prefixlen > 30:
            messagebox.showwarning("网段太小", "至少要能放下服务端 + 客户端，建议用 /24", parent=self.top)
            return
        try:
            port = int(self.port.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showwarning("端口不对", "监听端口要在 1-65535 之间", parent=self.top)
            return

        self.result = InstallOptions(
            iface=self.plan.iface,
            subnet=str(net),
            listen_port=port,
            endpoint_host=self.plan.endpoint_host,
            enable_forward=self.forward.get() or self.nat.get(),
            enable_nat=self.nat.get(),
            open_firewall=self.firewall.get(),
        )
        self.top.destroy()


class AdvancedDialog:
    def __init__(self, parent, conf_var, iface_var, endpoint_var):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title("高级设置")
        top.resizable(False, False)
        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both")
        rows = [
            ("配置文件路径：", conf_var, "留空自动探测；例如 /etc/wireguard/wg0.conf"),
            ("接口名：", iface_var, "留空自动探测；例如 wg0"),
            ("客户端 Endpoint 主机：", endpoint_var, "留空用 SSH 的 IP；公网 IP 不同时填这里"),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(frame, text=label, width=22, anchor="e").grid(row=i, column=0, sticky="e", pady=5)
            ttk.Entry(frame, textvariable=var, width=44).grid(row=i, column=1, pady=5)
            ttk.Label(frame, text=hint, foreground="#777777").grid(
                row=i, column=2, sticky="w", padx=(8, 0)
            )
        ttk.Label(frame, text="修改后需要重新连接才会生效。", foreground="#a05000").grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(10, 0)
        )
        ttk.Button(frame, text="关闭", width=12, command=top.destroy).grid(
            row=4, column=2, sticky="e", pady=(12, 0)
        )
        show_dialog(top, parent, modal=True)


HELP_TEXT = """WireGuard 密钥管理工具 · 使用说明

【连接】
填服务器 IP / SSH 端口 / 用户名，选密码或私钥文件登录后点「连接」。
工具会自动探测 wg 命令、/etc/wireguard/*.conf、活动接口、服务端公钥、监听端口和 VPN 网段；
如果 WireGuard 跑在 Docker 容器里，会尝试通过 docker exec 进入容器管理。
探测不准时，用「高级设置」手动指定配置文件路径和接口名。

【需要什么权限】
读取 /etc/wireguard/wg0.conf 通常需要 root（该目录一般是 700）。
· 最省事：直接用 root 账号登录；
· 普通账号：在「sudo 密码」里填该账号的 sudo 密码，工具会用 sudo -S 提权；
· 或者让管理员给该账号配置免密 sudo（NOPASSWD），这时 sudo 密码可以留空。
注意：用私钥登录时 SSH 本身没有密码，所以「sudo 密码」必须单独填写，
否则工具会因为没有 root 权限而读不到配置文件（会明确提示，不会静默失败）。

【查看】
列表显示备注名、公钥前缀、VPN 地址、最近握手、流量和在线状态（5 分钟内有握手视为在线）。
双击某一行可以看完整公钥。

【服务器上没有 WireGuard】
如果连上去发现服务器还没装 WireGuard 服务端，工具会弹出安装方案，确认后一键完成：
装包 → 生成服务端密钥 → 写 /etc/wireguard/wg0.conf → 开 IP 转发 → 启动 wg-quick@wg0。
· 会自动挑一个没被占用的网段和端口，也可以在弹窗里改；
· 不会覆盖已存在的配置文件，发现同名配置直接中止；
· 是否写 NAT 规则、是否开 IP 转发、是否放行防火墙端口，都在弹窗里勾选；
· 装完自动重新探测，直接进入管理界面。
支持 Ubuntu/Debian（apt）、RHEL 系（dnf/yum）、Arch（pacman）、openSUSE（zypper）。

【新增密钥】
自动挑一个网段里没被占用的 IPv4 / IPv6 地址，生成密钥对，往 wg0.conf 追加 [Peer]，
然后用 wg syncconf 热加载（不会踢掉现有连接）。生成的客户端 .conf 会弹窗展示，
并默认保存到 clients/ 目录，可直接导入 WireGuard 客户端。
那个窗口还能「生成二维码」，手机 App 扫码直接导入。

【修改密钥】
选中一行点「编辑选中」，可以改名称、备注和 VPN 地址。
改名称/备注只写注释，对已连接的隧道没有影响；改 VPN 地址会让该客户端断线，
必须同步修改客户端配置里的 Address。公钥和预共享密钥不可修改。

【下载客户端】
顶部「下载客户端」按钮里有 Windows / Android / iOS / macOS / Linux 的官方下载地址，
只收官方来源。注意：中国区 App Store 搜不到 WireGuard，Android 的 Google Play 在国内也打不开。

【删除密钥】
选中一行或多行（Ctrl / Shift 多选），点「删除选中」，二次确认后从配置和运行时一起移除。

【安全措施】
· 每次改写配置前，服务器都会留一份 wg0.conf.wgmgr.bak.时间戳 备份；
· 写文件用「临时文件 + 原子替换」，写完回读校验，热加载后再核对运行时公钥；
· 任何一步失败都会自动恢复备份；
· 未改动的配置行（含 PostUp / PostDown / MTU / 注释）逐字保留；
· 主机 SSH 指纹采用首次信任并记录（known_hosts 文件），指纹变化会拒绝连接；
· 密码不会写入连接记录文件，服务端私钥不会出现在命令行或日志里。

【重要提醒】
· 客户端私钥只在生成时出现一次，服务端只存公钥，之后无法重新导出，请务必保存 .conf；
· 如果 [Interface] 里有 SaveConfig = true，wg-quick 停止服务时可能覆盖备注注释，建议改成 false；
· wg-easy 新版可能用数据库管理客户端，直接改文件未必生效，请先在测试环境验证；
· 备注信息以 # WGM_NAME / # WGM_NOTE / # WGM_CREATED 注释写在每个 [Peer] 上方，
  也兼容读取 ### Client xxx、# Name = xxx 等常见一键脚本的格式。

【演示模式】
勾选后不需要真实服务器，会在内存里模拟一台带 3 个密钥的 WireGuard 服务器，
可以完整试用查看 / 新增 / 删除流程，不会碰本机任何真实文件。"""
