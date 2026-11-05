"""Windows 桌面界面（tkinter / ttk）。

界面分四块：连接服务器 -> 探测结果 -> 密钥列表与增删改 -> 操作日志。
所有 SSH 操作都放在后台线程，界面不会卡死；线程只通过队列把日志和结果送回主线程。
"""
from __future__ import annotations

import base64
import json
import os
import queue
import sys
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .backend import make_backend
from .probe import ProbeError, probe
from .service import WGService
from .util import (
    normalize_allowed_ips,
    patch_client_conf,
    qr_png,
    safe_filename,
    stamp,
)


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


class App:
    def __init__(self):
        _enable_dpi()
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("WireGuard 密钥管理工具  v1.0")
        self.root.geometry("1120x760")
        self.root.minsize(980, 660)
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
        self.service: WGService | None = None
        self.views = []
        self.row_keys: dict[str, str] = {}

        self._build()
        self.root.after(120, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._log("就绪。填好服务器信息后点「连接」；也可以直接勾选「演示模式」先试用。")
        self._refresh_profile_combo()
        # 按内容实际需要的尺寸开窗，并限制在屏幕内，避免新增控件被裁切
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        width = min(max(1120, self.root.winfo_reqwidth() + 12), int(sw * 0.94))
        height = min(max(720, self.root.winfo_reqheight() + 12), int(sh * 0.90))
        center_window(self.root, width, height)

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
        ttk.Label(row, text="已保存：").pack(side="left", padx=(14, 0))
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
        self.status_label = ttk.Label(row3, textvariable=self.status_var,
                                      foreground="#b03030")
        self.status_label.pack(side="right")
        self._on_auth_change()

        self.adv_conf = tk.StringVar()
        self.adv_iface = tk.StringVar()
        self.adv_endpoint = tk.StringVar()

    def _build_peers(self, frame) -> None:
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 8))
        self.count_var = tk.StringVar(value="共 0 个密钥")
        ttk.Label(bar, textvariable=self.count_var,
                  font=(CN_FONT, 11, "bold")).pack(side="left")
        self.refresh_btn = ttk.Button(bar, text="刷新", width=10, command=self.refresh,
                                      state="disabled")
        self.refresh_btn.pack(side="right", padx=4)
        self.clients_btn = ttk.Button(bar, text="打开配置目录", width=14,
                                      command=self._open_clients_dir)
        self.clients_btn.pack(side="right", padx=4)
        self.delete_btn = ttk.Button(bar, text="删除选中", width=12,
                                     command=self.delete_selected, state="disabled")
        self.delete_btn.pack(side="right", padx=4)
        self.edit_btn = ttk.Button(bar, text="编辑选中", width=12,
                                   command=self.edit_selected, state="disabled")
        self.edit_btn.pack(side="right", padx=4)
        self.add_btn = ttk.Button(bar, text="＋ 新增密钥", width=14,
                                  style="Accent.TButton", command=self.add_dialog,
                                  state="disabled")
        self.add_btn.pack(side="right", padx=4)

        columns = ("name", "note", "pubkey", "address", "handshake", "traffic", "endpoint", "status")
        headers = {
            "name": ("名称", 160), "note": ("备注", 150), "pubkey": ("公钥", 140),
            "address": ("VPN 地址", 175), "handshake": ("最近握手", 110),
            "traffic": ("流量 (收/发)", 140), "endpoint": ("来源端点", 145),
            "status": ("状态", 70),
        }
        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            title, width = headers[col]
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=70,
                             anchor="w" if col not in ("status",) else "center")
        self.tree.tag_configure("online", foreground="#0a7a3d")
        self.tree.tag_configure("offline", foreground="#777777")
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
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _async(self, label: str, work, done) -> None:
        if self.busy:
            return
        self.busy = True
        self.status_var.set(f"● {label}…")
        self._set_buttons()

        def runner():
            try:
                result = work()
            except Exception as exc:
                self.queue.put(("error", (label, exc, traceback.format_exc())))
            else:
                self.queue.put(("done", (result, done)))

        threading.Thread(target=runner, daemon=True).start()

    def _set_buttons(self) -> None:
        connected = self.service is not None
        enabled = connected and not self.busy
        for btn in (self.refresh_btn, self.add_btn, self.edit_btn, self.delete_btn):
            btn.configure(state="normal" if enabled else "disabled")
        self.connect_btn.configure(state="normal" if (not self.busy and not connected) else "disabled")
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
            return
        self._save_current_profile(conn)

        def work():
            backend = make_backend(conn, log=self._log)
            try:
                target, dep = probe(backend, conn, self._log)
                svc = WGService(target, dep, self._log)
                views = svc.list_peers()
            except Exception:
                backend.close()
                raise
            return backend, target, dep, svc, views

        self._async("连接", work, self._on_connected)

    def _on_connected(self, payload) -> None:
        self.backend, self.target, self.dep, self.service, views = payload
        self.status_var.set("● 已连接")
        self.info_var.set(self.dep.summary)
        self._fill(views)
        self._set_buttons()
        self._append_log("连接成功：" + self.dep.summary)
        for note in self.dep.notes:
            self._append_log("提示：" + note)
        if self.dep.notes:
            messagebox.showinfo(
                "探测提示",
                "检测到以下情况，请留意：\n\n• " + "\n• ".join(self.dep.notes),
                parent=self.root,
            )

    def disconnect(self) -> None:
        if self.backend:
            try:
                self.backend.close()
            except Exception:
                pass
        self.backend = self.target = self.dep = self.service = None
        self.views = []
        self._fill([])
        self.info_var.set("尚未连接")
        self.status_var.set("● 未连接")
        self._set_buttons()
        self._append_log("已断开连接")

    # ---------------------------------------------------------------- 列表
    def _fill(self, views) -> None:
        self.views = views or []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.row_keys.clear()
        for view in self.views:
            iid = self.tree.insert(
                "", "end",
                values=(
                    view.name, view.note, view.pubkey[:14] + "…", view.address,
                    view.handshake, view.traffic, view.endpoint,
                    "在线" if view.online else "离线/从未",
                ),
                tags=("online" if view.online else "offline",),
            )
            self.row_keys[iid] = view.pubkey
        online = sum(1 for v in self.views if v.online)
        self.count_var.set(f"共 {len(self.views)} 个密钥（在线 {online}）")

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
            if save_file:
                path = os.path.join(CLIENTS_DIR, f"{safe_filename(result.name)}.conf")
                try:
                    os.makedirs(CLIENTS_DIR, exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="\n") as f:
                        f.write(result.client_conf)
                except Exception as exc:
                    self._append_log(f"保存客户端配置失败：{exc}")
                    path = ""
            else:
                path = ""
            ClientConfDialog(self.root, result, path, self._append_log)
            self._append_log(f"服务器备份：{result.backup}")
            self._append_log(result.reload_msg)
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
            self._append_log("已删除：" + "、".join(names))
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
        profile = {
            "host": conn["host"], "port": conn["port"],
            "username": conn["username"], "auth": conn["auth"],
            "key_path": conn.get("key_path", ""),
        }
        profiles = _load_profiles()
        profiles = [p for p in profiles if p.get("host") != profile["host"]]
        profiles.insert(0, profile)
        _save_profiles(profiles)
        self._refresh_profile_combo()

    def _refresh_profile_combo(self) -> None:
        profiles = _load_profiles()
        self.profile_combo["values"] = [f"{p['host']} ({p.get('username', '')})" for p in profiles]
        self._profiles = profiles

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
        self._on_auth_change()

    def _on_close(self) -> None:
        try:
            if self.backend:
                self.backend.close()
        except Exception:
            pass
        self.root.destroy()

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
        self.psk = tk.BooleanVar(value=default_psk)
        self.save_file = tk.BooleanVar(value=True)

        rows = [
            ("密钥名称 *：", self.name, "例如 张三-手机，必填，方便以后知道该删哪个"),
            ("备注：", self.note, "选填，例如 研发部 / 2026年入职领用"),
            ("客户端 AllowedIPs：", self.allowed, "0.0.0.0/0, ::/0 = 全部流量走 VPN"),
            ("DNS：", self.dns, "客户端使用的 DNS"),
            ("服务端 Endpoint：", self.endpoint, "客户端连哪个地址，默认用 SSH 的 IP"),
            ("指定 VPN 地址：", self.vpn_addresses, "留空 = 自动分配空闲地址（推荐）"),
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

    def _ok(self) -> None:
        if not self.name.get().strip():
            messagebox.showwarning("缺少名称", "请填写密钥名称", parent=self.top)
            return
        params = {
            "name": self.name.get().strip(),
            "note": self.note.get().strip(),
            "client_allowed_ips": self.allowed.get().strip() or "0.0.0.0/0, ::/0",
            "dns": [d.strip() for d in self.dns.get().split(",") if d.strip()],
            "endpoint": self.endpoint.get().strip(),
            "use_psk": self.psk.get(),
            "vpn_addresses": self.vpn_addresses.get().strip(),
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

        rows = [
            ("名称 *：", self.name, "只影响显示，不动密钥本身"),
            ("备注：", self.note, "选填，例如 研发部 / 张三的手机"),
            ("VPN 地址：", self.addr, "多个用逗号分隔，如 10.8.0.9/32, fd08::9/128"),
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

        ttk.Label(
            frame,
            text="改名称、备注只动配置文件里的注释，对已连接的隧道没有影响；\n"
                 "改 VPN 地址会让该客户端立即断线，必须同步修改客户端配置里的 Address。",
            foreground="#a05000", wraplength=620, justify="left",
        ).grid(row=len(rows) + 1, column=0, columnspan=3, sticky="w", pady=(12, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 2, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(buttons, text="保存修改", width=14, style="Accent.TButton",
                   command=self._ok).pack(side="right", padx=4)
        ttk.Button(buttons, text="取消", width=10, command=top.destroy).pack(side="right", padx=4)
        top.bind("<Return>", lambda _e: self._ok())
        top.bind("<Escape>", lambda _e: top.destroy())
        show_dialog(top, parent, modal=True)

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

        self.addr.set(addr)
        if (
            name == (self.view.raw_name or "")
            and self.note.get().strip() == (self.view.note or "")
            and addr == (self.view.allowed_ips or "")
        ):
            self.top.destroy()  # 一个字都没改，直接关掉
            return

        self.result = {
            "name": name,
            "note": self.note.get().strip(),
            "allowed_ips": addr,
        }
        self.top.destroy()


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
        ttk.Label(frame, text="客户端配置（请立即保存，私钥不会再次显示）：",
                  foreground="#a05000").pack(anchor="w")
        text = scrolledtext.ScrolledText(frame, height=16, font=("Consolas", 10))
        text.pack(fill="both", expand=True, pady=6)
        text.insert("1.0", result.client_conf)
        text.configure(state="disabled")

        if saved_path:
            ttk.Label(frame, text=f"已自动保存到：{saved_path}",
                      foreground="#0a7a3d").pack(anchor="w")

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
        ttk.Button(bar, text="生成二维码", width=13, style="Accent.TButton",
                   command=lambda: QrDialog(
                       top, f"「{result.name}」的二维码", result.client_conf,
                       safe_filename(result.name), log,
                   )).pack(side="left")
        ttk.Button(bar, text="关闭", width=12, command=top.destroy).pack(side="right")
        show_dialog(top, parent, width=680, height=520)


class QrDialog:
    """把客户端配置渲染成二维码，手机 WireGuard App 扫码即可导入。

    只在「刚生成密钥」这一步可用：服务端只存公钥，事后无法再导出客户端私钥。
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


class DetailDialog:
    def __init__(self, parent, view):
        top = tk.Toplevel(parent)
        top.withdraw()
        top.title("密钥详情")
        frame = ttk.Frame(top, padding=16)
        frame.pack(fill="both", expand=True)
        lines = [
            ("名称", view.name), ("备注", view.note or "-"),
            ("创建时间", view.created or "-"), ("公钥", view.pubkey),
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

【新增密钥】
自动挑一个网段里没被占用的 IPv4 / IPv6 地址，生成密钥对，往 wg0.conf 追加 [Peer]，
然后用 wg syncconf 热加载（不会踢掉现有连接）。生成的客户端 .conf 会弹窗展示，
并默认保存到 clients/ 目录，可直接导入 WireGuard 客户端。

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
