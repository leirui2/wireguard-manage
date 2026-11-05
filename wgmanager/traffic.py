"""流量采样与速率计算。

`wg show transfer` 给的是**自 peer 创建以来的累计字节数**，不是速率。
要画趋势图必须存下每次采样的累计值，再用相邻两点做差除以时间间隔。

有两种差值必须丢掉，否则图上会出现负值或断崖：
* 当前值比上次小 —— 计数器被重置（服务重启、重新 syncconf）
* 间隔远超采样周期 —— 中间电脑休眠过，差值摊到这段时间没有意义

存储用 sqlite3（Python 自带的），每个采样点一行，按天清理。
"""
from __future__ import annotations

import os
import sqlite3
import time

DEFAULT_KEEP_DAYS = 7
# 两次采样正常相隔 5 分钟，超过 15 分钟就当中间断过
DEFAULT_MAX_GAP = 900

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts      INTEGER NOT NULL,
    host    TEXT    NOT NULL,
    pubkey  TEXT    NOT NULL,
    rx      INTEGER NOT NULL,
    tx      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples ON samples (host, pubkey, ts);
"""


class TrafficStore:
    def __init__(self, app_dir: str, keep_days: int = DEFAULT_KEEP_DAYS):
        self.path = os.path.join(app_dir, "traffic.db")
        self.keep_days = keep_days
        self._init()

    # ------------------------------------------------------------ 建表
    def _connect(self) -> sqlite3.Connection:
        # 每次开短连接：采样在后台线程写、界面在主线程读，
        # 共用一个连接迟早撞上 "SQLite objects created in a thread..."
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init(self) -> None:
        try:
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass  # 建不了表就让采样静默失效，别挡住主流程

    # ------------------------------------------------------------ 写
    def record(self, host: str, points, ts: float | None = None) -> int:
        """points 是 [(pubkey, rx, tx)]，rx/tx 为累计字节数。"""
        if not points:
            return 0
        stamp = int(ts if ts is not None else time.time())
        rows = [(stamp, host, str(pk), int(rx), int(tx)) for pk, rx, tx in points]
        try:
            conn = self._connect()
            try:
                conn.executemany(
                    "INSERT INTO samples (ts, host, pubkey, rx, tx) VALUES (?,?,?,?,?)",
                    rows,
                )
                conn.commit()
            finally:
                conn.close()
            return len(rows)
        except Exception:
            return 0

    def prune(self, keep_days: int | None = None) -> int:
        days = self.keep_days if keep_days is None else keep_days
        cutoff = int(time.time()) - int(days * 86400)
        try:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
                conn.commit()
                return cur.rowcount or 0
            finally:
                conn.close()
        except Exception:
            return 0

    # ------------------------------------------------------------ 读
    def series(self, host: str, pubkey: str,
               since: float | None = None) -> list[tuple[int, int, int]]:
        sql = "SELECT ts, rx, tx FROM samples WHERE host=? AND pubkey=?"
        args: list = [host, pubkey]
        if since:
            sql += " AND ts>=?"
            args.append(int(since))
        sql += " ORDER BY ts"
        try:
            conn = self._connect()
            try:
                return [(int(t), int(r), int(x))
                        for t, r, x in conn.execute(sql, args)]
            finally:
                conn.close()
        except Exception:
            return []

    def rates(self, host: str, pubkey: str, since: float | None = None,
              max_gap: int = DEFAULT_MAX_GAP) -> list[tuple[int, float, float]]:
        """[(时间戳, 下行 B/s, 上行 B/s)]。已剔除计数器重置和超长间隔。"""
        pts = self.series(host, pubkey, since)
        if len(pts) < 2:
            return []
        out = []
        for (t0, r0, x0), (t1, r1, x1) in zip(pts, pts[1:]):
            dt = t1 - t0
            if dt <= 0:
                continue
            if r1 < r0 or x1 < x0:
                continue
            if dt > max_gap:
                continue
            out.append((t1, (r1 - r0) / dt, (x1 - x0) / dt))
        return out

    def latest(self, host: str, pubkey: str) -> tuple[int, int] | None:
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT rx, tx FROM samples WHERE host=? AND pubkey=? "
                    "ORDER BY ts DESC LIMIT 1", (host, pubkey)).fetchone()
                return (int(row[0]), int(row[1])) if row else None
            finally:
                conn.close()
        except Exception:
            return None

    def peers(self, host: str, since: float | None = None) -> list[str]:
        """这台服务器上有采样记录的客户端公钥。"""
        sql = "SELECT DISTINCT pubkey FROM samples WHERE host=?"
        args: list = [host]
        if since:
            sql += " AND ts>=?"
            args.append(int(since))
        try:
            conn = self._connect()
            try:
                return [r[0] for r in conn.execute(sql, args)]
            finally:
                conn.close()
        except Exception:
            return []

    def span(self, host: str, pubkey: str) -> tuple[int, int] | None:
        """(最早时间, 最新时间)，用来告诉用户"只采了这么久"。"""
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT MIN(ts), MAX(ts) FROM samples WHERE host=? AND pubkey=?",
                    (host, pubkey)).fetchone()
                if row and row[0]:
                    return int(row[0]), int(row[1])
                return None
            finally:
                conn.close()
        except Exception:
            return None

    def count(self) -> int:
        try:
            conn = self._connect()
            try:
                return int(conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0])
            finally:
                conn.close()
        except Exception:
            return 0


def human_rate(bps: float) -> str:
    """字节/秒 → 人看的速率。和 human_bytes 一样走 1024 进制。"""
    try:
        n = float(bps)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if n < 1024 or unit == "GB/s":
            return f"{n:.0f} {unit}" if unit == "B/s" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB/s"


def nice_ceiling(value: float) -> float:
    """把上限取成 1/2/4/8 × 10^n。

    刻意不用常见的 1/2/5：Y 轴一般分 4 段，除以 4 之后
    1/2/4/8 能整除成整数，5 会变成 1.25 这种。
    """
    if value <= 0:
        return 1.0
    import math
    exp = math.floor(math.log10(value))
    base = 10 ** exp
    for mult in (1, 2, 4, 8):
        if value <= base * mult:
            return base * mult
    return base * 10


def nice_rate_ceiling(bps: float) -> float:
    """先换算到合适的单位再取整，免得刻度出现 122.1 KB/s 这种数字。

    直接在字节层面取整的话，400000 B/s 会被换成 390.6 KB/s ——
    数值上没错，但一眼看不出量级。
    """
    if bps <= 0:
        return 1.0
    for scale in (1024 ** 3, 1024 ** 2, 1024, 1):
        if bps >= scale or scale == 1:
            return nice_ceiling(bps / scale) * scale
    return float(bps)
