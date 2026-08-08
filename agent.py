

import tkinter as tk
import threading
import time
import os
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

import psutil
import requests

APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
CONFIG_PATH = os.path.join(APP_DIR, "agent_config.json")


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as config_file:
            return json.load(config_file)
    except (OSError, json.JSONDecodeError):
        return {}


CONFIG = _load_config()
BACKEND_URL = os.environ.get("NETWATCH_BACKEND_URL", CONFIG.get("backend_url", "")).rstrip("/")
API_SECRET_KEY = os.environ.get("NETWATCH_API_SECRET_KEY", CONFIG.get("api_secret_key", ""))
AGENT_ID = os.environ.get("NETWATCH_AGENT_ID", CONFIG.get("agent_id", "unconfigured-agent"))

INTERVAL  = 2
TIER      = "remote_client"
SNORT_LOG = r"C:\Snort\log\alert.ids"

AUTH_HEADERS = {
    "X-API-Key":    API_SECRET_KEY,
    "Content-Type": "application/json",
}

C = {
    "bg":      "#07090b",
    "bg1":     "#0d1117",
    "bg2":     "#111820",
    "line":    "#1c2a35",
    "line2":   "#243040",
    "dim":     "#334455",
    "muted":   "#4a6070",
    "text":    "#90b8c8",
    "text2":   "#c0d8e4",
    "bright":  "#e4f0f8",
    "green":   "#00e676",
    "green_d": "#0a2016",
    "cyan":    "#29d8f0",
    "amber":   "#ffba08",
    "red":     "#ff3355",
    "red_d":   "#3a1020",
}

_prev_net    = None
_prev_time   = None
_conn_hist   = deque(maxlen=10)
_port_window = deque(maxlen=5)


def _get_net_io_delta():
    global _prev_net, _prev_time
    now  = time.time()
    curr = psutil.net_io_counters()
    if _prev_net is None:
        _prev_net, _prev_time = curr, now
        return 0.0, 0.0
    elapsed = now - _prev_time
    if elapsed == 0:
        return 0.0, 0.0
    b_in  = (curr.bytes_recv - _prev_net.bytes_recv) / elapsed
    b_out = (curr.bytes_sent - _prev_net.bytes_sent) / elapsed
    _prev_net, _prev_time = curr, now
    return max(b_in, 0.0), max(b_out, 0.0)


def _get_connection_features():
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        try:
            conns = psutil.net_connections(kind="tcp")
        except Exception:
            return 0, 0.0, 0, "TCP", 0

    total    = len(conns)
    syn_sent = sum(1 for c in conns if c.status == "SYN_SENT")
    dst_ports, proto_cnt = set(), defaultdict(int)

    for c in conns:
        if c.raddr:
            dst_ports.add(c.raddr.port)
        if c.type == 1:
            proto_cnt["TCP"] += 1
        elif c.type == 2:
            proto_cnt["UDP"] += 1

    _port_window.append(dst_ports)
    rolling = set()
    for s in _port_window:
        rolling |= s

    top_proto = max(proto_cnt, key=proto_cnt.get) if proto_cnt else "TCP"
    _conn_hist.append(total)
    conn_rate = abs(total - _conn_hist[0]) / max(len(_conn_hist), 1)
    return total, round(conn_rate, 2), len(rolling), top_proto, syn_sent


def _collect_features():
    b_in, b_out = _get_net_io_delta()
    total, conn_rate, ports, proto, syn = _get_connection_features()
    return {
        "bytes_in":         round(b_in,  2),
        "bytes_out":        round(b_out, 2),
        "conn_total":       total,
        "conn_rate":        conn_rate,
        "unique_dst_ports": ports,
        "syn_rate":         round(syn / INTERVAL, 2),
        "top_proto":        proto,
        "snort_alert":      0,
    }


def _fmt_speed(b):
    if not b:
        return "0 B/s"
    if b > 1_000_000:
        return f"{b / 1_000_000:.1f} MB/s"
    if b > 1_000:
        return f"{b / 1_000:.0f} KB/s"
    return f"{b:.0f} B/s"


class NetWatchApp:

    def __init__(self, root: tk.Tk):
        self.root      = root
        self._running  = False
        self._stop_evt = threading.Event()
        self._pulse_on = False

        # Stats dict — written by background thread, read by GUI thread.
        # Lock protects access from both sides.
        self._stats: dict = {
            "bytes_in":   0.0,
            "bytes_out":  0.0,
            "conn_total": 0,
            "last_ts":    "—",
            "sent":       0,
            "error":      None,
        }
        self._lock = threading.Lock()

        self._setup_window()
        self._build_ui()
        self._tick()          # kick off the 500 ms GUI refresh loop

    def _setup_window(self):
        self.root.title("NetWatch Agent")
        self.root.configure(bg=C["bg"])
        self.root.resizable(False, False)

        W, H = 430, 540
        self.root.geometry(f"{W}x{H}")

        # Center after the event loop starts (geometry is not ready yet at __init__)
        self.root.after(0, self._center_window)
        self.root.protocol("WM_DELETE_WINDOW", self._quit)

        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4
            )
        except Exception:
            pass

    def _center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth()  - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"+{x}+{y}")

    def _build_ui(self):
        r = self.root

        topbar = tk.Frame(r, bg=C["bg1"], height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        logo = tk.Frame(topbar, bg=C["bg1"])
        logo.pack(side="left", padx=18)

        tk.Label(logo, text="NET",   bg=C["bg1"], fg=C["bright"],
                 font=("Courier", 15, "bold")).pack(side="left")
        tk.Label(logo, text="WATCH", bg=C["bg1"], fg=C["green"],
                 font=("Courier", 15, "bold")).pack(side="left")
        tk.Label(logo, text="  ·  AGENT", bg=C["bg1"], fg=C["dim"],
                 font=("Courier", 9)).pack(side="left")

        tk.Label(topbar, text="v4.0", bg=C["bg1"], fg=C["dim"],
                 font=("Courier", 8)).pack(side="right", padx=18)

        tk.Frame(r, bg=C["line2"], height=1).pack(fill="x")

        status_area = tk.Frame(r, bg=C["bg"], pady=26)
        status_area.pack(fill="x")

        dot_row = tk.Frame(status_area, bg=C["bg"])
        dot_row.pack()

        self._dot = tk.Label(dot_row, text="●", bg=C["bg"],
                             fg=C["dim"], font=("Courier", 20))
        self._dot.pack(side="left", padx=(0, 10))

        self._lbl_status = tk.Label(dot_row, text="OFFLINE",
                                    bg=C["bg"], fg=C["muted"],
                                    font=("Courier", 22, "bold"))
        self._lbl_status.pack(side="left")

        self._lbl_sub = tk.Label(
            status_area,
            text="Agent is stopped. Click Start to begin transmitting.",
            bg=C["bg"], fg=C["dim"],
            font=("Courier", 9), wraplength=380,
        )
        self._lbl_sub.pack(pady=(6, 0))

        tk.Frame(r, bg=C["line"], height=1).pack(fill="x", padx=22)

        btn_wrap = tk.Frame(r, bg=C["bg"], pady=26)
        btn_wrap.pack()

        self._btn = tk.Button(
            btn_wrap,
            text="▶   START MONITORING",
            command=self._toggle,
            font=("Courier", 13, "bold"),
            relief="flat",
            bd=0,
            padx=34,
            pady=14,
            cursor="hand2",
        )
        self._btn.pack()
        self._apply_btn_style(active=False)

        tk.Frame(r, bg=C["line"], height=1).pack(fill="x", padx=22)

        stats_frame = tk.Frame(r, bg=C["bg"], pady=20)
        stats_frame.pack(fill="x", padx=28)

        tk.Label(stats_frame, text="LIVE TELEMETRY",
                 bg=C["bg"], fg=C["muted"],
                 font=("Courier", 8, "bold")).pack(anchor="w", pady=(0, 10))

        grid = tk.Frame(stats_frame, bg=C["bg"])
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=0)

        def row(label_text, attr, row_idx):
            tk.Label(grid, text=label_text, bg=C["bg"], fg=C["muted"],
                     font=("Courier", 10), anchor="w"
                     ).grid(row=row_idx, column=0, sticky="w", pady=3)
            lbl = tk.Label(grid, text="—", bg=C["bg"], fg=C["dim"],
                           font=("Courier", 10, "bold"), anchor="e", width=18)
            lbl.grid(row=row_idx, column=1, sticky="e", pady=3)
            setattr(self, attr, lbl)

        row("Download speed",    "_st_in",    0)
        row("Upload speed",      "_st_out",   1)
        row("Open connections",  "_st_conn",  2)
        row("Packets sent",      "_st_count", 3)
        row("Last transmission", "_st_last",  4)

        tk.Frame(r, bg=C["line2"], height=1).pack(fill="x", side="bottom")

        foot = tk.Frame(r, bg=C["bg1"], height=36)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)

        tk.Label(foot, text=f"→  {BACKEND_URL}",
                 bg=C["bg1"], fg=C["dim"],
                 font=("Courier", 7), anchor="w"
                 ).pack(side="left", padx=14, pady=8)

        tk.Label(foot, text=f"id: {AGENT_ID}",
                 bg=C["bg1"], fg=C["dim"],
                 font=("Courier", 7), anchor="e"
                 ).pack(side="right", padx=14, pady=8)

    def _apply_btn_style(self, active: bool):
        if active:
            self._btn.config(
                text="■   STOP MONITORING",
                bg=C["red_d"],
                fg=C["red"],
                activebackground="#4a0018",
                activeforeground=C["red"],
                highlightbackground=C["red"],
                highlightthickness=1,
            )
        else:
            self._btn.config(
                text="▶   START MONITORING",
                bg=C["bg2"],
                fg=C["green"],
                activebackground=C["green_d"],
                activeforeground=C["green"],
                highlightbackground=C["line2"],
                highlightthickness=1,
            )

    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        if not BACKEND_URL.startswith(("https://", "http://")) or not API_SECRET_KEY:
            with self._lock:
                self._stats["error"] = "Configure agent_config.json before monitoring"
            return
        self._running = True
        self._stop_evt.clear()
        with self._lock:
            self._stats = {
                "bytes_in": 0.0, "bytes_out": 0.0,
                "conn_total": 0, "last_ts": "—",
                "sent": 0, "error": None,
            }
        self._apply_btn_style(active=True)

        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        threading.Thread(target=self._snort_loop,     daemon=True).start()

    def _stop(self):
        self._running = False
        self._stop_evt.set()
        self._apply_btn_style(active=False)

    def _quit(self):
        self._stop()
        self.root.destroy()

    def _telemetry_loop(self):
        _get_net_io_delta()          # prime the delta counter
        self._stop_evt.wait(INTERVAL)

        while not self._stop_evt.is_set():
            try:
                features = _collect_features()
                event = {
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "source_tier": TIER,
                    "agent_id":    AGENT_ID,
                    "features":    features,
                }
                resp = requests.post(
                    BACKEND_URL, json=event, headers=AUTH_HEADERS, timeout=5
                )

                with self._lock:
                    self._stats["bytes_in"]   = features["bytes_in"]
                    self._stats["bytes_out"]  = features["bytes_out"]
                    self._stats["conn_total"] = features["conn_total"]
                    self._stats["sent"]      += 1
                    self._stats["last_ts"]    = datetime.now().strftime("%H:%M:%S")
                    self._stats["error"]      = None if resp.ok else f"HTTP {resp.status_code}"

            except requests.exceptions.ConnectionError:
                with self._lock:
                    self._stats["error"] = "Backend unreachable"
            except Exception as exc:
                with self._lock:
                    self._stats["error"] = str(exc)[:50]

            self._stop_evt.wait(INTERVAL)

    def _snort_loop(self):
        while not os.path.exists(SNORT_LOG):
            if self._stop_evt.wait(10):
                return
        try:
            with open(SNORT_LOG) as f:
                f.seek(0, os.SEEK_END)
                while not self._stop_evt.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    event = {
                        "timestamp":   datetime.now(timezone.utc).isoformat(),
                        "source_tier": "snort_dpi",
                        "agent_id":    AGENT_ID,
                        "features": {
                            "snort_alert": 1, "snort_msg": line.strip(),
                            "bytes_in": 0, "bytes_out": 0,
                            "conn_total": 0, "conn_rate": 0,
                            "unique_dst_ports": 0, "syn_rate": 0,
                        },
                    }
                    try:
                        requests.post(BACKEND_URL, json=event,
                                      headers=AUTH_HEADERS, timeout=2)
                    except Exception:
                        pass
        except Exception:
            pass
    def _tick(self):
        with self._lock:
            s = dict(self._stats)

        if self._running:
            self._pulse_on = not self._pulse_on
            err = s["error"]

            if err:
                # Show error in amber
                self._dot.config(fg=C["amber"])
                self._lbl_status.config(text="ERROR",   fg=C["amber"])
                self._lbl_sub.config(text=f"⚠  {err}", fg=C["amber"])
            else:
                # Animate the pulse dot green ↔ dim-green
                self._dot.config(fg=C["green"] if self._pulse_on else "#004422")
                self._lbl_status.config(text="MONITORING", fg=C["green"])
                self._lbl_sub.config(
                    text="Transmitting telemetry to operator backend.",
                    fg=C["text"],
                )

            self._st_in.config(text=_fmt_speed(s["bytes_in"]),  fg=C["cyan"])
            self._st_out.config(text=_fmt_speed(s["bytes_out"]), fg=C["text2"])
            self._st_conn.config(
                text=str(s["conn_total"]) if s["conn_total"] else "—",
                fg=C["green"],
            )
            self._st_count.config(text=str(s["sent"]),    fg=C["text2"])
            self._st_last.config(text=s["last_ts"],        fg=C["dim"])

        else:
            self._dot.config(fg=C["dim"])
            self._lbl_status.config(text="OFFLINE", fg=C["muted"])
            self._lbl_sub.config(
                text="Agent is stopped. Click Start to begin transmitting.",
                fg=C["dim"],
            )
            for w in (self._st_in, self._st_out, self._st_conn,
                      self._st_count, self._st_last):
                w.config(text="—", fg=C["dim"])

        self.root.after(500, self._tick)


def main():
    root = tk.Tk()
    app = NetWatchApp(root)
    root.after(250, app._start)
    root.mainloop()


if __name__ == "__main__":
    main()
