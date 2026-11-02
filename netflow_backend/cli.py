"""
Terminal User Interface (TUI) and Console Dashboard for NetFlow Linux.
Provides live bandwidth rates, ASCII sparklines, and top network processes.
"""

from collections import deque
import os
import sys
import time
from typing import Deque

from .api_server import format_speed
from .bandwidth_tracker import BandwidthTracker
from .config import NetflowConfig
from .diagnostics import NetworkDiagnostics
from .storage import NetflowStorage


SPARKLINE_CHARS = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]


def render_sparkline(values: Deque[float], length: int = 30) -> str:
    if not values:
        return " " * length
    vals = list(values)[-length:]
    if len(vals) < length:
        vals = [0.0] * (length - len(vals)) + vals
    max_val = max(vals) if max(vals) > 0 else 1.0
    chars = []
    for v in vals:
        idx = int((v / max_val) * (len(SPARKLINE_CHARS) - 1))
        idx = max(0, min(len(SPARKLINE_CHARS) - 1, idx))
        chars.append(SPARKLINE_CHARS[idx])
    return "".join(chars)


class TerminalDashboard:
    def __init__(self, tracker: BandwidthTracker, storage: NetflowStorage, config: NetflowConfig):
        self.tracker = tracker
        self.storage = storage
        self.config = config
        self.rx_history: Deque[float] = deque(maxlen=40)
        self.tx_history: Deque[float] = deque(maxlen=40)

    def run(self) -> None:
        """Runs the live terminal dashboard loop."""
        sys.stdout.write("\033[?25l")  # Hide cursor
        try:
            while True:
                snapshot = self.tracker.get_latest_snapshot()
                if snapshot:
                    self.rx_history.append(snapshot.total_rx_speed)
                    self.tx_history.append(snapshot.total_tx_speed)
                    self._draw_screen(snapshot)
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            pass
        finally:
            sys.stdout.write("\033[?25h\033[0m\n")  # Show cursor
            sys.stdout.flush()

    def _draw_screen(self, s) -> None:
        # Clear screen and move cursor to top-left
        out = ["\033[H\033[2J"]
        out.append("\033[1;36m================================================================================")
        out.append("  ⚡ NetFlow Linux — Network Speed, Quota & Process Attribution Monitor")
        out.append("================================================================================\033[0m")

        # Speed Meter Section
        rx_human = format_speed(s.total_rx_speed)
        tx_human = format_speed(s.total_tx_speed)
        peak_rx = format_speed(s.peak_rx_speed)
        peak_tx = format_speed(s.peak_tx_speed)
        ping_str = f"{s.ping_latency_ms:.1f} ms" if s.ping_latency_ms is not None else "Measuring..."

        out.append(f"\033[1;32m  ▼ DOWNLOAD : {rx_human:<12} (Peak: {peak_rx:<10}) \033[0m | Ping: \033[1;33m{ping_str}\033[0m")
        out.append(f"    Graph : [\033[32m{render_sparkline(self.rx_history, 35)}\033[0m]")
        out.append(f"\033[1;34m  ▲ UPLOAD   : {tx_human:<12} (Peak: {peak_tx:<10}) \033[0m | Sockets: \033[1;35m{s.active_socket_count}\033[0m")
        out.append(f"    Graph : [\033[34m{render_sparkline(self.tx_history, 35)}\033[0m]")
        out.append("")

        # Data Plan Quota Bar
        plan = self.storage.get_data_plan_status()
        if plan.get("configured") and plan.get("limit_bytes"):
            pct = plan["percentage"]
            bar_len = 30
            filled = int((pct / 100) * bar_len)
            filled = min(bar_len, filled)
            bar = "█" * filled + "░" * (bar_len - filled)
            used_gb = plan["used_bytes"] / (1024**3)
            limit_gb = plan["limit_bytes"] / (1024**3)
            color = "\033[1;31m" if plan.get("warning_triggered") else "\033[1;32m"
            out.append(f"  📊 Quota ({plan['period']}): {color}[{bar}] {pct:.1f}% ({used_gb:.2f} GB / {limit_gb:.2f} GB)\033[0m")
            out.append("")

        # Interfaces breakdown
        out.append("\033[1m  Network Interfaces:\033[0m")
        for if_name, if_data in s.interfaces.items():
            if if_name in self.config.excluded_interfaces:
                continue
            rx_rate = format_speed(if_data["rx_speed"])
            tx_rate = format_speed(if_data["tx_speed"])
            out.append(f"    • {if_name:<10} ▼ {rx_rate:<10}  ▲ {tx_rate:<10}")
        out.append("")

        # Top Network Applications
        out.append("\033[1m  Top Network Applications & Active Sockets:\033[0m")
        out.append(f"  {'PID':<7} | {'PROCESS':<20} | {'CONN':<5} | {'REMOTE ENDPOINTS'}")
        out.append("  " + "-" * 74)

        if not s.top_processes:
            out.append("  (No active process sockets detected)")
        else:
            for p in s.top_processes[:8]:
                pid_str = str(p["pid"]) if p["pid"] else "-"
                pname = (p["name"][:18] + "..") if len(p["name"]) > 20 else p["name"]
                conns = str(p["active_connections"])
                remotes = ", ".join(p["remote_endpoints"][:2]) or "Listening / Idle"
                out.append(f"  {pid_str:<7} | {pname:<20} | {conns:<5} | {remotes}")

        out.append("")
        out.append("\033[90m  [Ctrl+C] Exit | API listening on http://127.0.0.1:" + str(self.config.api_port) + " | Storage: SQLite\033[0m")

        sys.stdout.write("\n".join(out))
        sys.stdout.flush()
