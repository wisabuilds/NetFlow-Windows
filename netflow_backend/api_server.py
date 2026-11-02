"""
Lightweight REST API server for NetFlow Linux telemetry and diagnostics.
Requires zero external dependencies (built on Python standard library).
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import socketserver
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional

from .bandwidth_tracker import BandwidthTracker
from .config import NetflowConfig
from .diagnostics import NetworkDiagnostics
from .storage import NetflowStorage


class NetflowAPIHandler(BaseHTTPRequestHandler):
    tracker: BandwidthTracker
    storage: NetflowStorage
    config: NetflowConfig

    def log_message(self, format, *args):
        # Silence default standard access logging to keep terminal clean
        return

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json") -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        # Restrict CORS to local origins only — prevents browser-based attacks
        origin = self.headers.get("Origin", "")
        if origin and origin.startswith(("http://127.0.0.1", "http://localhost")):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._set_headers(204)

    def do_HEAD(self) -> None:
        self._set_headers(200, "text/html; charset=utf-8")

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if path in ("/", "/index.html"):
            index_file = os.path.join(os.path.dirname(__file__), "web", "index.html")
            if os.path.exists(index_file):
                with open(index_file, "rb") as f:
                    content = f.read()
                self._set_headers(200, "text/html; charset=utf-8")
                self.wfile.write(content)
                return

        if path == "/api/stats/realtime":
            snapshot = self.tracker.get_latest_snapshot()
            if not snapshot:
                self._send_json({"status": "initializing"}, 200)
                return
            data = {
                "timestamp": snapshot.timestamp,
                "total_rx_speed_bps": snapshot.total_rx_speed,
                "total_tx_speed_bps": snapshot.total_tx_speed,
                "total_rx_speed_human": format_speed(snapshot.total_rx_speed),
                "total_tx_speed_human": format_speed(snapshot.total_tx_speed),
                "total_rx_bytes": snapshot.total_rx_bytes,
                "total_tx_bytes": snapshot.total_tx_bytes,
                "peak_rx_speed": snapshot.peak_rx_speed,
                "peak_tx_speed": snapshot.peak_tx_speed,
                "ping_latency_ms": snapshot.ping_latency_ms,
                "active_sockets": snapshot.active_socket_count,
                "interfaces": snapshot.interfaces,
                "top_processes": snapshot.top_processes,
            }
            self._send_json(data)

        elif path == "/api/stats/history":
            seconds = int(query_params.get("seconds", [60])[0])
            iface = query_params.get("interface", [None])[0]
            points = self.storage.get_recent_speeds(seconds=seconds, interface=iface)
            self._send_json({"points": points, "count": len(points)})

        elif path == "/api/stats/daily":
            days = int(query_params.get("days", [30])[0])
            history = self.storage.get_daily_usage(days=days)
            self._send_json({"daily_usage": history})

        elif path == "/api/stats/summary":
            summary = self.storage.get_usage_summary()
            self._send_json(summary)

        elif path == "/api/stats/top-apps":
            period = int(query_params.get("period", [86400])[0])
            limit = int(query_params.get("limit", [15])[0])
            top_apps = self.storage.get_top_processes(period_seconds=period, limit=limit)
            self._send_json({"top_apps": top_apps})

        elif path == "/api/netstat":
            results = self.tracker.get_active_sockets_enriched()
            self._send_json({"sockets": results, "total": len(results)})

        elif path == "/api/plan":
            status = self.storage.get_data_plan_status()
            self._send_json(status)

        elif path == "/api/plan/forecast":
            forecast = self.storage.get_budget_forecast()
            self._send_json(forecast)

        elif path == "/api/monitor/status":
            self._send_json({"incognito": self.tracker.is_incognito})

        elif path == "/api/export/csv":
            export_type = query_params.get("type", ["daily"])[0]
            if export_type == "processes":
                csv_data = self.storage.export_processes_csv()
            else:
                csv_data = self.storage.export_daily_csv()
            self._send_csv(csv_data, filename=f"netflow_{export_type}.csv")

        elif path == "/api/export/json":
            export_data = {
                "daily": self.storage.get_daily_usage(days=90),
                "top_processes": self.storage.get_top_processes(period_seconds=30 * 86400),
                "plan": self.storage.get_data_plan_status(),
                "forecast": self.storage.get_budget_forecast(),
                "exported_at": time.time(),
            }
            self._send_json(export_data)

        elif path == "/api/diagnostics/ping":
            target = query_params.get("target", [self.config.default_ping_target])[0]
            result = NetworkDiagnostics.measure_ping(target=target)
            self._send_json(result)

        elif path == "/api/diagnostics/devices":
            devices = NetworkDiagnostics.get_local_subnet_devices()
            self._send_json({"devices": devices, "total": len(devices)})

        elif path == "/api/diagnostics/wifi":
            wifi_networks = NetworkDiagnostics.scan_wifi_networks()
            self._send_json({"networks": wifi_networks, "total": len(wifi_networks)})

        elif path == "/api/firewall/status":
            status = self.tracker.firewall.get_status()
            self._send_json(status)

        elif path == "/api/firewall/events":
            limit = int(query_params.get("limit", [50])[0])
            events = self.storage.get_firewall_events(limit=limit)
            self._send_json({"events": events, "total": len(events)})

        else:
            self._send_json({"error": "Endpoint not found", "path": path}, 404)

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/plan":
            period = payload.get("period", "monthly")
            if period not in ("daily", "monthly"):
                period = "monthly"
            limit_bytes = payload.get("limit_bytes")
            if limit_bytes is not None:
                try:
                    limit_bytes = int(limit_bytes)
                except (ValueError, TypeError):
                    limit_bytes = None
                if limit_bytes is not None and limit_bytes < 0:
                    limit_bytes = 0
            reset_day = max(1, min(28, int(payload.get("reset_day", 1))))
            warning_pct = max(1, min(100, int(payload.get("warning_pct", 80))))
            self.storage.update_data_plan(period, limit_bytes, reset_day, warning_pct)
            self._send_json({"status": "updated", "plan": self.storage.get_data_plan_status()})

        elif path == "/api/monitor/incognito":
            state = payload.get("enabled")
            new_state = self.tracker.toggle_incognito(state)
            self._send_json({"incognito": new_state, "status": "active" if new_state else "disabled"})

        elif path == "/api/firewall/toggle":
            enabled = payload.get("enabled")
            new_state = self.tracker.firewall.toggle_firewall(enabled=enabled)
            self._send_json({"enabled": new_state, "status": "active" if new_state else "disabled"})

        elif path == "/api/firewall/policy":
            process_name = payload.get("process_name")
            if not process_name:
                self._send_json({"error": "Missing process_name"}, 400)
                return
            policy = payload.get("policy", "block")
            pol = self.tracker.firewall.set_app_policy(process_name, policy)
            self._send_json({
                "process_name": process_name,
                "policy": pol,
                "blocked": pol in ("block", "lan_only"),
                "firewall": self.tracker.firewall.get_status(),
            })

        elif path == "/api/firewall/block":
            process_name = payload.get("process_name")
            if not process_name:
                self._send_json({"error": "Missing process_name"}, 400)
                return
            blocked = bool(payload.get("blocked", True))
            pol = "block" if blocked else "allow"
            self.tracker.firewall.set_app_policy(process_name, pol)
            self._send_json({
                "process_name": process_name,
                "blocked": blocked,
                "policy": pol,
                "status": "blocked" if blocked else "allowed",
                "firewall": self.tracker.firewall.get_status(),
            })

        elif path == "/api/firewall/clear":
            cleared_count = self.tracker.firewall.clear_all_blocks()
            self._send_json({"cleared_count": cleared_count, "status": "all_unblocked"})

        elif path == "/api/diagnostics/speedtest":
            size_mb = max(1, min(100, int(payload.get("size_mb", 5))))
            result = NetworkDiagnostics.run_speed_test(test_size_mb=size_mb)
            self._send_json(result)

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

    def _send_csv(self, csv_data: str, filename: str = "export.csv") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        origin = self.headers.get("Origin", "")
        if origin and origin.startswith(("http://127.0.0.1", "http://localhost")):
            self.send_header("Access-Control-Allow-Origin", origin)
        payload = csv_data.encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


    def _send_json(self, data: Any, status_code: int = 200) -> None:
        self._set_headers(status_code, "application/json")
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))


def format_speed(bytes_per_sec: float) -> str:
    """Formats bytes/s to human readable string (e.g. 1.25 MB/s)."""
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.0f} B/s"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    elif bytes_per_sec < 1024 * 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
    else:
        return f"{bytes_per_sec / (1024 * 1024 * 1024):.2f} GB/s"


class APIServer:
    def __init__(self, tracker: BandwidthTracker, storage: NetflowStorage, config: NetflowConfig):
        self.tracker = tracker
        self.storage = storage
        self.config = config
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        # Bind handler with dependency injection
        class CustomHandler(NetflowAPIHandler):
            tracker = self.tracker
            storage = self.storage
            config = self.config

        self._server = HTTPServer((self.config.api_host, self.config.api_port), CustomHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
