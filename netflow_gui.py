#!/usr/bin/env python3
"""
NetFlow Linux: Native GNOME / Libadwaita Desktop Application.
Renders NetFlow as a standalone native Linux desktop app window using GTK 4 and Libadwaita.
"""

import os
import signal
import sys
import threading
import time

# Ubuntu 24.04 LTS restricts unprivileged bwrap namespaces; disable sandbox for local trusted UI
os.environ["WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"] = "1"

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("WebKit", "6.0")

from gi.repository import Adw, GLib, Gio, Gtk, WebKit

from netflow_backend.api_server import APIServer
from netflow_backend.bandwidth_tracker import BandwidthTracker
from netflow_backend.config import NetflowConfig
from netflow_backend.diagnostics import NetworkDiagnostics
from netflow_backend.storage import NetflowStorage


APP_ID = "io.github.netflow.NetFlowLinux"


class NetflowNativeApp(Adw.Application):
    def __init__(self, port: int = 9095, default_tab: str = ""):
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.port = port
        self.default_tab = default_tab
        self.server: APIServer = None
        self.tracker: BandwidthTracker = None
        self.storage: NetflowStorage = None
        self.stop_event = threading.Event()
        self._ensure_backend_running()

    def _ensure_backend_running(self):
        """Starts the local collector engine and API server in background threads if needed."""
        import urllib.request
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/api/stats/realtime", timeout=1) as resp:
                if resp.status == 200:
                    # Daemon is already running healthy in background
                    return
        except Exception:
            pass

        config = NetflowConfig(api_port=self.port)
        config.ensure_directories()
        self.storage = NetflowStorage(config.db_path)
        self.tracker = BandwidthTracker(config, self.storage)
        self.tracker.tick()

        # Start API server
        self.server = APIServer(self.tracker, self.storage, config)
        try:
            self.server.start()
        except OSError:
            # Server port might already be bound by a background daemon instance
            pass

        # Collector loop thread
        def collector_loop():
            while not self.stop_event.is_set():
                self.tracker.tick()
                time.sleep(config.poll_interval)

        th = threading.Thread(target=collector_loop, daemon=True)
        th.start()

        # Ping probe thread
        def ping_loop():
            while not self.stop_event.is_set():
                res = NetworkDiagnostics.measure_ping(config.default_ping_target, count=1, timeout=2)
                if res.get("success") and res.get("latency_ms") is not None:
                    self.tracker.set_ping_latency(res["latency_ms"])
                self.stop_event.wait(5.0)

        pth = threading.Thread(target=ping_loop, daemon=True)
        pth.start()

    def do_activate(self):
        # Create native Libadwaita window
        win = self.props.active_window
        if not win:
            win = Adw.ApplicationWindow(application=self)
            win.set_title("NetFlow")
            win.set_icon_name("netflow")
            win.set_default_size(1060, 740)

            # Window layout box
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

            # Native GNOME AdwHeaderBar
            header = Adw.HeaderBar()
            header.set_show_title(True)

            # Title widget with subtitle
            title_widget = Adw.WindowTitle()
            title_widget.set_title("NetFlow")
            title_widget.set_subtitle("Network Monitor & Quota")
            header.set_title_widget(title_widget)

            # Refresh button in header
            refresh_btn = Gtk.Button()
            refresh_btn.set_icon_name("view-refresh-symbolic")
            refresh_btn.set_tooltip_text("Reload Data")
            header.pack_start(refresh_btn)

            box.append(header)

            # Native WebKitGTK view
            webview = WebKit.WebView()
            
            # Ensure local loopback connections bypass environment proxies
            ns = webview.get_network_session()
            if ns:
                ns.set_proxy_settings(WebKit.NetworkProxyMode.NO_PROXY, None)

            # Configure settings (dark mode, local access)
            settings = webview.get_settings()
            settings.set_enable_developer_extras(True)
            settings.set_javascript_can_access_clipboard(True)

            # Bind refresh button
            refresh_btn.connect("clicked", lambda b: webview.reload())

            # Load the local NetFlow interface in native mode (supports optional default_tab)
            hash_frag = f"#{self.default_tab}" if self.default_tab else ""
            webview.load_uri(f"http://127.0.0.1:{self.port}/?native=1{hash_frag}")
            box.append(webview)

            # Make webview expand to fill window
            webview.set_vexpand(True)
            webview.set_hexpand(True)

            win.set_content(box)

        win.present()

    def do_shutdown(self):
        self.stop_event.set()
        if self.server:
            self.server.stop()
        Adw.Application.do_shutdown(self)


def main():
    # Handle clean termination
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    tab = ""
    clean_argv = [sys.argv[0]]
    for arg in sys.argv[1:]:
        if arg.startswith("--tab="):
            tab = arg.split("=", 1)[1]
        else:
            clean_argv.append(arg)
    app = NetflowNativeApp(port=9095, default_tab=tab)
    return app.run(clean_argv)


if __name__ == "__main__":
    sys.exit(main())
