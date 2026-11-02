#!/usr/bin/env python3
"""
NetFlow Linux: Main entrypoint.
Starts the bandwidth collector, storage engine, background diagnostics, and REST API.
"""

import argparse
import os
import signal
import sys
import threading
import time

from netflow_backend.api_server import APIServer
from netflow_backend.bandwidth_tracker import BandwidthTracker
from netflow_backend.cli import TerminalDashboard
from netflow_backend.config import NetflowConfig
from netflow_backend.diagnostics import NetworkDiagnostics
from netflow_backend.storage import NetflowStorage


def ping_worker(tracker: BandwidthTracker, target: str, stop_event: threading.Event) -> None:
    """Background worker periodically checking gateway/DNS latency."""
    while not stop_event.is_set():
        res = NetworkDiagnostics.measure_ping(target=target, count=1, timeout=2)
        if res.get("success") and res.get("latency_ms") is not None:
            tracker.set_ping_latency(res["latency_ms"])
        stop_event.wait(5.0)


def main():
    parser = argparse.ArgumentParser(
        description="NetFlow Linux: Network Speed, Quota & Process Attribution Monitor"
    )
    parser.add_argument("--port", type=int, default=9095, help="REST API port (default: 9095)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="API host (default: 127.0.0.1)")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--db", type=str, default=None, help="Custom SQLite database path")
    parser.add_argument("--daemon", action="store_true", help="Run in headless daemon mode (no TUI)")
    parser.add_argument("--tui", action="store_true", help="Run interactive terminal dashboard")
    parser.add_argument("--open", action="store_true", help="Automatically open GUI in default browser")
    # Quick Diagnostic subcommands
    parser.add_argument("--ping", type=str, nargs="?", const="1.1.1.1", help="Run latency ping test to target")
    parser.add_argument("--scan", action="store_true", help="Scan local network for devices (ARP/neighbor)")
    parser.add_argument("--speedtest", action="store_true", help="Run internet speed test")
    parser.add_argument("--plan-set-gb", type=float, help="Set data plan limit in Gigabytes (GB)")

    args = parser.parse_args()

    # Standalone diagnostic commands
    if args.ping:
        print(f"[*] Pinging {args.ping}...")
        res = NetworkDiagnostics.measure_ping(args.ping, count=3)
        if res.get("success"):
            print(f"[-] Target: {res['target']} | Latency: {res.get('avg_ms')} ms (min: {res.get('min_ms')} ms, max: {res.get('max_ms')} ms)")
        else:
            print(f"[!] Ping failed: {res.get('error')}")
        return

    if args.scan:
        print("[*] Scanning local subnet for active devices...")
        devices = NetworkDiagnostics.get_local_subnet_devices()
        if not devices:
            print("[!] No local devices found in neighbor table.")
        else:
            print(f"\n{'IP Address':<18} | {'MAC Address':<18} | {'Vendor':<20} | {'Hostname'}")
            print("-" * 75)
            for d in devices:
                print(f"{d['ip']:<18} | {d['mac']:<18} | {d['vendor']:<20} | {d['hostname']}")
            print(f"\nTotal: {len(devices)} device(s) found.")
        return

    if args.speedtest:
        print("[*] Running internet speed test (fetching test payload from CDN)...")
        res = NetworkDiagnostics.run_speed_test(test_size_mb=5)
        if res.get("success"):
            print(f"[-] Download Speed: {res['speed_mbps']} Mbps ({res['speed_mbytes_sec']} MB/s)")
            print(f"[-] Transferred: {res['bytes_transferred'] / 1024 / 1024:.2f} MB in {res['duration_seconds']}s")
        else:
            print(f"[!] Speed test failed: {res.get('error')}")
        return

    # Initialize configuration & storage
    config = NetflowConfig(
        poll_interval=args.interval,
        api_host=args.host,
        api_port=args.port,
    )
    if args.db:
        config.db_path = args.db

    config.ensure_directories()
    storage = NetflowStorage(config.db_path)

    if args.plan_set_gb:
        limit_bytes = int(args.plan_set_gb * 1024 * 1024 * 1024)
        storage.update_data_plan(period="monthly", limit_bytes=limit_bytes)
        print(f"[+] Configured data plan limit to {args.plan_set_gb} GB.")
        return

    tracker = BandwidthTracker(config, storage)

    # Start REST API server
    api_server = APIServer(tracker, storage, config)
    api_server.start()
    url = f"http://{config.api_host}:{config.api_port}"
    print(f"[+] NetFlow API Server running at {url}")

    if args.open:
        import webbrowser
        webbrowser.open(url)

    # Start background ping monitoring
    stop_event = threading.Event()
    ping_th = threading.Thread(
        target=ping_worker,
        args=(tracker, config.default_ping_target, stop_event),
        daemon=True,
    )
    ping_th.start()

    # Initial tick to seed rates
    tracker.tick()

    def handle_exit(signum, frame):
        stop_event.set()
        api_server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Decide whether to run TUI or daemon loop
    should_run_tui = args.tui or (not args.daemon and sys.stdout.isatty())

    if should_run_tui:
        # Background collection thread driving the tracker
        def collector_loop():
            while not stop_event.is_set():
                tracker.tick()
                time.sleep(config.poll_interval)

        coll_th = threading.Thread(target=collector_loop, daemon=True)
        coll_th.start()

        dashboard = TerminalDashboard(tracker, storage, config)
        dashboard.run()
        handle_exit(None, None)
    else:
        print("[+] NetFlow Daemon active. Collecting traffic stats...")
        try:
            while not stop_event.is_set():
                snapshot = tracker.tick()
                time.sleep(config.poll_interval)
        except KeyboardInterrupt:
            handle_exit(None, None)


if __name__ == "__main__":
    main()
