"""
Integrated network diagnostics suite: Ping, LAN Device Scanner, and Speed Test.
"""

from concurrent.futures import ThreadPoolExecutor
import os
import re
import socket
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional


COMMON_OUI_VENDORS = {
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "f0:18:98": "Apple",
    "a4:83:e7": "Apple",
    "3c:22:fb": "Apple",
    "ac:de:48": "Apple",
    "bc:d0:74": "Google",
    "54:60:09": "Google",
    "f4:f5:e8": "Google",
    "d4:6a:6a": "Samsung",
    "8c:79:67": "Samsung",
    "00:1a:2b": "Cisco",
    "00:0c:29": "VMware",
    "52:54:00": "QEMU/KVM",
    "08:00:27": "VirtualBox",
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    "00:11:32": "Synology",
    "b0:4e:26": "Intel",
}


def lookup_mac_vendor(mac: str) -> str:
    cleaned = mac.lower().replace("-", ":")
    prefix = ":".join(cleaned.split(":")[:3])
    return COMMON_OUI_VENDORS.get(prefix, "Unknown Vendor")


class NetworkDiagnostics:
    @staticmethod
    def measure_ping(target: str = "1.1.1.1", count: int = 1, timeout: int = 2) -> Dict[str, Any]:
        """
        Measures ICMP round-trip latency to a destination host using system ping.
        """
        try:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), target]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout + 2,
            )
            if result.returncode != 0:
                return {
                    "target": target,
                    "success": False,
                    "latency_ms": None,
                    "error": "Destination unreachable",
                }

            # Parse ping output: 'rtt min/avg/max/mdev = 12.345/14.567/18.901/2.345 ms'
            match = re.search(r"rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", result.stdout)
            if match:
                return {
                    "target": target,
                    "success": True,
                    "latency_ms": float(match.group(2)),
                    "min_ms": float(match.group(1)),
                    "avg_ms": float(match.group(2)),
                    "max_ms": float(match.group(3)),
                    "mdev_ms": float(match.group(4)),
                }

            # Fallback simple time parse: 'time=14.2 ms'
            simple_match = re.search(r"time=([\d\.]+)\s*ms", result.stdout)
            if simple_match:
                lat = float(simple_match.group(1))
                return {"target": target, "success": True, "latency_ms": lat, "avg_ms": lat}

            return {"target": target, "success": True, "latency_ms": None}
        except Exception:
            # Fallback: Measure TCP handshake latency (e.g. port 80/443/53) which requires no raw socket privileges
            try:
                port = 80
                if target in ("1.1.1.1", "8.8.8.8"):
                    port = 53
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target, port))
                sock.close()
                elapsed_ms = (time.time() - start) * 1000.0
                return {
                    "target": target,
                    "success": True,
                    "latency_ms": round(elapsed_ms, 2),
                    "min_ms": round(elapsed_ms, 2),
                    "avg_ms": round(elapsed_ms, 2),
                    "max_ms": round(elapsed_ms, 2),
                    "method": "tcp_connect",
                }
            except Exception as tcp_ex:
                return {"target": target, "success": False, "latency_ms": None, "error": str(tcp_ex)}


    @staticmethod
    def get_local_subnet_devices() -> List[Dict[str, Any]]:
        """
        Discovers active devices on the local network by reading the kernel ARP/neighbor table.
        """
        devices: List[Dict[str, Any]] = []
        arp_path = "/proc/net/arp"

        if os.path.exists(arp_path):
            try:
                with open(arp_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        hw_type = parts[1]
                        flags = parts[2]
                        mac = parts[3]
                        iface = parts[5]

                        # Ignore incomplete / empty MACs
                        if mac == "00:00:00:00:00:00" or flags == "0x0":
                            continue

                        hostname = "Unknown"
                        try:
                            # Quick non-blocking reverse DNS
                            name, _, _ = socket.gethostbyaddr(ip)
                            hostname = name
                        except Exception:
                            pass

                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": lookup_mac_vendor(mac),
                            "interface": iface,
                            "hostname": hostname,
                        })
            except Exception:
                pass

        # Also probe via 'ip neigh' if available for updated status
        if not devices:
            try:
                out = subprocess.check_output(["ip", "neigh"], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        ip = parts[0]
                        mac = parts[parts.index("lladdr") + 1]
                        iface = parts[parts.index("dev") + 1] if "dev" in parts else ""
                        state = parts[-1]
                        if state != "FAILED":
                            devices.append({
                                "ip": ip,
                                "mac": mac,
                                "vendor": lookup_mac_vendor(mac),
                                "interface": iface,
                                "hostname": "Unknown",
                            })
            except Exception:
                pass

        return devices

    @staticmethod
    def run_speed_test(test_size_mb: int = 5) -> Dict[str, Any]:
        """
        Runs an HTTP multi-megabyte download test against a standard CDN to compute throughput.
        """
        # Test download endpoint (Cloudflare speed test endpoint)
        bytes_to_fetch = test_size_mb * 1024 * 1024
        url = f"https://speed.cloudflare.com/__down?bytes={bytes_to_fetch}"

        start_time = time.time()
        received_bytes = 0
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NetFlow-Linux-SpeedTest/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    received_bytes += len(chunk)

            duration = max(0.001, time.time() - start_time)
            speed_bps = (received_bytes * 8) / duration
            speed_mbps = speed_bps / 1_000_000
            speed_mbytes_sec = (received_bytes / 1024 / 1024) / duration

            return {
                "success": True,
                "bytes_transferred": received_bytes,
                "duration_seconds": round(duration, 2),
                "speed_mbps": round(speed_mbps, 2),
                "speed_mbytes_sec": round(speed_mbytes_sec, 2),
            }
        except Exception as ex:
            return {
                "success": False,
                "error": str(ex),
                "speed_mbps": 0.0,
            }

    @staticmethod
    def scan_wifi_networks() -> List[Dict[str, Any]]:
        """
        Wi-Fi Analyzer: scans nearby Wi-Fi SSIDs, channels, frequencies, signal %, and security.
        Uses nmcli or iw scan.
        """
        networks: List[Dict[str, Any]] = []
        try:
            # Trigger rescan and list Wi-Fi networks via nmcli
            cmd = ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,BARS", "dev", "wifi", "list"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().splitlines():
                    # Format: SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY:BARS
                    # Handle escaped colons in SSID
                    parts = line.split(":")
                    if len(parts) >= 6:
                        # Sometimes SSID has colons; extract from right side
                        security = parts[-2] if len(parts) >= 7 else parts[-1]
                        signal_pct = int(parts[-3]) if len(parts) >= 7 and parts[-3].isdigit() else (int(parts[-2]) if parts[-2].isdigit() else 0)
                        freq = parts[-4] if len(parts) >= 7 else parts[-3]
                        channel = parts[-5] if len(parts) >= 7 else parts[-4]
                        bssid = parts[-6] if len(parts) >= 7 else parts[-5]
                        ssid = ":".join(parts[:-6]) if len(parts) >= 7 else parts[0]
                        ssid = ssid.strip() or "(Hidden SSID)"

                        # Determine 2.4GHz vs 5GHz / 6GHz
                        band = "2.4 GHz"
                        try:
                            f_mhz = int(freq.replace("MHz", "").strip())
                            if f_mhz > 5900:
                                band = "6 GHz"
                            elif f_mhz > 5000:
                                band = "5 GHz"
                        except Exception:
                            pass

                        networks.append({
                            "ssid": ssid,
                            "bssid": bssid,
                            "channel": channel,
                            "frequency": freq,
                            "band": band,
                            "signal_pct": signal_pct,
                            "security": security or "Open",
                        })
        except Exception:
            pass

        # Sort by signal strength descending
        networks.sort(key=lambda x: x["signal_pct"], reverse=True)
        return networks
