"""
Bandwidth tracker and process attribution engine.
Computes real-time rates, deltas, and aggregates metrics.
"""

from dataclasses import asdict, dataclass, field
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from .config import NetflowConfig
from .dns_resolver import get_dns_resolver
from .firewall import FirewallEngine
from .notifications import send_desktop_notification
from .proc_reader import InterfaceStats, ProcReader, SocketInfo
from .storage import NetflowStorage


@dataclass
class ProcessBandwidth:
    pid: int
    name: str
    cmdline: str
    active_connections: int
    remote_endpoints: List[str]
    rx_bytes_delta: int = 0
    tx_bytes_delta: int = 0
    rx_speed: float = 0.0
    tx_speed: float = 0.0


@dataclass
class RealtimeSnapshot:
    timestamp: float
    total_rx_speed: float  # bytes / sec
    total_tx_speed: float  # bytes / sec
    total_rx_bytes: int
    total_tx_bytes: int
    peak_rx_speed: float
    peak_tx_speed: float
    interfaces: Dict[str, Dict[str, Any]]
    top_processes: List[Dict[str, Any]]
    active_socket_count: int
    ping_latency_ms: Optional[float] = None


class BandwidthTracker:
    def __init__(self, config: NetflowConfig, storage: NetflowStorage):
        self.config = config
        self.storage = storage
        self.proc_reader = ProcReader()
        self.firewall = FirewallEngine(self.storage)
        self.dns_resolver = get_dns_resolver()
        self.is_incognito = False
        self._last_surge_notification: float = 0.0

        self._prev_iface_stats: Dict[str, InterfaceStats] = {}
        self._prev_timestamp: float = 0.0

        self.peak_rx_speed: float = 0.0
        self.peak_tx_speed: float = 0.0
        self.latest_ping_ms: Optional[float] = None

        self._lock = threading.Lock()
        self._latest_snapshot: Optional[RealtimeSnapshot] = None
        self._active_sockets: List[SocketInfo] = []

        # Periodic flush accumulator for storage (writes to DB every N ticks)
        self._storage_flush_counter: int = 0
        self._storage_flush_interval: int = 2  # every 2 seconds
        self._last_quota_notification: float = 0.0

    def tick(self) -> RealtimeSnapshot:
        """
        Executes one polling cycle:
        1. Reads current /proc/net/dev counters.
        2. Calculates time delta and rate (bytes/s).
        3. Parses active sockets and associates with processes.
        4. Distributes metrics and writes to database.
        """
        current_time = time.time()
        curr_iface_stats = self.proc_reader.read_interface_stats()

        # Handle first tick
        if not self._prev_iface_stats or self._prev_timestamp <= 0:
            self._prev_iface_stats = curr_iface_stats
            self._prev_timestamp = current_time
            # Return initial zero-rate snapshot
            snapshot = RealtimeSnapshot(
                timestamp=current_time,
                total_rx_speed=0.0,
                total_tx_speed=0.0,
                total_rx_bytes=sum(s.rx_bytes for name, s in curr_iface_stats.items() if name not in self.config.excluded_interfaces),
                total_tx_bytes=sum(s.tx_bytes for name, s in curr_iface_stats.items() if name not in self.config.excluded_interfaces),
                peak_rx_speed=0.0,
                peak_tx_speed=0.0,
                interfaces={},
                top_processes=[],
                active_socket_count=0,
                ping_latency_ms=self.latest_ping_ms,
            )
            with self._lock:
                self._latest_snapshot = snapshot
            return snapshot

        dt = max(0.001, current_time - self._prev_timestamp)

        total_rx_speed = 0.0
        total_tx_speed = 0.0
        total_rx_bytes = 0
        total_tx_bytes = 0
        iface_summary: Dict[str, Dict[str, Any]] = {}

        for iface_name, curr in curr_iface_stats.items():
            prev = self._prev_iface_stats.get(iface_name)
            if not prev:
                continue

            rx_delta = max(0, curr.rx_bytes - prev.rx_bytes)
            tx_delta = max(0, curr.tx_bytes - prev.tx_bytes)

            rx_speed = rx_delta / dt
            tx_speed = tx_delta / dt

            is_excluded = iface_name in self.config.excluded_interfaces
            if not is_excluded:
                total_rx_speed += rx_speed
                total_tx_speed += tx_speed
                total_rx_bytes += curr.rx_bytes
                total_tx_bytes += curr.tx_bytes

            iface_summary[iface_name] = {
                "rx_speed": rx_speed,
                "tx_speed": tx_speed,
                "rx_delta": rx_delta,
                "tx_delta": tx_delta,
                "total_rx": curr.rx_bytes,
                "total_tx": curr.tx_bytes,
                "rx_packets": curr.rx_packets,
                "tx_packets": curr.tx_packets,
                "rx_drop": curr.rx_drop,
                "tx_drop": curr.tx_drop,
            }

            # Write to storage (bypassed when in incognito privacy mode)
            if not self.is_incognito and not is_excluded and (rx_delta > 0 or tx_delta > 0 or self._storage_flush_counter % 5 == 0):
                self.storage.record_interface_snapshot(
                    timestamp=int(current_time),
                    interface=iface_name,
                    rx_bytes=rx_delta,
                    tx_bytes=tx_delta,
                    rx_speed=rx_speed,
                    tx_speed=tx_speed,
                )

        if total_rx_speed > self.peak_rx_speed:
            self.peak_rx_speed = total_rx_speed
        if total_tx_speed > self.peak_tx_speed:
            self.peak_tx_speed = total_tx_speed

        # Bandwidth surge / spike detector (alert if sustained high throughput)
        if total_rx_speed > 12 * 1024 * 1024 and (current_time - self._last_surge_notification > 60):
            self._last_surge_notification = current_time
            send_desktop_notification(
                "NetFlow: High Bandwidth Surge",
                f"Download traffic surged to {total_rx_speed / (1024*1024):.1f} MB/s.",
                urgency="normal",
            )

        # Process active sockets
        sockets = self.proc_reader.read_sockets(include_udp=True, resolve_processes=True)
        with self._lock:
            self._active_sockets = sockets

        # Aggregate sockets by process
        proc_groups: Dict[str, Dict[str, Any]] = {}
        for s in sockets:
            pname = s.process_name or f"system/uid:{s.uid}"
            pid = s.pid or 0
            key = f"{pname}:{pid}"
            if key not in proc_groups:
                proc_groups[key] = {
                    "pid": pid,
                    "name": pname,
                    "cmdline": s.cmdline or pname,
                    "active_connections": 0,
                    "remote_endpoints": set(),
                }
            proc_groups[key]["active_connections"] += 1
            if s.remote_ip and s.remote_ip != "0.0.0.0" and s.remote_ip != "::":
                proc_groups[key]["remote_endpoints"].add(f"{s.remote_ip}:{s.remote_port}")

        top_procs: List[Dict[str, Any]] = []
        for group in proc_groups.values():
            endpoints = list(group["remote_endpoints"])[:5]  # cap display to 5
            pol = self.firewall.get_app_policy(group["name"])
            top_procs.append({
                "pid": group["pid"],
                "name": group["name"],
                "cmdline": group["cmdline"],
                "active_connections": group["active_connections"],
                "remote_endpoints": endpoints,
                "blocked": pol in ("block", "lan_only"),
                "policy": pol,
            })

        # Enforce active firewall policy against current sockets
        self.firewall.enforce(sockets, top_procs)

        # Sort top processes by active connection count
        top_procs.sort(key=lambda x: x["active_connections"], reverse=True)

        # Record process snapshots for active network apps (bypassed in incognito mode)
        if not self.is_incognito:
            for p in top_procs[:10]:
                self.storage.record_process_snapshot(
                    timestamp=int(current_time),
                    process_name=p["name"],
                    pid=p["pid"],
                    rx_bytes=0,
                    tx_bytes=0,
                    active_connections=p["active_connections"],
                )

        snapshot = RealtimeSnapshot(
            timestamp=current_time,
            total_rx_speed=total_rx_speed,
            total_tx_speed=total_tx_speed,
            total_rx_bytes=total_rx_bytes,
            total_tx_bytes=total_tx_bytes,
            peak_rx_speed=self.peak_rx_speed,
            peak_tx_speed=self.peak_tx_speed,
            interfaces=iface_summary,
            top_processes=top_procs[:15],
            active_socket_count=len(sockets),
            ping_latency_ms=self.latest_ping_ms,
        )

        with self._lock:
            self._latest_snapshot = snapshot

        self._prev_iface_stats = curr_iface_stats
        self._prev_timestamp = current_time
        self._storage_flush_counter += 1

        # Check data plan quota alert every 30 seconds
        if self._storage_flush_counter % 30 == 0:
            plan = self.storage.get_data_plan_status()
            if plan.get("configured") and plan.get("warning_triggered"):
                if current_time - self._last_quota_notification > 21600:
                    pct = plan.get("percentage", 0)
                    used_gb = plan.get("used_bytes", 0) / (1024**3)
                    limit_gb = plan.get("limit_bytes", 0) / (1024**3)
                    send_desktop_notification(
                        "NetFlow: Data Plan Warning",
                        f"You have consumed {pct:.1f}% ({used_gb:.2f} GB of {limit_gb:.2f} GB) of your data allowance.",
                        urgency="critical" if plan.get("exceeded") else "normal",
                    )
                    self._last_quota_notification = current_time

        # Prune old records every ~1 hour to prevent unbounded DB growth
        if self._storage_flush_counter % 3600 == 0 and self._storage_flush_counter > 0:
            try:
                pruned = self.storage.prune_old_records(self.config.history_retention_days)
            except Exception:
                pass

        return snapshot

    def get_latest_snapshot(self) -> Optional[RealtimeSnapshot]:
        with self._lock:
            return self._latest_snapshot

    def get_active_sockets(self) -> List[SocketInfo]:
        with self._lock:
            return list(self._active_sockets)

    def set_ping_latency(self, latency_ms: Optional[float]) -> None:
        self.latest_ping_ms = latency_ms

    def toggle_incognito(self, state: Optional[bool] = None) -> bool:
        """Toggles or sets the incognito/pause tracking state."""
        with self._lock:
            if state is not None:
                self.is_incognito = state
            else:
                self.is_incognito = not self.is_incognito
            return self.is_incognito

    def get_active_sockets_enriched(self) -> List[Dict[str, Any]]:
        """Returns active sockets enriched with reverse DNS hostnames and network scope."""
        with self._lock:
            sockets = list(self._active_sockets)

        enriched = []
        for s in sockets:
            remote_ip = s.remote_ip or ""
            hostname = self.dns_resolver.get_hostname(remote_ip) if remote_ip else remote_ip
            scope = self.dns_resolver.classify_ip(remote_ip) if remote_ip else "unknown"
            pname = s.process_name or ""
            pol = self.firewall.get_app_policy(pname) if pname else "allow"
            enriched.append({
                "protocol": s.protocol,
                "local": f"{s.local_ip}:{s.local_port}",
                "remote": f"{s.remote_ip}:{s.remote_port}",
                "remote_ip": remote_ip,
                "remote_port": s.remote_port,
                "remote_hostname": hostname,
                "scope": scope,
                "state": s.state,
                "pid": s.pid,
                "process_name": pname,
                "cmdline": s.cmdline,
                "policy": pol,
                "blocked": (pol == "block") or (pol == "lan_only" and scope == "wan"),
            })
        return enriched

