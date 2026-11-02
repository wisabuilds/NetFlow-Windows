"""
NetFlow Linux: Application Blocker & Firewall Engine.
Provides process-level network isolation, socket severing, and security event auditing.
"""

import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set

from .dns_resolver import DNSResolver
from .notifications import send_desktop_notification
from .proc_reader import SocketInfo
from .storage import NetflowStorage


class FirewallEngine:
    def __init__(self, storage: NetflowStorage):
        self.storage = storage
        self.is_enabled = True
        self._lock = threading.Lock()
        self._policies: Dict[str, str] = {}
        self._last_notification_time: Dict[str, float] = {}
        self._total_blocked_connections: int = 0
        self._load_rules()

    def _load_rules(self) -> None:
        """Loads configured firewall policies from SQLite."""
        with self._lock:
            self._policies = self.storage.get_firewall_policies()

    def get_app_policy(self, process_name: str) -> str:
        """Returns the policy for a process: 'allow', 'lan_only', or 'block'."""
        if not self.is_enabled:
            return "allow"
        with self._lock:
            clean_name = os.path.basename(process_name.strip()).lower()
            for p, pol in self._policies.items():
                if p.lower() == clean_name:
                    return pol
            return "allow"

    def is_app_blocked(self, process_name: str) -> bool:
        """Checks if an application is blocked or restricted by firewall policy."""
        pol = self.get_app_policy(process_name)
        return pol in ("block", "lan_only")

    def set_app_policy(self, process_name: str, policy: str) -> str:
        """Sets policy for an application ('allow', 'lan_only', 'block')."""
        clean_name = os.path.basename(process_name.strip())
        pol = policy.lower().strip()
        if pol not in ("allow", "lan_only", "block"):
            pol = "block"
        with self._lock:
            self._policies[clean_name] = pol
        self.storage.set_process_policy(clean_name, pol)

        if pol == "block":
            self._notify_user("Firewall: Application Blocked", f"{clean_name} is completely blocked from network access.")
        elif pol == "lan_only":
            self._notify_user("Firewall: LAN Only", f"{clean_name} is restricted to local network only (WAN blocked).")
        else:
            self._notify_user("Firewall: Application Allowed", f"{clean_name} has unrestricted network access.")
        return pol

    def block_app(self, process_name: str) -> None:
        self.set_app_policy(process_name, "block")

    def unblock_app(self, process_name: str) -> None:
        self.set_app_policy(process_name, "allow")

    def set_app_blocked(self, process_name: str, blocked: bool) -> None:
        self.set_app_policy(process_name, "block" if blocked else "allow")

    def toggle_firewall(self, enabled: Optional[bool] = None) -> bool:
        """Toggles or sets the master firewall protection switch."""
        with self._lock:
            if enabled is not None:
                self.is_enabled = enabled
            else:
                self.is_enabled = not self.is_enabled
            state = self.is_enabled
        msg = "Active & Enforcing" if state else "Disabled"
        self._notify_user("NetFlow Firewall", f"Protection status is now {msg}.")
        return state

    def clear_all_blocks(self) -> int:
        """Unblocks all applications."""
        with self._lock:
            count = len(self._policies)
            self._policies.clear()
        self.storage.clear_firewall_rules()
        self._notify_user("Firewall: Rules Reset", "All application firewall rules cleared.")
        return count

    def enforce(self, active_sockets: List[SocketInfo], active_processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enforces firewall policy against active sockets and checks for first-seen apps:
        1. Identifies first-seen applications and triggers notifications.
        2. Drops sockets for completely blocked processes.
        3. Drops public WAN sockets for LAN-only restricted processes.
        4. Records audit log events and sends rate-limited alerts.
        """
        now = time.time()
        interceptions = []

        # 1. First-Seen Detection on active processes
        for p in active_processes:
            pname = (p.get("name") or "").strip()
            if pname and not pname.startswith("system/"):
                clean_name = os.path.basename(pname)
                is_first_seen = self.storage.mark_or_check_first_seen(clean_name, p.get("cmdline", ""))
                if is_first_seen:
                    self.storage.log_firewall_event(clean_name, p.get("pid"), "first-connection", "FIRST_SEEN")
                    self._notify_user(
                        "NetFlow: New Network Application",
                        f"Discovered '{clean_name}' (PID: {p.get('pid')}) connecting for the first time.",
                        urgency="normal",
                    )

        if not self.is_enabled:
            return []

        with self._lock:
            policies = dict(self._policies)

        if not policies:
            return []

        for s in active_sockets:
            pname = (s.process_name or "").strip()
            if not pname or pname.startswith("system/"):
                continue

            clean_name = os.path.basename(pname)
            pol = "allow"
            for k, v in policies.items():
                if k.lower() == clean_name.lower():
                    pol = v
                    break

            if pol == "allow":
                continue

            remote_ip = s.remote_ip or ""
            remote_str = f"{remote_ip}:{s.remote_port}" if remote_ip else "unknown"
            should_block = False
            action_name = "BLOCKED"

            if pol == "block":
                should_block = True
                action_name = "BLOCKED"
            elif pol == "lan_only":
                # Only block if connecting to public WAN
                if remote_ip and not DNSResolver.is_lan_or_local(remote_ip):
                    should_block = True
                    action_name = "BLOCKED_WAN"

            if should_block:
                self._sever_connection(s)
                self._total_blocked_connections += 1

                event = {
                    "process_name": clean_name,
                    "pid": s.pid,
                    "remote_endpoint": remote_str,
                    "timestamp": now,
                    "action": action_name,
                }
                interceptions.append(event)
                self.storage.log_firewall_event(clean_name, s.pid, remote_str, action_name)

                # Rate-limited desktop alert (max 1 per 10s per process)
                last_time = self._last_notification_time.get(clean_name, 0)
                if now - last_time > 10:
                    self._last_notification_time[clean_name] = now
                    reason = "WAN connection restricted (LAN Only)" if action_name == "BLOCKED_WAN" else "Firewall Blocked"
                    self._notify_user(
                        f"Firewall: {reason}",
                        f"Severed {clean_name} stream to {remote_str}",
                        urgency="critical",
                    )

        return interceptions

    def _sever_connection(self, s: SocketInfo) -> None:
        """Attempts to sever unauthorized network socket."""
        if s.remote_ip and s.remote_port:
            try:
                subprocess.run(
                    ["ss", "-K", "dst", s.remote_ip, "dport", str(s.remote_port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.5,
                )
            except Exception:
                pass

    def _notify_user(self, title: str, message: str, urgency: str = "normal") -> None:
        """Sends native desktop notification."""
        send_desktop_notification(title, message, urgency=urgency, app_name="NetFlow")

    def get_status(self) -> Dict[str, Any]:
        """Returns firewall operational status, rules, and statistics."""
        with self._lock:
            policies_copy = dict(self._policies)
            enabled = self.is_enabled

        rules = self.storage.get_firewall_rules()
        blocked_list = [r["process_name"] for r in rules if r.get("policy") in ("block", "lan_only")]
        events = self.storage.get_firewall_events(limit=30)
        return {
            "enabled": enabled,
            "blocked_count": len(blocked_list),
            "blocked_apps": blocked_list,
            "policies": policies_copy,
            "rules": rules,
            "total_blocked_connections": self._total_blocked_connections,
            "recent_events": events,
        }

