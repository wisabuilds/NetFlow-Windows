"""
Asynchronous Reverse DNS resolver and IP endpoint classification.
Resolves remote IP addresses into human-readable hostnames in the background
and categorizes network scopes (Loopback, LAN, WAN).
Zero external dependencies.
"""

from collections import OrderedDict
import concurrent.futures
import ipaddress
import queue
import socket
import threading
import time
from typing import Dict, Optional, Tuple


class DNSResolver:
    """
    Background worker that resolves IP addresses to hostnames asynchronously
    with LRU caching to prevent any blocking in the telemetry loop.
    """

    def __init__(self, max_cache_size: int = 2000, cache_ttl_seconds: int = 3600):
        self.max_cache_size = max_cache_size
        self.cache_ttl = cache_ttl_seconds
        # key: ip_str -> (hostname, timestamp)
        self._cache: OrderedDict[str, Tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue(maxsize=1000)
        self._in_flight = set()

        self._stop_event = threading.Event()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="NetFlowDNSExec"
        )
        self._worker_thread = threading.Thread(
            target=self._resolve_worker, daemon=True, name="NetFlowDNSWorker"
        )
        self._worker_thread.start()

    def _resolve_worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            hostname = ip
            try:
                # Fast reverse DNS lookup with per-call timeout
                # Uses ThreadPoolExecutor future timeout to avoid mutating global socket.setdefaulttimeout()
                future = self._executor.submit(socket.getnameinfo, (ip, 0), socket.NI_NAMEREQD)
                host_info = future.result(timeout=1.2)
                if host_info and host_info[0]:
                    hostname = host_info[0]
            except Exception:
                # Fallback to the raw IP if reverse DNS fails or times out
                hostname = ip
            finally:
                with self._lock:
                    self._cache[ip] = (hostname, time.time())
                    if len(self._cache) > self.max_cache_size:
                        self._cache.popitem(last=False)
                    self._in_flight.discard(ip)
                self._queue.task_done()

    def get_hostname(self, ip: str) -> str:
        """
        Returns cached hostname immediately. If not cached, enqueues background lookup
        and returns the raw IP for this cycle.
        """
        if not ip or ip in ("*", "0.0.0.0", "::", "[::]"):
            return ip

        now = time.time()
        with self._lock:
            if ip in self._cache:
                hostname, ts = self._cache[ip]
                if now - ts < self.cache_ttl:
                    # Move to end (MRU)
                    self._cache.move_to_end(ip)
                    return hostname

            # Enqueue if not already queued
            if ip not in self._in_flight:
                try:
                    self._in_flight.add(ip)
                    self._queue.put_nowait(ip)
                except queue.Full:
                    pass

        return ip

    @staticmethod
    def classify_ip(ip_str: str) -> str:
        """
        Classifies an IP address into:
        - 'loopback': 127.0.0.0/8, ::1
        - 'lan': RFC1918, link-local, multicast, ULA
        - 'wan': Public Internet
        - 'unspecified': 0.0.0.0, ::, *
        """
        if not ip_str or ip_str in ("*", "0.0.0.0", "::", "[::]"):
            return "unspecified"

        # Strip brackets if IPv6
        clean_ip = ip_str.strip("[]")
        try:
            addr = ipaddress.ip_address(clean_ip)
            if addr.is_loopback:
                return "loopback"
            if addr.is_private or addr.is_link_local or addr.is_multicast:
                return "lan"
            if addr.is_unspecified:
                return "unspecified"
            return "wan"
        except ValueError:
            return "unknown"

    @classmethod
    def is_lan_or_local(cls, ip_str: str) -> bool:
        """Returns True if the IP is LAN, loopback, or private."""
        scope = cls.classify_ip(ip_str)
        return scope in ("loopback", "lan", "unspecified")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


# Shared singleton instance
_dns_resolver_instance: Optional[DNSResolver] = None


def get_dns_resolver() -> DNSResolver:
    global _dns_resolver_instance
    if _dns_resolver_instance is None:
        _dns_resolver_instance = DNSResolver()
    return _dns_resolver_instance
