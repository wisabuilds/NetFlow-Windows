"""
Linux /proc filesystem parser for network interfaces, sockets, and processes.
"""

from dataclasses import dataclass
import glob
import os
import socket
import struct
from typing import Dict, List, Optional, Tuple


TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass
class InterfaceStats:
    name: str
    rx_bytes: int
    rx_packets: int
    rx_errs: int
    rx_drop: int
    tx_bytes: int
    tx_packets: int
    tx_errs: int
    tx_drop: int


@dataclass
class SocketInfo:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int
    uid: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    cmdline: Optional[str] = None


def decode_ipv4_hex(hex_str: str) -> str:
    """
    Decodes little-endian 8-hex-character IPv4 string to dotted-decimal notation.
    Example: '0100007F' -> '127.0.0.1'
    """
    try:
        packed_ip = struct.pack("<I", int(hex_str, 16))
        return socket.inet_ntop(socket.AF_INET, packed_ip)
    except Exception:
        return "0.0.0.0"


def decode_ipv6_hex(hex_str: str) -> str:
    """
    Decodes 32-hex-character IPv6 string from /proc/net/tcp6 to standard IPv6 notation.
    Linux stores IPv6 addresses in /proc/net as four 32-bit words in host endian order.
    """
    try:
        # Split into four 8-character (32-bit) words
        words = [hex_str[i : i + 8] for i in range(0, 32, 8)]
        packed = b"".join(struct.pack("<I", int(w, 16)) for w in words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "::"


def parse_ip_port(ip_port_hex: str, is_ipv6: bool = False) -> Tuple[str, int]:
    """
    Splits hex 'IP:PORT' string into human-readable (ip_string, port_integer).
    """
    if ":" not in ip_port_hex:
        return ("0.0.0.0" if not is_ipv6 else "::", 0)
    ip_part, port_part = ip_port_hex.split(":")
    port = int(port_part, 16)
    if is_ipv6:
        ip = decode_ipv6_hex(ip_part)
    else:
        ip = decode_ipv4_hex(ip_part)
    return (ip, port)


class ProcReader:
    def __init__(self):
        self._inode_to_proc_cache: Dict[int, Tuple[int, str, str]] = {}

    def read_interface_stats(self, proc_net_dev: str = "/proc/net/dev") -> Dict[str, InterfaceStats]:
        """
        Reads and parses /proc/net/dev for all network interfaces.
        """
        stats: Dict[str, InterfaceStats] = {}
        if not os.path.exists(proc_net_dev):
            return stats

        try:
            with open(proc_net_dev, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, PermissionError):
            return stats

        for line in lines[2:]:  # Skip the two header lines
            line = line.strip()
            if not line or ":" not in line:
                continue
            iface_name, rest = line.split(":", 1)
            iface_name = iface_name.strip()
            parts = rest.split()
            if len(parts) >= 16:
                try:
                    stats[iface_name] = InterfaceStats(
                        name=iface_name,
                        rx_bytes=int(parts[0]),
                        rx_packets=int(parts[1]),
                        rx_errs=int(parts[2]),
                        rx_drop=int(parts[3]),
                        tx_bytes=int(parts[8]),
                        tx_packets=int(parts[9]),
                        tx_errs=int(parts[10]),
                        tx_drop=int(parts[11]),
                    )
                except ValueError:
                    continue

        return stats

    def build_inode_process_map(self) -> Dict[int, Tuple[int, str, str]]:
        """
        Scans /proc/[pid]/fd to map socket inodes to (pid, process_name, cmdline).
        Handles processes exiting during scan and permission restrictions gracefully.
        """
        inode_map: Dict[int, Tuple[int, str, str]] = {}
        proc_dirs = glob.glob("/proc/[0-9]*")

        for proc_dir in proc_dirs:
            try:
                pid = int(os.path.basename(proc_dir))
            except ValueError:
                continue

            comm = "unknown"
            cmdline = ""
            try:
                with open(os.path.join(proc_dir, "comm"), "r", encoding="utf-8", errors="ignore") as f:
                    comm = f.read().strip()
                with open(os.path.join(proc_dir, "cmdline"), "r", encoding="utf-8", errors="ignore") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass

            fd_dir = os.path.join(proc_dir, "fd")
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(fd_path)
                        if target.startswith("socket:[") and target.endswith("]"):
                            inode_str = target[8:-1]
                            inode = int(inode_str)
                            inode_map[inode] = (pid, comm, cmdline or comm)
                    except (FileNotFoundError, PermissionError, ValueError, OSError):
                        continue
            except (FileNotFoundError, PermissionError, NotADirectoryError, OSError):
                continue

        self._inode_to_proc_cache = inode_map
        return inode_map

    def read_sockets(
        self,
        include_udp: bool = True,
        resolve_processes: bool = True,
    ) -> List[SocketInfo]:
        """
        Parses /proc/net/tcp, tcp6, udp, udp6 and correlates with process inodes.
        """
        if resolve_processes:
            inode_map = self.build_inode_process_map()
        else:
            inode_map = self._inode_to_proc_cache

        sockets: List[SocketInfo] = []
        files_to_check = [
            ("/proc/net/tcp", "tcp", False),
            ("/proc/net/tcp6", "tcp6", True),
        ]
        if include_udp:
            files_to_check.extend([
                ("/proc/net/udp", "udp", False),
                ("/proc/net/udp6", "udp6", True),
            ])

        for path, proto, is_ipv6 in files_to_check:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except (IOError, PermissionError):
                continue

            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                try:
                    local_ip, local_port = parse_ip_port(parts[1], is_ipv6)
                    remote_ip, remote_port = parse_ip_port(parts[2], is_ipv6)
                    state_hex = parts[3]
                    state = TCP_STATES.get(state_hex, state_hex) if "tcp" in proto else "STATELESS"
                    uid = int(parts[7])
                    inode = int(parts[9])

                    proc_info = inode_map.get(inode)
                    pid, proc_name, cmdline = proc_info if proc_info else (None, None, None)

                    sockets.append(
                        SocketInfo(
                            protocol=proto,
                            local_ip=local_ip,
                            local_port=local_port,
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            state=state,
                            inode=inode,
                            uid=uid,
                            pid=pid,
                            process_name=proc_name,
                            cmdline=cmdline,
                        )
                    )
                except (ValueError, IndexError):
                    continue

        return sockets
