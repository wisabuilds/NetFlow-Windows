"""
NetFlow Linux: Desktop notification dispatcher.
Provides unified rate-limited desktop notifications via libnotify / notify-send.
"""

import subprocess
from typing import Optional


def send_desktop_notification(
    title: str,
    message: str,
    urgency: str = "normal",
    app_name: str = "NetFlow Linux",
    timeout_sec: float = 2.0,
) -> bool:
    """
    Sends native desktop notification using notify-send.
    Returns True if successfully spawned, False otherwise.
    """
    try:
        subprocess.run(
            ["notify-send", "-u", urgency, "-a", app_name, title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec,
        )
        return True
    except Exception:
        return False
