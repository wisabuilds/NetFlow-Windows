"""
Configuration management for NetFlow Linux backend.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import List, Optional


@dataclass
class NetflowConfig:
    poll_interval: float = 1.0
    db_path: str = field(
        default_factory=lambda: str(
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "netflow_linux"
            / "netflow.db"
        )
    )
    api_host: str = "127.0.0.1"
    api_port: int = 9095
    history_retention_days: int = 90
    excluded_interfaces: List[str] = field(default_factory=lambda: ["lo"])
    default_ping_target: str = "1.1.1.1"
    # Data Plan Settings
    data_plan_bytes_limit: Optional[int] = None  # None = no limit, e.g. 50 * 1024**3
    data_plan_period: str = "monthly"  # "daily", "monthly"
    data_plan_reset_day: int = 1  # day of month to reset (1-28)
    data_plan_warning_pct: int = 80  # alert at 80%

    def ensure_directories(self) -> None:
        try:
            db_file = Path(self.db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            # Fallback to local workspace data directory
            fallback_dir = Path.cwd() / "data"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(fallback_dir / "netflow.db")

    @classmethod
    def load_from_file(cls, path: str) -> "NetflowConfig":
        if not os.path.exists(path):
            cfg = cls()
            cfg.save_to_file(path)
            return cfg
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    def save_to_file(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=2)
