"""
SQLite storage engine for time-series network history and data plans.
"""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class NetflowStorage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = self._create_connection()
        self._init_db()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency without blocking reads/writes
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _get_connection(self) -> sqlite3.Connection:
        """Returns the persistent connection. All callers must use self._lock."""
        return self._conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS interface_history (
                    timestamp INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    rx_bytes INTEGER NOT NULL,
                    tx_bytes INTEGER NOT NULL,
                    rx_speed REAL NOT NULL,
                    tx_speed REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iface_time 
                ON interface_history (timestamp, interface);

                CREATE TABLE IF NOT EXISTS process_history (
                    timestamp INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    pid INTEGER,
                    rx_bytes INTEGER DEFAULT 0,
                    tx_bytes INTEGER DEFAULT 0,
                    active_connections INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_proc_time 
                ON process_history (timestamp, process_name);

                CREATE TABLE IF NOT EXISTS data_plan (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    period TEXT NOT NULL DEFAULT 'monthly',
                    limit_bytes INTEGER,
                    reset_day INTEGER DEFAULT 1,
                    warning_pct INTEGER DEFAULT 80
                );

                INSERT OR IGNORE INTO data_plan (id, period, limit_bytes, reset_day, warning_pct)
                VALUES (1, 'monthly', NULL, 1, 80);

                CREATE TABLE IF NOT EXISTS firewall_rules (
                    process_name TEXT PRIMARY KEY,
                    blocked INTEGER NOT NULL DEFAULT 1,
                    policy TEXT NOT NULL DEFAULT 'block',
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS firewall_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    process_name TEXT NOT NULL,
                    pid INTEGER,
                    remote_endpoint TEXT,
                    action TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fw_events_time
                ON firewall_events (timestamp DESC);

                CREATE TABLE IF NOT EXISTS seen_applications (
                    process_name TEXT PRIMARY KEY,
                    first_seen_timestamp REAL NOT NULL,
                    last_seen_timestamp REAL NOT NULL,
                    cmdline TEXT
                );
            """)

            # Column migration check for policy in firewall_rules
            cursor = conn.execute("PRAGMA table_info(firewall_rules);")
            columns = [row["name"] for row in cursor.fetchall()]
            if "policy" not in columns:
                conn.execute("ALTER TABLE firewall_rules ADD COLUMN policy TEXT NOT NULL DEFAULT 'block';")


    def record_interface_snapshot(
        self,
        timestamp: int,
        interface: str,
        rx_bytes: int,
        tx_bytes: int,
        rx_speed: float,
        tx_speed: float,
    ) -> None:
        with self._lock:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO interface_history (timestamp, interface, rx_bytes, tx_bytes, rx_speed, tx_speed)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (timestamp, interface, rx_bytes, tx_bytes, rx_speed, tx_speed),
            )
            conn.commit()

    def record_process_snapshot(
        self,
        timestamp: int,
        process_name: str,
        pid: Optional[int],
        rx_bytes: int,
        tx_bytes: int,
        active_connections: int,
    ) -> None:
        with self._lock:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO process_history (timestamp, process_name, pid, rx_bytes, tx_bytes, active_connections)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (timestamp, process_name, pid, rx_bytes, tx_bytes, active_connections),
            )
            conn.commit()

    def get_recent_speeds(self, seconds: int = 60, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves recent speed data points for live rolling charts (e.g. last 60 seconds).
        """
        cutoff = int(time.time()) - seconds
        with self._get_connection() as conn:
            if interface:
                cursor = conn.execute(
                    """
                    SELECT timestamp, interface, rx_speed, tx_speed, rx_bytes, tx_bytes
                    FROM interface_history
                    WHERE timestamp >= ? AND interface = ?
                    ORDER BY timestamp ASC
                    """,
                    (cutoff, interface),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT timestamp, SUM(rx_speed) as rx_speed, SUM(tx_speed) as tx_speed,
                           SUM(rx_bytes) as rx_bytes, SUM(tx_bytes) as tx_bytes
                    FROM interface_history
                    WHERE timestamp >= ? AND interface != 'lo'
                    GROUP BY timestamp
                    ORDER BY timestamp ASC
                    """,
                    (cutoff,),
                )
            return [dict(row) for row in cursor.fetchall()]

    def get_daily_usage(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Aggregates daily data consumption (like Evozi's daily usage view).
        """
        cutoff = int(time.time()) - (days * 86400)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT date(timestamp, 'unixepoch', 'localtime') as day,
                       SUM(rx_bytes) as total_rx,
                       SUM(tx_bytes) as total_tx,
                       (SUM(rx_bytes) + SUM(tx_bytes)) as total_bytes
                FROM interface_history
                WHERE timestamp >= ? AND interface != 'lo'
                GROUP BY day
                ORDER BY day ASC
                """,
                (cutoff,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_usage_summary(self) -> Dict[str, Any]:
        """
        Computes aggregate bandwidth metrics for NetworkFlow history:
        Today, Yesterday, Last 7 Days, Last 30 Days.
        """
        now = datetime.now()
        today_start = int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        yesterday_start = today_start - 86400
        week_start = int(time.time()) - (7 * 86400)
        month_start = int(time.time()) - (30 * 86400)

        with self._get_connection() as conn:
            def q(start_epoch, end_epoch=None):
                if end_epoch:
                    row = conn.execute(
                        "SELECT COALESCE(SUM(rx_bytes), 0) as rx, COALESCE(SUM(tx_bytes), 0) as tx FROM interface_history WHERE timestamp >= ? AND timestamp < ? AND interface != 'lo'",
                        (start_epoch, end_epoch),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COALESCE(SUM(rx_bytes), 0) as rx, COALESCE(SUM(tx_bytes), 0) as tx FROM interface_history WHERE timestamp >= ? AND interface != 'lo'",
                        (start_epoch,),
                    ).fetchone()
                return {"rx": row["rx"], "tx": row["tx"], "total": row["rx"] + row["tx"]}

            return {
                "today": q(today_start),
                "yesterday": q(yesterday_start, today_start),
                "last_7_days": q(week_start),
                "last_30_days": q(month_start),
            }

    def get_top_processes(self, period_seconds: int = 86400, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Returns top network-consuming applications for a given time window (default 24h).
        """
        cutoff = int(time.time()) - period_seconds
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT process_name,
                       SUM(rx_bytes) as rx_bytes,
                       SUM(tx_bytes) as tx_bytes,
                       (SUM(rx_bytes) + SUM(tx_bytes)) as total_bytes,
                       MAX(active_connections) as max_connections
                FROM process_history
                WHERE timestamp >= ?
                GROUP BY process_name
                ORDER BY total_bytes DESC
                LIMIT ?
                """,
                (cutoff, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def update_data_plan(
        self,
        period: str,
        limit_bytes: Optional[int],
        reset_day: int = 1,
        warning_pct: int = 80,
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE data_plan
                SET period = ?, limit_bytes = ?, reset_day = ?, warning_pct = ?
                WHERE id = 1
                """,
                (period, limit_bytes, reset_day, warning_pct),
            )

    @staticmethod
    def _calculate_billing_bounds(
        period: str = "monthly", reset_day: int = 1, now: Optional[datetime] = None
    ) -> Tuple[datetime, datetime]:
        """
        Calculates the start and end datetimes of the current billing cycle.
        Safely handles month-end, leap years, and daily boundaries.
        """
        if now is None:
            now = datetime.now()

        if period == "daily":
            start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = start_dt + timedelta(days=1)
            return start_dt, end_dt

        # Monthly billing period
        day = max(1, min(reset_day, 28))
        try:
            if now.day >= day:
                start_dt = now.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
                next_month = now.month + 1 if now.month < 12 else 1
                next_year = now.year if now.month < 12 else now.year + 1
                end_dt = now.replace(year=next_year, month=next_month, day=day, hour=0, minute=0, second=0, microsecond=0)
            else:
                prev_month = now.month - 1 if now.month > 1 else 12
                prev_year = now.year if now.month > 1 else now.year - 1
                start_dt = now.replace(year=prev_year, month=prev_month, day=day, hour=0, minute=0, second=0, microsecond=0)
                end_dt = now.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
        except ValueError:
            start_dt = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            next_month = now.month + 1 if now.month < 12 else 1
            next_year = now.year if now.month < 12 else now.year + 1
            end_dt = now.replace(year=next_year, month=next_month, day=1, hour=0, minute=0, second=0, microsecond=0)

        return start_dt, end_dt

    def get_data_plan_status(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            plan = conn.execute("SELECT * FROM data_plan WHERE id = 1").fetchone()
            if not plan:
                return {"configured": False}

            period = plan["period"]
            limit_bytes = plan["limit_bytes"]
            reset_day = plan["reset_day"] or 1
            warning_pct = plan["warning_pct"]

            if not limit_bytes:
                return {
                    "configured": False,
                    "period": period,
                    "limit_bytes": None,
                    "used_bytes": 0,
                    "warning_pct": warning_pct,
                }

            # Calculate start of current billing period
            start_dt, _ = self._calculate_billing_bounds(period=period, reset_day=reset_day)

            start_epoch = int(start_dt.timestamp())
            usage = conn.execute(
                """
                SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) as used
                FROM interface_history
                WHERE timestamp >= ? AND interface != 'lo'
                """,
                (start_epoch,),
            ).fetchone()["used"]

            percentage = (usage / limit_bytes) * 100 if limit_bytes > 0 else 0.0
            warning_triggered = percentage >= warning_pct
            exceeded = usage >= limit_bytes

            return {
                "configured": True,
                "period": period,
                "limit_bytes": limit_bytes,
                "used_bytes": usage,
                "remaining_bytes": max(0, limit_bytes - usage),
                "percentage": round(percentage, 2),
                "warning_pct": warning_pct,
                "warning_triggered": warning_triggered,
                "exceeded": exceeded,
                "period_start": start_dt.isoformat(),
            }

    def prune_old_records(self, retention_days: int = 90) -> int:
        cutoff = int(time.time()) - (retention_days * 86400)
        with self._get_connection() as conn:
            cur1 = conn.execute("DELETE FROM interface_history WHERE timestamp < ?", (cutoff,))
            cur2 = conn.execute("DELETE FROM process_history WHERE timestamp < ?", (cutoff,))
            return cur1.rowcount + cur2.rowcount

    # --- FIREWALL & APP BLOCKER PERSISTENCE ---

    def get_blocked_processes(self) -> set[str]:
        """Returns the set of process names currently marked as blocked."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT process_name FROM firewall_rules WHERE blocked = 1 AND policy != 'allow'"
            ).fetchall()
            return {row["process_name"] for row in rows}

    def get_firewall_policies(self) -> Dict[str, str]:
        """Returns mapping of process_name -> policy ('allow', 'lan_only', 'block')."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT process_name, policy, blocked FROM firewall_rules"
            ).fetchall()
            policies = {}
            for r in rows:
                pol = r["policy"]
                if not pol:
                    pol = "block" if r["blocked"] else "allow"
                policies[r["process_name"]] = pol
            return policies

    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Returns all configured firewall rules."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT process_name, blocked, policy, updated_at FROM firewall_rules ORDER BY process_name ASC"
            ).fetchall()
            rules = []
            for r in rows:
                pol = r["policy"] or ("block" if r["blocked"] else "allow")
                rules.append({
                    "process_name": r["process_name"],
                    "policy": pol,
                    "blocked": pol in ("block", "lan_only"),
                    "updated_at": r["updated_at"],
                })
            return rules

    def set_process_policy(self, process_name: str, policy: str) -> None:
        """Sets granular policy: 'allow', 'lan_only', or 'block'."""
        pol = policy.lower().strip()
        if pol not in ("allow", "lan_only", "block"):
            pol = "block"
        blocked = 1 if pol in ("block", "lan_only") else 0
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO firewall_rules (process_name, blocked, policy, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(process_name) DO UPDATE SET
                    blocked = excluded.blocked,
                    policy = excluded.policy,
                    updated_at = excluded.updated_at
                """,
                (process_name, blocked, pol, time.time()),
            )

    def set_process_blocked(self, process_name: str, blocked: bool) -> None:
        """Sets the firewall blocking state for a process name."""
        policy = "block" if blocked else "allow"
        self.set_process_policy(process_name, policy)

    def clear_firewall_rules(self) -> int:
        """Unblocks all applications."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM firewall_rules")
            return cur.rowcount

    def log_firewall_event(
        self,
        process_name: str,
        pid: Optional[int],
        remote_endpoint: str,
        action: str = "BLOCKED",
    ) -> None:
        """Logs a firewall security interception event."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO firewall_events (timestamp, process_name, pid, remote_endpoint, action)
                VALUES (?, ?, ?, ?, ?)
                """,
                (time.time(), process_name, pid, remote_endpoint, action),
            )

    def get_firewall_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent firewall security audit logs."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, process_name, pid, remote_endpoint, action
                FROM firewall_events
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "process_name": r["process_name"],
                    "pid": r["pid"],
                    "remote_endpoint": r["remote_endpoint"],
                    "action": r["action"],
                }
                for r in rows
            ]

    # --- FIRST-SEEN APPLICATION TRACKING ---

    def mark_or_check_first_seen(self, process_name: str, cmdline: str = "") -> bool:
        """
        Returns True if this is the FIRST time this process has been seen connecting.
        Returns False if previously known, updating its last_seen timestamp.
        """
        if not process_name or process_name.startswith("system/"):
            return False

        now = time.time()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT first_seen_timestamp FROM seen_applications WHERE process_name = ?",
                (process_name,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO seen_applications (process_name, first_seen_timestamp, last_seen_timestamp, cmdline)
                    VALUES (?, ?, ?, ?)
                    """,
                    (process_name, now, now, cmdline),
                )
                return True
            else:
                conn.execute(
                    "UPDATE seen_applications SET last_seen_timestamp = ?, cmdline = ? WHERE process_name = ?",
                    (now, cmdline, process_name),
                )
                return False

    def get_seen_applications(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Returns list of seen applications with first seen and last seen timestamps."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT process_name, first_seen_timestamp, last_seen_timestamp, cmdline
                FROM seen_applications
                ORDER BY first_seen_timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "process_name": r["process_name"],
                    "first_seen": r["first_seen_timestamp"],
                    "last_seen": r["last_seen_timestamp"],
                    "cmdline": r["cmdline"],
                }
                for r in rows
            ]

    # --- PREDICTIVE BUDGET & FORECASTING ---

    def get_budget_forecast(self) -> Dict[str, Any]:
        """
        Calculates burn rate, projected monthly usage, exhaustion date,
        and recommended safe daily pace based on current data plan.
        """
        plan = self.get_data_plan_status()
        now = datetime.now()

        reset_day = 1
        period = "monthly"
        with self._get_connection() as conn:
            plan_row = conn.execute("SELECT period, reset_day, limit_bytes FROM data_plan WHERE id = 1").fetchone()
            if plan_row:
                if plan_row["reset_day"]:
                    reset_day = plan_row["reset_day"]
                if plan_row["period"]:
                    period = plan_row["period"]

        start_dt, end_dt = self._calculate_billing_bounds(period=period, reset_day=reset_day, now=now)

        total_period_seconds = max(86400, (end_dt - start_dt).total_seconds())
        elapsed_seconds = max(60, (now - start_dt).total_seconds())
        remaining_seconds = max(60, (end_dt - now).total_seconds())

        total_days = total_period_seconds / 86400.0
        days_elapsed = max(0.1, elapsed_seconds / 86400.0)
        days_remaining = max(0.1, remaining_seconds / 86400.0)

        used_bytes = plan.get("used_bytes", 0)
        limit_bytes = plan.get("limit_bytes") or 0

        avg_daily_bytes = used_bytes / days_elapsed
        projected_total_bytes = avg_daily_bytes * total_days

        remaining_bytes = max(0, limit_bytes - used_bytes) if limit_bytes > 0 else 0
        recommended_daily_bytes = (remaining_bytes / days_remaining) if (limit_bytes > 0 and days_remaining > 0) else 0

        # Forecast exhaustion date
        exhaustion_date_str = None
        burn_status = "unconfigured"
        projected_pct = 0.0

        if limit_bytes > 0:
            projected_pct = round((projected_total_bytes / limit_bytes) * 100, 1)
            if used_bytes >= limit_bytes:
                burn_status = "exceeded"
                exhaustion_date_str = "Already Exceeded"
            elif avg_daily_bytes > 0:
                seconds_to_exhaust = (remaining_bytes / (avg_daily_bytes / 86400.0))
                exhaust_dt = now.timestamp() + seconds_to_exhaust
                exhaustion_date_str = datetime.fromtimestamp(exhaust_dt).strftime("%b %d, %Y")
                if projected_pct < 85:
                    burn_status = "healthy"
                elif projected_pct <= 100:
                    burn_status = "warning"
                else:
                    burn_status = "critical"
            else:
                burn_status = "healthy"
                exhaustion_date_str = "Within limits"

        return {
            "configured": bool(limit_bytes > 0),
            "limit_bytes": limit_bytes,
            "used_bytes": used_bytes,
            "remaining_bytes": remaining_bytes,
            "days_elapsed": round(days_elapsed, 1),
            "days_remaining": round(days_remaining, 1),
            "avg_daily_bytes": int(avg_daily_bytes),
            "recommended_daily_budget_bytes": int(recommended_daily_bytes),
            "projected_total_bytes": int(projected_total_bytes),
            "projected_percentage": projected_pct,
            "burn_status": burn_status,
            "estimated_exhaustion_date": exhaustion_date_str,
            "period_start": start_dt.isoformat(),
            "period_end": end_dt.isoformat(),
        }

    # --- CSV & REPORT EXPORT ---

    def export_daily_csv(self) -> str:
        """Exports daily usage history as CSV format."""
        daily_stats = self.get_daily_usage(days=90)
        lines = ["Date,Download_Bytes,Upload_Bytes,Total_Bytes,Total_Human"]
        for row in daily_stats:
            d_bytes = row.get("total_rx", 0)
            u_bytes = row.get("total_tx", 0)
            tot = row.get("total_bytes", 0)
            tot_h = f"{tot / (1024*1024):.2f} MB" if tot < 1024**3 else f"{tot / (1024**3):.2f} GB"
            lines.append(f"{row.get('day', 'unknown')},{d_bytes},{u_bytes},{tot},{tot_h}")
        return "\n".join(lines)


    def export_processes_csv(self) -> str:
        """Exports cumulative top process usage as CSV format."""
        top_apps = self.get_top_processes(period_seconds=30 * 86400, limit=50)
        lines = ["Process_Name,Download_Bytes,Upload_Bytes,Total_Bytes,Total_Human"]
        for row in top_apps:
            d_bytes = row.get("rx_bytes", 0)
            u_bytes = row.get("tx_bytes", 0)
            tot = row.get("total_bytes", 0)
            tot_h = f"{tot / (1024*1024):.2f} MB" if tot < 1024**3 else f"{tot / (1024**3):.2f} GB"
            lines.append(f"{row.get('process_name', 'unknown')},{d_bytes},{u_bytes},{tot},{tot_h}")
        return "\n".join(lines)



