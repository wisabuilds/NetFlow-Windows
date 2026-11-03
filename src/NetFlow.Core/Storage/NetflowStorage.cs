using System.Globalization;
using System.Text;
using NetFlow.Core.Models;

namespace NetFlow.Core.Storage;

public class NetflowStorage : IDisposable
{
    private readonly string _dbPath;
    private IntPtr _db = IntPtr.Zero;
    private readonly object _lock = new();

    public NetflowStorage(string dbPath)
    {
        _dbPath = dbPath;
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        Open();
        InitDb();
    }

    private void Open()
    {
        int flags = WinSqliteInterop.SQLITE_OPEN_READWRITE | WinSqliteInterop.SQLITE_OPEN_CREATE;
        int rc = WinSqliteInterop.Open(WinSqliteInterop.Utf8Bytes(_dbPath), out _db, flags, IntPtr.Zero);
        if (rc != WinSqliteInterop.SQLITE_OK)
        {
            string err = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ErrMsg(_db));
            throw new InvalidOperationException($"Failed to open SQLite database at '{_dbPath}': {err} (code {rc})");
        }

        ExecuteNonQuery("PRAGMA busy_timeout = 5000;");
        ExecuteNonQuery("PRAGMA journal_mode=WAL;");
        ExecuteNonQuery("PRAGMA synchronous=NORMAL;");
        ExecuteNonQuery("PRAGMA auto_vacuum=INCREMENTAL;");
    }

    public void ExecuteNonQuery(string sql)
    {
        lock (_lock)
        {
            int rc = WinSqliteInterop.Exec(_db, WinSqliteInterop.Utf8Bytes(sql), IntPtr.Zero, IntPtr.Zero, out IntPtr errPtr);
            if (rc != WinSqliteInterop.SQLITE_OK)
            {
                string msg = WinSqliteInterop.PtrToStringUtf8(errPtr);
                throw new InvalidOperationException($"SQLite execution error: {msg} for SQL: {sql}");
            }
        }
    }

    private void InitDb()
    {
        ExecuteNonQuery("""
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

            CREATE TABLE IF NOT EXISTS interface_history_hourly (
                timestamp INTEGER NOT NULL,
                interface TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL,
                rx_speed_avg REAL NOT NULL DEFAULT 0,
                tx_speed_avg REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (timestamp, interface)
            );

            CREATE INDEX IF NOT EXISTS idx_iface_hourly_time 
            ON interface_history_hourly (timestamp, interface);

            CREATE TABLE IF NOT EXISTS process_history_daily (
                day TEXT NOT NULL,
                process_name TEXT NOT NULL,
                total_rx INTEGER NOT NULL,
                total_tx INTEGER NOT NULL,
                max_connections INTEGER DEFAULT 0,
                PRIMARY KEY (day, process_name)
            );

            CREATE INDEX IF NOT EXISTS idx_proc_daily_day 
            ON process_history_daily (day, process_name);

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

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """);
    }

    public void RecordInterfaceSnapshot(long timestamp, string iface, long rxBytes, long txBytes, double rxSpeed, double txSpeed)
    {
        lock (_lock)
        {
            string sql = "INSERT INTO interface_history (timestamp, interface, rx_bytes, tx_bytes, rx_speed, tx_speed) VALUES (?, ?, ?, ?, ?, ?);";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, timestamp);
                    WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(iface), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindInt64(stmt, 3, rxBytes);
                    WinSqliteInterop.BindInt64(stmt, 4, txBytes);
                    WinSqliteInterop.BindDouble(stmt, 5, rxSpeed);
                    WinSqliteInterop.BindDouble(stmt, 6, txSpeed);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public void RecordProcessSnapshot(long timestamp, string processName, int pid, long rxBytes, long txBytes, int activeConnections)
    {
        lock (_lock)
        {
            string sql = "INSERT INTO process_history (timestamp, process_name, pid, rx_bytes, tx_bytes, active_connections) VALUES (?, ?, ?, ?, ?, ?);";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, timestamp);
                    WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindInt(stmt, 3, pid);
                    WinSqliteInterop.BindInt64(stmt, 4, rxBytes);
                    WinSqliteInterop.BindInt64(stmt, 5, txBytes);
                    WinSqliteInterop.BindInt(stmt, 6, activeConnections);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public List<Dictionary<string, object>> GetRecentSpeeds(int seconds = 60, string? iface = null)
    {
        lock (_lock)
        {
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - seconds;
            string sql = string.IsNullOrEmpty(iface)
                ? "SELECT timestamp, SUM(rx_speed) as rx_speed, SUM(tx_speed) as tx_speed FROM interface_history WHERE timestamp >= ? GROUP BY timestamp ORDER BY timestamp ASC;"
                : "SELECT timestamp, rx_speed, tx_speed FROM interface_history WHERE timestamp >= ? AND interface = ? ORDER BY timestamp ASC;";

            var list = new List<Dictionary<string, object>>();
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, cutoff);
                    if (!string.IsNullOrEmpty(iface))
                    {
                        WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(iface), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    }

                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        list.Add(new Dictionary<string, object>
                        {
                            ["timestamp"] = WinSqliteInterop.ColumnInt64(stmt, 0),
                            ["rx_speed"] = WinSqliteInterop.ColumnDouble(stmt, 1),
                            ["tx_speed"] = WinSqliteInterop.ColumnDouble(stmt, 2)
                        });
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public List<Dictionary<string, object>> GetDailyUsage(int days = 30)
    {
        lock (_lock)
        {
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - (days * 86400L);
            string sql = """
                SELECT 
                    day,
                    SUM(rx_delta) as total_rx,
                    SUM(tx_delta) as total_tx
                FROM (
                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        MAX(rx_bytes) - MIN(rx_bytes) as rx_delta,
                        MAX(tx_bytes) - MIN(tx_bytes) as tx_delta
                    FROM interface_history
                    WHERE timestamp >= ?
                    GROUP BY day, interface

                    UNION ALL

                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        SUM(rx_bytes) as rx_delta,
                        SUM(tx_bytes) as tx_delta
                    FROM interface_history_hourly
                    WHERE timestamp >= ? AND timestamp < (SELECT COALESCE(MIN(timestamp), 9999999999) FROM interface_history)
                    GROUP BY day, interface
                )
                GROUP BY day
                ORDER BY day ASC;
            """;

            var list = new List<Dictionary<string, object>>();
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, cutoff);
                    WinSqliteInterop.BindInt64(stmt, 2, cutoff);
                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        string day = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                        long rx = WinSqliteInterop.ColumnInt64(stmt, 1);
                        long tx = WinSqliteInterop.ColumnInt64(stmt, 2);
                        list.Add(new Dictionary<string, object>
                        {
                            ["date"] = day,
                            ["rx_bytes"] = rx,
                            ["tx_bytes"] = tx,
                            ["total_bytes"] = rx + tx
                        });
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public Dictionary<string, object> GetUsageSummary()
    {
        lock (_lock)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long dayStart = new DateTimeOffset(DateTime.UtcNow.Date, TimeSpan.Zero).ToUnixTimeSeconds();

            long todayRx = 0, todayTx = 0;
            string sqlToday = """
                SELECT 
                    COALESCE(SUM(rx_delta), 0),
                    COALESCE(SUM(tx_delta), 0)
                FROM (
                    SELECT 
                        interface,
                        MAX(rx_bytes) - MIN(rx_bytes) as rx_delta,
                        MAX(tx_bytes) - MIN(tx_bytes) as tx_delta
                    FROM interface_history
                    WHERE timestamp >= ?
                    GROUP BY interface
                );
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sqlToday), -1, out IntPtr s1, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(s1, 1, dayStart);
                    if (WinSqliteInterop.Step(s1) == WinSqliteInterop.SQLITE_ROW)
                    {
                        todayRx = WinSqliteInterop.ColumnInt64(s1, 0);
                        todayTx = WinSqliteInterop.ColumnInt64(s1, 1);
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(s1);
                }
            }

            long allRx = 0, allTx = 0;
            string sqlAll = """
                SELECT 
                    COALESCE(SUM(rx_delta), 0),
                    COALESCE(SUM(tx_delta), 0)
                FROM (
                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        MAX(rx_bytes) - MIN(rx_bytes) as rx_delta,
                        MAX(tx_bytes) - MIN(tx_bytes) as tx_delta
                    FROM interface_history
                    GROUP BY day, interface

                    UNION ALL

                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        SUM(rx_bytes) as rx_delta,
                        SUM(tx_bytes) as tx_delta
                    FROM interface_history_hourly
                    WHERE timestamp < (SELECT COALESCE(MIN(timestamp), 9999999999) FROM interface_history)
                    GROUP BY day, interface
                );
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sqlAll), -1, out IntPtr s2, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    if (WinSqliteInterop.Step(s2) == WinSqliteInterop.SQLITE_ROW)
                    {
                        allRx = WinSqliteInterop.ColumnInt64(s2, 0);
                        allTx = WinSqliteInterop.ColumnInt64(s2, 1);
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(s2);
                }
            }

            return new Dictionary<string, object>
            {
                ["today_rx_bytes"] = todayRx,
                ["today_tx_bytes"] = todayTx,
                ["today_total_bytes"] = todayRx + todayTx,
                ["all_time_rx_bytes"] = allRx,
                ["all_time_tx_bytes"] = allTx,
                ["all_time_total_bytes"] = allRx + allTx,
            };
        }
    }

    public List<Dictionary<string, object>> GetTopProcesses(int periodSeconds = 86400, int limit = 15)
    {
        lock (_lock)
        {
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - periodSeconds;
            string sql = """
                SELECT 
                    process_name,
                    SUM(rx_bytes) as total_rx,
                    SUM(tx_bytes) as total_tx,
                    MAX(active_connections) as max_conn
                FROM process_history
                WHERE timestamp >= ?
                GROUP BY process_name
                ORDER BY (total_rx + total_tx) DESC
                LIMIT ?;
            """;

            var list = new List<Dictionary<string, object>>();
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, cutoff);
                    WinSqliteInterop.BindInt(stmt, 2, limit);
                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                        long rx = WinSqliteInterop.ColumnInt64(stmt, 1);
                        long tx = WinSqliteInterop.ColumnInt64(stmt, 2);
                        int maxConn = WinSqliteInterop.ColumnInt(stmt, 3);
                        list.Add(new Dictionary<string, object>
                        {
                            ["process_name"] = name,
                            ["rx_bytes"] = rx,
                            ["tx_bytes"] = tx,
                            ["total_bytes"] = rx + tx,
                            ["max_connections"] = maxConn,
                        });
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public DataPlanStatus GetDataPlanStatus()
    {
        lock (_lock)
        {
            string period = "monthly";
            long? limitBytes = null;
            int resetDay = 1;
            int warningPct = 80;

            string sql = "SELECT period, limit_bytes, reset_day, warning_pct FROM data_plan WHERE id = 1;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        period = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                        if (WinSqliteInterop.ColumnType(stmt, 1) != 5) // SQLITE_NULL
                        {
                            limitBytes = WinSqliteInterop.ColumnInt64(stmt, 1);
                        }
                        resetDay = WinSqliteInterop.ColumnInt(stmt, 2);
                        warningPct = WinSqliteInterop.ColumnInt(stmt, 3);
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }

            var now = DateTime.UtcNow;
            DateTime periodStart;
            DateTime periodEnd;

            if (period == "daily")
            {
                periodStart = new DateTime(now.Year, now.Month, now.Day, 0, 0, 0, DateTimeKind.Utc);
                periodEnd = periodStart.AddDays(1);
            }
            else
            {
                int rDay = Math.Min(resetDay, DateTime.DaysInMonth(now.Year, now.Month));
                periodStart = new DateTime(now.Year, now.Month, rDay, 0, 0, 0, DateTimeKind.Utc);
                if (now < periodStart)
                {
                    var prevMonth = now.AddMonths(-1);
                    int prevRDay = Math.Min(resetDay, DateTime.DaysInMonth(prevMonth.Year, prevMonth.Month));
                    periodStart = new DateTime(prevMonth.Year, prevMonth.Month, prevRDay, 0, 0, 0, DateTimeKind.Utc);
                    periodEnd = new DateTime(now.Year, now.Month, rDay, 0, 0, 0, DateTimeKind.Utc);
                }
                else
                {
                    var nextMonth = now.AddMonths(1);
                    int nextRDay = Math.Min(resetDay, DateTime.DaysInMonth(nextMonth.Year, nextMonth.Month));
                    periodEnd = new DateTime(nextMonth.Year, nextMonth.Month, nextRDay, 0, 0, 0, DateTimeKind.Utc);
                }
            }

            long startUnix = new DateTimeOffset(periodStart).ToUnixTimeSeconds();
            long usageBytes = 0;
            string sqlUsage = """
                SELECT 
                    COALESCE(SUM(rx_delta + tx_delta), 0)
                FROM (
                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        CASE WHEN COUNT(*) > 1 THEN MAX(rx_bytes) - MIN(rx_bytes) ELSE MAX(rx_bytes) END as rx_delta,
                        CASE WHEN COUNT(*) > 1 THEN MAX(tx_bytes) - MIN(tx_bytes) ELSE MAX(tx_bytes) END as tx_delta
                    FROM interface_history
                    WHERE timestamp >= ?
                    GROUP BY day, interface

                    UNION ALL

                    SELECT 
                        date(timestamp, 'unixepoch') as day,
                        interface,
                        SUM(rx_bytes) as rx_delta,
                        SUM(tx_bytes) as tx_delta
                    FROM interface_history_hourly
                    WHERE timestamp >= ? AND timestamp < (SELECT COALESCE(MIN(timestamp), 9999999999) FROM interface_history)
                    GROUP BY day, interface
                );
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sqlUsage), -1, out IntPtr sUsage, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sUsage, 1, startUnix);
                    WinSqliteInterop.BindInt64(sUsage, 2, startUnix);
                    if (WinSqliteInterop.Step(sUsage) == WinSqliteInterop.SQLITE_ROW)
                    {
                        usageBytes = WinSqliteInterop.ColumnInt64(sUsage, 0);
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(sUsage);
                }
            }

            double percentUsed = limitBytes.HasValue && limitBytes.Value > 0
                ? Math.Round((double)usageBytes / limitBytes.Value * 100.0, 1)
                : 0.0;

            bool isWarning = limitBytes.HasValue && percentUsed >= warningPct;
            bool isExceeded = limitBytes.HasValue && usageBytes >= limitBytes.Value;
            double remainingDays = Math.Max(0, (periodEnd - now).TotalDays);

            return new DataPlanStatus
            {
                Period = period,
                LimitBytes = limitBytes,
                ResetDay = resetDay,
                WarningPct = warningPct,
                UsageBytes = usageBytes,
                PercentUsed = percentUsed,
                IsWarning = isWarning,
                IsExceeded = isExceeded,
                PeriodStart = startUnix,
                PeriodEnd = new DateTimeOffset(periodEnd).ToUnixTimeSeconds(),
                RemainingDays = Math.Round(remainingDays, 1),
                RemainingBytes = limitBytes.HasValue ? Math.Max(0, limitBytes.Value - usageBytes) : null,
            };
        }
    }

    public BudgetForecast GetBudgetForecast()
    {
        var plan = GetDataPlanStatus();
        if (!plan.LimitBytes.HasValue || plan.LimitBytes.Value <= 0)
        {
            return new BudgetForecast
            {
                Configured = false,
                BurnStatus = "unconfigured",
                Period = plan.Period,
                EstimatedExhaustionDate = "Unlimited"
            };
        }

        long limitBytes = plan.LimitBytes.Value;
        long usedBytes = plan.UsageBytes;
        long remainingBytes = Math.Max(0, limitBytes - usedBytes);

        double totalPeriodSeconds = Math.Max(86400.0, plan.PeriodEnd - plan.PeriodStart);
        double nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        double elapsedSeconds = Math.Max(60.0, nowUnix - plan.PeriodStart);
        double remainingSeconds = Math.Max(60.0, plan.PeriodEnd - nowUnix);

        double totalDays = totalPeriodSeconds / 86400.0;
        double daysElapsed = Math.Max(0.1, elapsedSeconds / 86400.0);
        double daysRemaining = Math.Max(0.1, remainingSeconds / 86400.0);

        double avgDailyBytes = usedBytes / daysElapsed;
        double projectedTotalBytes = avgDailyBytes * totalDays;
        double projectedPct = Math.Round((projectedTotalBytes / limitBytes) * 100.0, 1);
        double recommendedDaily = remainingBytes / daysRemaining;

        string burnStatus = "healthy";
        string exhaustionDateStr;

        if (usedBytes >= limitBytes)
        {
            burnStatus = "exceeded";
            exhaustionDateStr = "Already Exceeded";
        }
        else if (avgDailyBytes > 0)
        {
            double secondsToExhaust = remainingBytes / (avgDailyBytes / 86400.0);
            var exhaustDt = DateTime.UtcNow.AddSeconds(secondsToExhaust);

            if (projectedPct < 85)
                burnStatus = "healthy";
            else if (projectedPct <= 100)
                burnStatus = "warning";
            else
                burnStatus = "critical";

            if (secondsToExhaust < remainingSeconds)
                exhaustionDateStr = exhaustDt.ToString("MMM dd, yyyy");
            else
                exhaustionDateStr = "Within Limit";
        }
        else
        {
            burnStatus = "healthy";
            exhaustionDateStr = "Within Limit";
        }

        return new BudgetForecast
        {
            Configured = true,
            LimitBytes = limitBytes,
            UsedBytes = usedBytes,
            RemainingBytes = remainingBytes,
            DaysElapsed = Math.Round(daysElapsed, 1),
            DaysRemaining = Math.Round(daysRemaining, 1),
            AvgDailyBytes = avgDailyBytes >= long.MaxValue ? long.MaxValue : (long)Math.Max(0, avgDailyBytes),
            RecommendedDailyBudgetBytes = recommendedDaily >= long.MaxValue ? long.MaxValue : (long)Math.Max(0, recommendedDaily),
            ProjectedTotalBytes = projectedTotalBytes >= long.MaxValue ? long.MaxValue : (long)Math.Max(0, projectedTotalBytes),
            ProjectedPercentage = projectedPct,
            BurnStatus = burnStatus,
            EstimatedExhaustionDate = exhaustionDateStr,
            Period = plan.Period
        };
    }

    public void UpdateDataPlan(string period = "monthly", long? limitBytes = null, int resetDay = 1, int warningPct = 80)
    {
        lock (_lock)
        {
            string sql = """
                INSERT OR REPLACE INTO data_plan (id, period, limit_bytes, reset_day, warning_pct)
                VALUES (1, ?, ?, ?, ?);
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(period), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    if (limitBytes.HasValue)
                        WinSqliteInterop.BindInt64(stmt, 2, limitBytes.Value);
                    else
                        WinSqliteInterop.BindNull(stmt, 2);
                    WinSqliteInterop.BindInt(stmt, 3, resetDay);
                    WinSqliteInterop.BindInt(stmt, 4, warningPct);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public Dictionary<string, string> GetFirewallPolicies()
    {
        lock (_lock)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string sql = "SELECT process_name, policy FROM firewall_rules;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                        string pol = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1));
                        dict[name] = pol;
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return dict;
        }
    }

    public void SetFirewallRule(string processName, bool blocked, string policy)
    {
        lock (_lock)
        {
            double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string sql = """
                INSERT OR REPLACE INTO firewall_rules (process_name, blocked, policy, updated_at)
                VALUES (?, ?, ?, ?);
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindInt(stmt, 2, blocked ? 1 : 0);
                    WinSqliteInterop.BindText(stmt, 3, WinSqliteInterop.Utf8Bytes(policy), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindDouble(stmt, 4, now);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public void ClearFirewallRules()
    {
        ExecuteNonQuery("DELETE FROM firewall_rules;");
    }

    public void LogFirewallEvent(string processName, int? pid, string remoteEndpoint, string action)
    {
        lock (_lock)
        {
            double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string sql = """
                INSERT INTO firewall_events (timestamp, process_name, pid, remote_endpoint, action)
                VALUES (?, ?, ?, ?, ?);
            """;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindDouble(stmt, 1, now);
                    WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    if (pid.HasValue) WinSqliteInterop.BindInt(stmt, 3, pid.Value); else WinSqliteInterop.BindNull(stmt, 3);
                    WinSqliteInterop.BindText(stmt, 4, WinSqliteInterop.Utf8Bytes(remoteEndpoint), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindText(stmt, 5, WinSqliteInterop.Utf8Bytes(action), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public List<FirewallEvent> GetFirewallEvents(int limit = 50)
    {
        lock (_lock)
        {
            var list = new List<FirewallEvent>();
            string sql = "SELECT id, timestamp, process_name, pid, remote_endpoint, action FROM firewall_events ORDER BY id DESC LIMIT ?;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt(stmt, 1, limit);
                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        long id = WinSqliteInterop.ColumnInt64(stmt, 0);
                        double ts = WinSqliteInterop.ColumnDouble(stmt, 1);
                        string name = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 2));
                        int? pid = WinSqliteInterop.ColumnType(stmt, 3) != 5 ? WinSqliteInterop.ColumnInt(stmt, 3) : null;
                        string endpoint = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 4));
                        string action = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 5));
                        list.Add(new FirewallEvent(id, ts, name, pid, endpoint, action));
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public bool MarkOrCheckFirstSeen(string processName, string cmdline)
    {
        lock (_lock)
        {
            double now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string checkSql = "SELECT first_seen_timestamp FROM seen_applications WHERE process_name = ?;";
            bool isNew = true;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(checkSql), -1, out IntPtr s1, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(s1, 1, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    if (WinSqliteInterop.Step(s1) == WinSqliteInterop.SQLITE_ROW)
                    {
                        isNew = false;
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(s1);
                }
            }

            if (isNew)
            {
                string insertSql = "INSERT INTO seen_applications (process_name, first_seen_timestamp, last_seen_timestamp, cmdline) VALUES (?, ?, ?, ?);";
                if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(insertSql), -1, out IntPtr s2, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
                {
                    try
                    {
                        WinSqliteInterop.BindText(s2, 1, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                        WinSqliteInterop.BindDouble(s2, 2, now);
                        WinSqliteInterop.BindDouble(s2, 3, now);
                        WinSqliteInterop.BindText(s2, 4, WinSqliteInterop.Utf8Bytes(cmdline ?? ""), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                        WinSqliteInterop.Step(s2);
                    }
                    finally
                    {
                        WinSqliteInterop.Finalize(s2);
                    }
                }
            }
            else
            {
                string updateSql = "UPDATE seen_applications SET last_seen_timestamp = ? WHERE process_name = ?;";
                if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(updateSql), -1, out IntPtr s3, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
                {
                    try
                    {
                        WinSqliteInterop.BindDouble(s3, 1, now);
                        WinSqliteInterop.BindText(s3, 2, WinSqliteInterop.Utf8Bytes(processName), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                        WinSqliteInterop.Step(s3);
                    }
                    finally
                    {
                        WinSqliteInterop.Finalize(s3);
                    }
                }
            }

            return isNew;
        }
    }

    public string ExportDailyCsv()
    {
        var days = GetDailyUsage(365);
        var sb = new StringBuilder();
        sb.AppendLine("Date,RX Bytes,TX Bytes,Total Bytes,Total MB");
        foreach (var d in days)
        {
            string date = d["date"].ToString()!;
            long rx = (long)d["rx_bytes"];
            long tx = (long)d["tx_bytes"];
            long total = (long)d["total_bytes"];
            double mb = total / (1024.0 * 1024.0);
            sb.AppendLine($"{date},{rx},{tx},{total},{mb:F2}");
        }
        return sb.ToString();
    }

    public string ExportProcessesCsv()
    {
        var procs = GetTopProcesses(30 * 86400, 100);
        var sb = new StringBuilder();
        sb.AppendLine("Process Name,RX Bytes,TX Bytes,Total Bytes,Total MB,Max Connections");
        foreach (var p in procs)
        {
            string name = p["process_name"].ToString()!;
            long rx = (long)p["rx_bytes"];
            long tx = (long)p["tx_bytes"];
            long total = (long)p["total_bytes"];
            double mb = total / (1024.0 * 1024.0);
            int conns = (int)p["max_connections"];
            sb.AppendLine($"\"{name}\",{rx},{tx},{total},{mb:F2},{conns}");
        }
        return sb.ToString();
    }

    public string GetSetting(string key, string defaultValue = "")
    {
        lock (_lock)
        {
            string sql = "SELECT value FROM app_settings WHERE key = ? LIMIT 1;";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(key), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    if (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        return WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0));
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return defaultValue;
        }
    }

    public void SetSetting(string key, string value)
    {
        lock (_lock)
        {
            string sql = "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?);";
            int rc = WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero);
            if (rc == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(key), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(value), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    WinSqliteInterop.Step(stmt);
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
        }
    }

    public bool GetSettingBool(string key, bool defaultValue = true)
    {
        string val = GetSetting(key, defaultValue ? "1" : "0");
        return val is "1" or "true" or "True";
    }

    public void SetSettingBool(string key, bool value)
    {
        SetSetting(key, value ? "1" : "0");
    }

    public record LifecycleMaintenanceResult(
        int HourlyRollupsProcessed,
        int DailyRollupsProcessed,
        int RawInterfaceRowsPurged,
        int RawProcessRowsPurged,
        int ExpiredHourlyRowsPurged
    );

    public LifecycleMaintenanceResult PerformLifecycleMaintenance(long? nowTimestamp = null)
    {
        lock (_lock)
        {
            long now = nowTimestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long currentHour = (now / 3600) * 3600;

            // 1. Rollup interface_history into interface_history_hourly (before currentHour)
            string rollupIfaceSql = """
                INSERT OR REPLACE INTO interface_history_hourly (timestamp, interface, rx_bytes, tx_bytes, rx_speed_avg, tx_speed_avg)
                SELECT 
                    (timestamp / 3600) * 3600 AS hour_ts,
                    interface,
                    MAX(rx_bytes) - MIN(rx_bytes) AS rx_delta,
                    MAX(tx_bytes) - MIN(tx_bytes) AS tx_delta,
                    ROUND(AVG(rx_speed), 2) AS avg_rx_speed,
                    ROUND(AVG(tx_speed), 2) AS avg_tx_speed
                FROM interface_history
                WHERE timestamp < ?
                GROUP BY hour_ts, interface;
            """;

            int ifaceRollups = 0;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(rollupIfaceSql), -1, out IntPtr sRollupIface, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sRollupIface, 1, currentHour);
                    WinSqliteInterop.Step(sRollupIface);
                }
                finally
                {
                    WinSqliteInterop.Finalize(sRollupIface);
                }
                ifaceRollups = WinSqliteInterop.Changes(_db);
            }

            // 2. Rollup process_history into process_history_daily (before today)
            long todayStart = new DateTimeOffset(DateTimeOffset.FromUnixTimeSeconds(now).Date, TimeSpan.Zero).ToUnixTimeSeconds();
            string rollupProcSql = """
                INSERT OR REPLACE INTO process_history_daily (day, process_name, total_rx, total_tx, max_connections)
                SELECT 
                    date(timestamp, 'unixepoch') AS day_str,
                    process_name,
                    SUM(rx_bytes) AS total_rx,
                    SUM(tx_bytes) AS total_tx,
                    MAX(active_connections) AS max_conn
                FROM process_history
                WHERE timestamp < ?
                GROUP BY day_str, process_name;
            """;

            int procRollups = 0;
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(rollupProcSql), -1, out IntPtr sRollupProc, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sRollupProc, 1, todayStart);
                    WinSqliteInterop.Step(sRollupProc);
                }
                finally
                {
                    WinSqliteInterop.Finalize(sRollupProc);
                }
                procRollups = WinSqliteInterop.Changes(_db);
            }

            // 3. Purge raw snapshots older than 7 days (7 * 86400 = 604,800 seconds)
            long rawRetentionCutoff = now - (7 * 86400L);
            int purgedRawIface = 0;
            string purgeIfaceSql = "DELETE FROM interface_history WHERE timestamp < ?;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(purgeIfaceSql), -1, out IntPtr sPurgeIface, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sPurgeIface, 1, rawRetentionCutoff);
                    WinSqliteInterop.Step(sPurgeIface);
                }
                finally
                {
                    WinSqliteInterop.Finalize(sPurgeIface);
                }
                purgedRawIface = WinSqliteInterop.Changes(_db);
            }

            int purgedRawProc = 0;
            string purgeProcSql = "DELETE FROM process_history WHERE timestamp < ?;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(purgeProcSql), -1, out IntPtr sPurgeProc, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sPurgeProc, 1, rawRetentionCutoff);
                    WinSqliteInterop.Step(sPurgeProc);
                }
                finally
                {
                    WinSqliteInterop.Finalize(sPurgeProc);
                }
                purgedRawProc = WinSqliteInterop.Changes(_db);
            }

            // 4. Retain hourly rollups for 30 days (30 * 86400 seconds)
            long hourlyRetentionCutoff = now - (30 * 86400L);
            int purgedHourly = 0;
            string purgeHourlySql = "DELETE FROM interface_history_hourly WHERE timestamp < ?;";
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(purgeHourlySql), -1, out IntPtr sPurgeHourly, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(sPurgeHourly, 1, hourlyRetentionCutoff);
                    WinSqliteInterop.Step(sPurgeHourly);
                }
                finally
                {
                    WinSqliteInterop.Finalize(sPurgeHourly);
                }
                purgedHourly = WinSqliteInterop.Changes(_db);
            }

            // 5. Incremental vacuum to reclaim database pages
            ExecuteNonQuery("PRAGMA incremental_vacuum;");

            return new LifecycleMaintenanceResult(ifaceRollups, procRollups, purgedRawIface, purgedRawProc, purgedHourly);
        }
    }

    public List<Dictionary<string, object>> GetHourlyInterfaceRollups(int hours = 24, string? iface = null)
    {
        lock (_lock)
        {
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - (hours * 3600L);
            string sql = string.IsNullOrEmpty(iface)
                ? "SELECT timestamp, interface, rx_bytes, tx_bytes, rx_speed_avg, tx_speed_avg FROM interface_history_hourly WHERE timestamp >= ? ORDER BY timestamp ASC;"
                : "SELECT timestamp, interface, rx_bytes, tx_bytes, rx_speed_avg, tx_speed_avg FROM interface_history_hourly WHERE timestamp >= ? AND interface = ? ORDER BY timestamp ASC;";

            var list = new List<Dictionary<string, object>>();
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindInt64(stmt, 1, cutoff);
                    if (!string.IsNullOrEmpty(iface))
                    {
                        WinSqliteInterop.BindText(stmt, 2, WinSqliteInterop.Utf8Bytes(iface), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    }

                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        list.Add(new Dictionary<string, object>
                        {
                            ["timestamp"] = WinSqliteInterop.ColumnInt64(stmt, 0),
                            ["interface"] = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1)),
                            ["rx_bytes"] = WinSqliteInterop.ColumnInt64(stmt, 2),
                            ["tx_bytes"] = WinSqliteInterop.ColumnInt64(stmt, 3),
                            ["rx_speed_avg"] = WinSqliteInterop.ColumnDouble(stmt, 4),
                            ["tx_speed_avg"] = WinSqliteInterop.ColumnDouble(stmt, 5)
                        });
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public List<Dictionary<string, object>> GetDailyProcessRollups(int days = 30)
    {
        lock (_lock)
        {
            string cutoffDay = DateTimeOffset.UtcNow.AddDays(-days).ToString("yyyy-MM-dd");
            string sql = "SELECT day, process_name, total_rx, total_tx, max_connections FROM process_history_daily WHERE day >= ? ORDER BY day ASC, (total_rx + total_tx) DESC;";

            var list = new List<Dictionary<string, object>>();
            if (WinSqliteInterop.Prepare(_db, WinSqliteInterop.Utf8Bytes(sql), -1, out IntPtr stmt, IntPtr.Zero) == WinSqliteInterop.SQLITE_OK)
            {
                try
                {
                    WinSqliteInterop.BindText(stmt, 1, WinSqliteInterop.Utf8Bytes(cutoffDay), -1, WinSqliteInterop.SQLITE_TRANSIENT);
                    while (WinSqliteInterop.Step(stmt) == WinSqliteInterop.SQLITE_ROW)
                    {
                        list.Add(new Dictionary<string, object>
                        {
                            ["day"] = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 0)),
                            ["process_name"] = WinSqliteInterop.PtrToStringUtf8(WinSqliteInterop.ColumnText(stmt, 1)),
                            ["total_rx"] = WinSqliteInterop.ColumnInt64(stmt, 2),
                            ["total_tx"] = WinSqliteInterop.ColumnInt64(stmt, 3),
                            ["max_connections"] = WinSqliteInterop.ColumnInt(stmt, 4)
                        });
                    }
                }
                finally
                {
                    WinSqliteInterop.Finalize(stmt);
                }
            }
            return list;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_db != IntPtr.Zero)
            {
                WinSqliteInterop.Close(_db);
                _db = IntPtr.Zero;
            }
        }
    }
}
