using NetFlow.Core.Services;
using NetFlow.Core.Storage;

namespace NetFlow.Tests;

public class NetflowStorageTests : IDisposable
{
    private readonly string _tempDb;
    private readonly NetflowStorage _storage;

    public NetflowStorageTests()
    {
        _tempDb = Path.Combine(Path.GetTempPath(), $"netflow_test_{Guid.NewGuid():N}.db");
        _storage = new NetflowStorage(_tempDb);
    }

    [Fact]
    public void Storage_Initializes_Tables_Successfully()
    {
        Assert.NotNull(_storage);
        var status = _storage.GetDataPlanStatus();
        Assert.NotNull(status);
        Assert.Equal("monthly", status.Period);
    }

    [Fact]
    public void Storage_Records_And_Retrieves_Interface_Speeds()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _storage.RecordInterfaceSnapshot(now, "Ethernet", 1000, 500, 100.0, 50.0);

        var recent = _storage.GetRecentSpeeds(10);
        Assert.NotEmpty(recent);
        Assert.Equal(100.0, (double)recent[0]["rx_speed"]);
    }

    [Fact]
    public void Storage_Records_And_Aggregates_Processes()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _storage.RecordProcessSnapshot(now, "chrome.exe", 1234, 5000, 2000, 3);
        _storage.RecordProcessSnapshot(now + 1, "chrome.exe", 1234, 3000, 1000, 2);

        var top = _storage.GetTopProcesses(60);
        Assert.NotEmpty(top);
        Assert.Equal("chrome.exe", top[0]["process_name"]);
        Assert.Equal(8000L, (long)top[0]["rx_bytes"]);
        Assert.Equal(3000L, (long)top[0]["tx_bytes"]);
    }

    [Fact]
    public void Storage_DataPlan_Quota_Calculation()
    {
        long limit = 10L * 1024 * 1024 * 1024; // 10 GB
        _storage.UpdateDataPlan("monthly", limit, resetDay: 1, warningPct: 80);

        var plan = _storage.GetDataPlanStatus();
        Assert.Equal(limit, plan.LimitBytes);
        Assert.False(plan.IsWarning);
        Assert.False(plan.IsExceeded);
    }

    [Fact]
    public void Storage_Firewall_Policies_And_FirstSeen()
    {
        _storage.SetFirewallRule("malware.exe", true, "block");
        var policies = _storage.GetFirewallPolicies();

        Assert.True(policies.ContainsKey("malware.exe"));
        Assert.Equal("block", policies["malware.exe"]);

        // First seen test
        bool isFirst = _storage.MarkOrCheckFirstSeen("test_app.exe", "test_app.exe --run");
        Assert.True(isFirst);

        bool isSecond = _storage.MarkOrCheckFirstSeen("test_app.exe", "test_app.exe --run");
        Assert.False(isSecond);
    }

    [Fact]
    public void Storage_CsvExport_Generates_ValidHeaders()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _storage.RecordInterfaceSnapshot(now, "Wi-Fi", 2048, 1024, 2048, 1024);
        _storage.RecordProcessSnapshot(now, "discord.exe", 999, 1024, 512, 1);

        string dailyCsv = _storage.ExportDailyCsv();
        Assert.Contains("Date,RX Bytes,TX Bytes,Total Bytes,Total MB", dailyCsv);

        string procCsv = _storage.ExportProcessesCsv();
        Assert.Contains("Process Name,RX Bytes,TX Bytes,Total Bytes,Total MB,Max Connections", procCsv);
        Assert.Contains("discord.exe", procCsv);
    }

    [Fact]
    public void DnsResolver_Classifies_Scopes()
    {
        Assert.Equal("LOOPBACK", DnsResolver.ClassifyScope("127.0.0.1"));
        Assert.Equal("LOOPBACK", DnsResolver.ClassifyScope("::1"));
        Assert.Equal("LAN", DnsResolver.ClassifyScope("192.168.1.100"));
        Assert.Equal("LAN", DnsResolver.ClassifyScope("10.0.0.5"));
        Assert.Equal("LAN", DnsResolver.ClassifyScope("172.20.1.1"));
        Assert.Equal("WAN", DnsResolver.ClassifyScope("1.1.1.1"));
        Assert.Equal("WAN", DnsResolver.ClassifyScope("8.8.8.8"));
    }

    [Fact]
    public void Storage_BudgetForecast_Unconfigured()
    {
        var forecast = _storage.GetBudgetForecast();
        Assert.False(forecast.Configured);
        Assert.Equal("unconfigured", forecast.BurnStatus);
        Assert.Equal("Unlimited", forecast.EstimatedExhaustionDate);
    }

    [Fact]
    public void Storage_BudgetForecast_HealthyPace()
    {
        long limit = 10L * 1024 * 1024 * 1024; // 10 GB
        _storage.UpdateDataPlan("monthly", limit, resetDay: 1, warningPct: 80);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Baseline snapshot then 500 KB delta in period
        _storage.RecordInterfaceSnapshot(now - 60, "Wi-Fi", 0, 0, 0.0, 0.0);
        _storage.RecordInterfaceSnapshot(now, "Wi-Fi", 300 * 1024, 200 * 1024, 1000.0, 500.0);

        var forecast = _storage.GetBudgetForecast();
        Assert.True(forecast.Configured);
        Assert.Equal(limit, forecast.LimitBytes);
        Assert.True(forecast.UsedBytes > 0);
        Assert.True(forecast.RemainingBytes > 0);
        Assert.True(forecast.RecommendedDailyBudgetBytes > 0);
        Assert.Equal("healthy", forecast.BurnStatus);
    }

    [Fact]
    public void Storage_BudgetForecast_Exceeded()
    {
        long limit = 1024 * 1024; // 1 MB
        _storage.UpdateDataPlan("monthly", limit, resetDay: 1, warningPct: 80);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Baseline snapshot then 3 MB delta in period (exceeding 1 MB limit)
        _storage.RecordInterfaceSnapshot(now - 60, "Wi-Fi", 0, 0, 0.0, 0.0);
        _storage.RecordInterfaceSnapshot(now, "Wi-Fi", 2 * 1024 * 1024, 1024 * 1024, 1000.0, 500.0);

        var forecast = _storage.GetBudgetForecast();
        Assert.True(forecast.Configured);
        Assert.Equal("exceeded", forecast.BurnStatus);
        Assert.Equal("Already Exceeded", forecast.EstimatedExhaustionDate);
    }

    [Fact]
    public void Storage_GetUsageSummary_CalculatesTodayAndAllTime()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long twoDaysAgo = now - (86400 * 2);

        // Snapshots from 2 days ago: 1,000,000 rx, 500,000 tx delta
        _storage.RecordInterfaceSnapshot(twoDaysAgo - 60, "Ethernet", 0, 0, 0.0, 0.0);
        _storage.RecordInterfaceSnapshot(twoDaysAgo, "Ethernet", 1_000_000, 500_000, 100.0, 50.0);
        // Snapshots from today: continuing cumulative counter to 1,200,000 rx, 600,000 tx (200,000 rx, 100,000 tx delta)
        _storage.RecordInterfaceSnapshot(now - 60, "Ethernet", 1_000_000, 500_000, 0.0, 0.0);
        _storage.RecordInterfaceSnapshot(now, "Ethernet", 1_200_000, 600_000, 50.0, 25.0);

        var summary = _storage.GetUsageSummary();
        Assert.NotNull(summary);
        Assert.Equal(200_000L, Convert.ToInt64(summary["today_rx_bytes"]));
        Assert.Equal(100_000L, Convert.ToInt64(summary["today_tx_bytes"]));
        Assert.Equal(300_000L, Convert.ToInt64(summary["today_total_bytes"]));

        Assert.Equal(1_200_000L, Convert.ToInt64(summary["all_time_rx_bytes"]));
        Assert.Equal(600_000L, Convert.ToInt64(summary["all_time_tx_bytes"]));
        Assert.Equal(1_800_000L, Convert.ToInt64(summary["all_time_total_bytes"]));
    }

    [Fact]
    public void Storage_SingleSnapshot_DoesNotReportPhantomUsage()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // A single snapshot with 50 GB cumulative lifetime counter
        _storage.RecordInterfaceSnapshot(now, "Ethernet", 50L * 1024 * 1024 * 1024, 10L * 1024 * 1024 * 1024, 100.0, 50.0);

        var summary = _storage.GetUsageSummary();
        Assert.NotNull(summary);
        Assert.Equal(0L, Convert.ToInt64(summary["today_rx_bytes"]));
        Assert.Equal(0L, Convert.ToInt64(summary["today_tx_bytes"]));
        Assert.Equal(0L, Convert.ToInt64(summary["today_total_bytes"]));
        Assert.Equal(0L, Convert.ToInt64(summary["all_time_total_bytes"]));

        var daily = _storage.GetDailyUsage(1);
        Assert.NotEmpty(daily);
        Assert.Equal(0L, Convert.ToInt64(daily[0]["total_bytes"]));
    }

    public void Dispose()
    {
        _storage.Dispose();
        try
        {
            if (File.Exists(_tempDb)) File.Delete(_tempDb);
        }
        catch { }
    }
}
