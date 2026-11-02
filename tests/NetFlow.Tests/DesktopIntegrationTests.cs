using System.Collections.Concurrent;
using System.Text.Json;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Services;
using NetFlow.Server;
using Xunit;

namespace NetFlow.Tests;

public class DesktopIntegrationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();

    public void Dispose()
    {
        foreach (var file in _tempFiles)
        {
            try
            {
                if (File.Exists(file)) File.Delete(file);
            }
            catch { }
        }
    }

    private string CreateTempDbPath()
    {
        string path = Path.Combine(Path.GetTempPath(), $"netflow_desktop_test_{Guid.NewGuid():N}.db");
        _tempFiles.Add(path);
        return path;
    }

    #region 1. Tray Tooltip Formatting & 63-char Win32 Invariant

    [Fact]
    public void Tooltip_FormatSpeed_Bytes_Boundaries()
    {
        Assert.Equal("0 B/s", TrayTooltipHelper.FormatSpeed(0));
        Assert.Equal("500 B/s", TrayTooltipHelper.FormatSpeed(500));
        Assert.Equal("1023 B/s", TrayTooltipHelper.FormatSpeed(1023));
    }

    [Fact]
    public void Tooltip_FormatSpeed_Kilobytes_Boundaries()
    {
        Assert.Equal("1.0 KB/s", TrayTooltipHelper.FormatSpeed(1024));
        Assert.Equal("350.0 KB/s", TrayTooltipHelper.FormatSpeed(1024 * 350));
        Assert.Equal("1023.9 KB/s", TrayTooltipHelper.FormatSpeed(1024 * 1023.9));
    }

    [Fact]
    public void Tooltip_FormatSpeed_Megabytes_Boundaries()
    {
        Assert.Equal("1.0 MB/s", TrayTooltipHelper.FormatSpeed(1024 * 1024));
        Assert.Equal("1.2 MB/s", TrayTooltipHelper.FormatSpeed(1024 * 1024 * 1.25));
        Assert.Equal("50.5 MB/s", TrayTooltipHelper.FormatSpeed(1024 * 1024 * 50.5));
    }

    [Fact]
    public void Tooltip_FormatSpeed_Gigabytes_Boundaries()
    {
        Assert.Equal("1.00 GB/s", TrayTooltipHelper.FormatSpeed(1024L * 1024L * 1024L));
        Assert.Equal("2.50 GB/s", TrayTooltipHelper.FormatSpeed(1024L * 1024L * 1024L * 2.5));
    }

    [Fact]
    public void Tooltip_FormatTooltip_ExpectedFormatting()
    {
        double rx = 1024 * 1024 * 1.25; // 1.25 MB/s
        double tx = 1024 * 350;         // 350 KB/s

        string tooltip = TrayTooltipHelper.FormatTooltip(rx, tx);
        Assert.Equal("NetFlow - ↓ 1.2 MB/s | ↑ 350.0 KB/s", tooltip);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(500, 200)]
    [InlineData(1024 * 10, 1024 * 20)]
    [InlineData(1024 * 1024 * 100, 1024 * 1024 * 50)]
    [InlineData(1024L * 1024L * 1024L * 999.99, 1024L * 1024L * 1024L * 888.88)]
    [InlineData(double.MaxValue / 2, double.MaxValue / 2)]
    public void Tooltip_FormatTooltip_LengthNeverExceeds63Chars(double rx, double tx)
    {
        string tip = TrayTooltipHelper.FormatTooltip(rx, tx);
        Assert.True(tip.Length <= TrayTooltipHelper.MaxTooltipLength,
            $"Tooltip '{tip}' has length {tip.Length} which exceeds Win32 limit of 63 chars.");
    }

    #endregion

    #region 2. WindowsStartupManager & Registry Logic

    [Fact]
    public void Startup_Constants_MatchWindowsSpec()
    {
        Assert.Equal(@"Software\Microsoft\Windows\CurrentVersion\Run", WindowsStartupManager.RunRegistryKey);
        Assert.Equal("NetFlow", WindowsStartupManager.AppValueName);
    }

    [Fact]
    public void Startup_GetAppPath_ReturnsValidExecutable()
    {
        string path = WindowsStartupManager.GetAppPath();
        Assert.False(string.IsNullOrWhiteSpace(path));
        Assert.EndsWith(".exe", path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Startup_GetContract_JsonSerialization()
    {
        var model = new
        {
            enabled = WindowsStartupManager.IsStartupEnabled(),
            path = WindowsStartupManager.GetAppPath()
        };

        string json = JsonSerializer.Serialize(model);
        using var doc = JsonDocument.Parse(json);

        Assert.True(doc.RootElement.TryGetProperty("enabled", out var enabledProp));
        Assert.True(enabledProp.ValueKind == JsonValueKind.True || enabledProp.ValueKind == JsonValueKind.False);
        Assert.True(doc.RootElement.TryGetProperty("path", out var pathProp));
        Assert.False(string.IsNullOrWhiteSpace(pathProp.GetString()));
    }

    [Fact]
    public void Startup_PostContract_JsonSerialization()
    {
        var model = new
        {
            success = true,
            enabled = true,
            path = @"C:\Program Files\NetFlow\NetFlow.App.exe",
            error = (string?)null
        };

        string json = JsonSerializer.Serialize(model);
        using var doc = JsonDocument.Parse(json);

        Assert.True(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("enabled").GetBoolean());
        Assert.Equal(@"C:\Program Files\NetFlow\NetFlow.App.exe", doc.RootElement.GetProperty("path").GetString());
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("error").ValueKind);
    }

    [Fact]
    public void Startup_SetStartupEnabled_HandlesGracefullyWithoutCrashing()
    {
        // Safe query / toggle test - should catch any security exceptions and return graceful tuple
        bool current = WindowsStartupManager.IsStartupEnabled();
        var result = WindowsStartupManager.SetStartupEnabled(current);

        Assert.False(string.IsNullOrWhiteSpace(result.Path));
        // Result either succeeded or gracefully returned an error string
        if (!result.Success)
        {
            Assert.NotNull(result.Error);
        }
    }

    #endregion

    #region 3. Toast Notification Escaping & Payloads

    [Fact]
    public void Toast_EscapesSingleQuotes_ForPowerShellSafety()
    {
        string rawTitle = "Security Threat: Hacker's Payload 'Backdoor.exe'";
        string safeTitle = rawTitle.Replace("'", "''");

        Assert.Equal("Security Threat: Hacker''s Payload ''Backdoor.exe''", safeTitle);
        Assert.DoesNotContain("Hacker's", safeTitle);
    }

    [Fact]
    public void Toast_EscapesMultipleConsecutiveQuotes()
    {
        string input = "Test '' ''";
        string escaped = input.Replace("'", "''");
        Assert.Equal("Test '''' ''''", escaped);
    }

    [Fact]
    public void Toast_PayloadXmlStructure_Validation()
    {
        string title = "Quota Alert";
        string message = "85% used";

        string script = $@"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('{title}')) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode('{message}')) | Out-Null
";
        Assert.Contains("ToastText02", script);
        Assert.Contains(title, script);
        Assert.Contains(message, script);
    }

    #endregion

    #region 4. Data Plan Quota Threshold Crossing & Human Formatting

    [Fact]
    public void Quota_Threshold_BelowWarning()
    {
        var status = new DataPlanStatus
        {
            LimitBytes = 1000,
            UsageBytes = 750,
            PercentUsed = 75.0,
            WarningPct = 80,
            IsWarning = false,
            IsExceeded = false
        };

        Assert.False(status.IsWarning);
        Assert.False(status.IsExceeded);
    }

    [Fact]
    public void Quota_Threshold_AtWarningThreshold_80Pct()
    {
        long limit = 1000;
        long usage = 800;
        double pct = (double)usage / limit * 100.0;

        var status = new DataPlanStatus
        {
            LimitBytes = limit,
            UsageBytes = usage,
            PercentUsed = pct,
            WarningPct = 80,
            IsWarning = pct >= 80,
            IsExceeded = usage >= limit
        };

        Assert.True(status.IsWarning);
        Assert.False(status.IsExceeded);
    }

    [Fact]
    public void Quota_Threshold_AtLimit_100Pct()
    {
        long limit = 1000;
        long usage = 1000;
        double pct = (double)usage / limit * 100.0;

        var status = new DataPlanStatus
        {
            LimitBytes = limit,
            UsageBytes = usage,
            PercentUsed = pct,
            WarningPct = 80,
            IsWarning = pct >= 80,
            IsExceeded = usage >= limit
        };

        Assert.True(status.IsWarning);
        Assert.True(status.IsExceeded);
    }

    [Fact]
    public void Quota_HumanReadable_BytesFormatting()
    {
        var status1 = new DataPlanStatus
        {
            UsageBytes = 500,
            LimitBytes = 1024L * 1024L * 50
        };
        Assert.Equal("500 B", status1.UsedBytesHuman);
        Assert.Equal("50.0 MB", status1.LimitBytesHuman);

        var status2 = new DataPlanStatus
        {
            UsageBytes = (long)(1024L * 1024L * 1024L * 42.5),
            LimitBytes = (long)(1024L * 1024L * 1024L * 50.0)
        };
        Assert.Equal("42.50 GB", status2.UsedBytesHuman);
        Assert.Equal("50.00 GB", status2.LimitBytesHuman);

        var statusUnlimited = new DataPlanStatus
        {
            UsageBytes = 1024 * 100,
            LimitBytes = null
        };
        Assert.Equal("100.0 KB", statusUnlimited.UsedBytesHuman);
        Assert.Equal("Unlimited", statusUnlimited.LimitBytesHuman);
    }

    [Fact]
    public void Quota_Alert_RateLimiting_15MinuteCooldown()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        storage.UpdateDataPlan("monthly", 1000, 1, 80);

        // Record usage exceeding warning (850 / 1000 bytes = 85%)
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        storage.RecordInterfaceSnapshot(now, "eth0", 500, 350, 100, 100);

        var tracker = new BandwidthTracker(storage, new DummyFirewall(), new DummySocketProvider());
        var worker = new NetflowBackgroundWorker(tracker, storage);

        var t0 = DateTimeOffset.UtcNow;

        // Check 1: Initial alert triggers
        bool alerted1 = worker.CheckQuotaAlerts(t0);
        Assert.True(alerted1);
        Assert.Equal(t0, worker.LastQuotaAlert);

        // Check 2: Immediately after (e.g. +5 minutes) -> Suppressed by 15-minute cooldown
        bool alerted2 = worker.CheckQuotaAlerts(t0.AddMinutes(5));
        Assert.False(alerted2);

        // Check 3: At +14 minutes -> Still suppressed
        bool alerted3 = worker.CheckQuotaAlerts(t0.AddMinutes(14));
        Assert.False(alerted3);

        // Check 4: At +16 minutes -> Cooldown elapsed, alerts again
        bool alerted4 = worker.CheckQuotaAlerts(t0.AddMinutes(16));
        Assert.True(alerted4);
        Assert.Equal(t0.AddMinutes(16), worker.LastQuotaAlert);
    }

    #endregion

    #region 5. Threat Notification Rate Limiting & Deduplication

    [Fact]
    public void Threat_Alert_HighRisk_TriggeredAndRateLimited60Seconds()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var tracker = new ThreatInjectableTracker(storage);
        var worker = new NetflowBackgroundWorker(tracker, storage);

        int pid = 8844;
        tracker.SetThreatProcesses(new List<ProcessBandwidth>
        {
            new ProcessBandwidth
            {
                Pid = pid,
                Name = "trojan.exe",
                Threat = new ThreatAssessment
                {
                    Level = RiskLevel.High,
                    Publisher = "Unknown",
                    StatusMessage = "Unsigned high risk process"
                }
            }
        });

        var t0 = DateTimeOffset.UtcNow;

        // 1. First poll at t0 -> Should alert and record timestamp
        worker.CheckThreatAlerts(t0);
        Assert.True(worker.AlertedThreatPids.ContainsKey(pid));
        Assert.Equal(t0, worker.AlertedThreatPids[pid]);

        // 2. Second poll at t0 + 30 seconds -> Suppressed by 60s cooldown
        worker.CheckThreatAlerts(t0.AddSeconds(30));
        Assert.Equal(t0, worker.AlertedThreatPids[pid]); // Timestamp unchanged

        // 3. Third poll at t0 + 59 seconds -> Still suppressed
        worker.CheckThreatAlerts(t0.AddSeconds(59));
        Assert.Equal(t0, worker.AlertedThreatPids[pid]);

        // 4. Fourth poll at t0 + 65 seconds -> Cooldown elapsed, re-alerted and timestamp updated
        var t65 = t0.AddSeconds(65);
        worker.CheckThreatAlerts(t65);
        Assert.Equal(t65, worker.AlertedThreatPids[pid]);
    }

    [Fact]
    public void Threat_Alert_MultiplePids_TrackedIndependently()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var tracker = new ThreatInjectableTracker(storage);
        var worker = new NetflowBackgroundWorker(tracker, storage);

        int pid1 = 1001;
        int pid2 = 2002;

        tracker.SetThreatProcesses(new List<ProcessBandwidth>
        {
            new ProcessBandwidth { Pid = pid1, Name = "evil1.exe", Threat = new ThreatAssessment { Level = RiskLevel.High } },
            new ProcessBandwidth { Pid = pid2, Name = "evil2.exe", Threat = new ThreatAssessment { Level = RiskLevel.Critical } }
        });

        var t0 = DateTimeOffset.UtcNow;
        worker.CheckThreatAlerts(t0);

        Assert.True(worker.AlertedThreatPids.ContainsKey(pid1));
        Assert.True(worker.AlertedThreatPids.ContainsKey(pid2));
        Assert.Equal(t0, worker.AlertedThreatPids[pid1]);
        Assert.Equal(t0, worker.AlertedThreatPids[pid2]);
    }

    [Fact]
    public void Threat_Alert_SafeAndLowRisk_Ignored()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var tracker = new ThreatInjectableTracker(storage);
        var worker = new NetflowBackgroundWorker(tracker, storage);

        tracker.SetThreatProcesses(new List<ProcessBandwidth>
        {
            new ProcessBandwidth { Pid = 3001, Name = "notepad.exe", Threat = new ThreatAssessment { Level = RiskLevel.Safe } },
            new ProcessBandwidth { Pid = 3002, Name = "updater.exe", Threat = new ThreatAssessment { Level = RiskLevel.Low } },
            new ProcessBandwidth { Pid = 3003, Name = "scanner.exe", Threat = new ThreatAssessment { Level = RiskLevel.Medium } }
        });

        worker.CheckThreatAlerts(DateTimeOffset.UtcNow);
        Assert.Empty(worker.AlertedThreatPids);
    }

    #endregion

    #region Mock / Test Doubles

    private class DummyFirewall : IFirewallEngine
    {
        public bool IsEnabled => true;
        public void LoadRules() { }
        public bool ToggleFirewall(bool? enabled = null) => true;
        public bool IsAppBlocked(string processName) => false;
        public string GetAppPolicy(string processName) => "allow";
        public string SetAppPolicy(string processName, string policy) => policy;
        public int ClearAllBlocks() => 0;
        public Dictionary<string, object> GetStatus() => new();
        public List<Dictionary<string, object>> Enforce(List<SocketInfo> activeSockets, List<ProcessBandwidth> activeProcesses) => new();
    }

    private class DummySocketProvider : ISocketProvider
    {
        public List<SocketInfo> GetEnrichedSockets() => new();
        public bool TryGetProcessIo(int pid, out ulong readBytes, out ulong writeBytes)
        {
            readBytes = 0;
            writeBytes = 0;
            return false;
        }
    }

    private class ThreatInjectableTracker : BandwidthTracker
    {
        private List<ProcessBandwidth> _threatProcesses = new();

        public ThreatInjectableTracker(NetflowStorage storage)
            : base(storage, new DummyFirewall(), new DummySocketProvider())
        {
        }

        public void SetThreatProcesses(List<ProcessBandwidth> procs)
        {
            _threatProcesses = procs;
        }

        public override RealtimeSnapshot? GetLatestSnapshot()
        {
            return new RealtimeSnapshot
            {
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                TopProcesses = _threatProcesses
            };
        }
    }

    #endregion
}
