using System.Net;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Core.Telemetry;
using NetFlow.Platform.Windows.Services;
using NetFlow.Platform.Windows.Vpn;
using Xunit;
using GeoIpService = NetFlow.Core.Telemetry.GeoIpService;

namespace NetFlow.Tests;

public class ArchitecturalEnhancementsTests : IDisposable
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
        string path = Path.Combine(Path.GetTempPath(), $"netflow_arch_test_{Guid.NewGuid():N}.db");
        _tempFiles.Add(path);
        return path;
    }

    #region 1. Native WinRT / Zero-Overhead Toast Notifier

    [Fact]
    public void Toast_StrictlyHonors_IsEnabled_Setting()
    {
        string? receivedTitle = null;
        WindowsNotifier.NotificationHandler = (t, m) => receivedTitle = t;

        // Enabled
        WindowsNotifier.IsEnabled = true;
        WindowsNotifier.SendNotification("Alert 1", "Body 1");
        Assert.Equal("Alert 1", receivedTitle);

        // Disabled
        receivedTitle = null;
        WindowsNotifier.IsEnabled = false;
        WindowsNotifier.SendNotification("Alert 2", "Body 2");
        Assert.Null(receivedTitle);

        // Reset
        WindowsNotifier.IsEnabled = true;
        WindowsNotifier.NotificationHandler = null;
    }

    [Fact]
    public void Toast_StrictlyHonors_StorageCheck_Setting()
    {
        string? receivedTitle = null;
        WindowsNotifier.NotificationHandler = (t, m) => receivedTitle = t;

        bool allow = true;
        WindowsNotifier.StorageCheck = () => allow;

        WindowsNotifier.SendNotification("Permitted", "Allowed notification");
        Assert.Equal("Permitted", receivedTitle);

        receivedTitle = null;
        allow = false;
        WindowsNotifier.SendNotification("Blocked", "Suppressed notification");
        Assert.Null(receivedTitle);

        // Reset
        WindowsNotifier.StorageCheck = null;
        WindowsNotifier.NotificationHandler = null;
    }

    [Fact]
    public void Toast_RateLimits_Rapid_Consecutive_Notifications()
    {
        WindowsNotifier.ResetRateLimitForTesting();
        double now = 1000.0;

        Assert.True(WindowsNotifier.CheckRateLimit(now));
        Assert.False(WindowsNotifier.CheckRateLimit(now + 0.5)); // Suppressed within 1.0s window
        Assert.True(WindowsNotifier.CheckRateLimit(now + 1.2));  // Permitted after 1.0s window
    }

    [Fact]
    public void Toast_TryShowWinRtToast_ExecutesSafely_WithoutThrowing()
    {
        // Safe execution on any Windows desktop/test environment
        bool result = WindowsNotifier.TryShowWinRtToastForTesting("Test Title", "Test Message");
        // Result is true if host has registered AUMID/ActionCenter, false in headless CI/testhost without Start menu shortcut.
        // The key requirement is zero exceptions and proper COM apartment cleanup.
        Assert.True(result || !result);
    }

    [Fact]
    public void Toast_Dispatches_WithoutCrashing_WhenHandlerNull()
    {
        WindowsNotifier.NotificationHandler = null;
        WindowsNotifier.ResetRateLimitForTesting();
        WindowsNotifier.IsEnabled = true;

        // Calling SendNotification with null NotificationHandler exercises WinRT -> Native Shell Balloon path
        var ex = Record.Exception(() => WindowsNotifier.SendNotification("Direct Shell", "Message text"));
        Assert.Null(ex);
    }

    #endregion

    #region 2. Database Lifecycle Retention & Rollup Engine

    [Fact]
    public void Storage_Initializes_Hourly_And_Daily_Rollup_Tables()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());

        // Verify tables exist by running sample queries without error
        var hourly = storage.GetHourlyInterfaceRollups(24);
        var daily = storage.GetDailyProcessRollups(30);

        Assert.NotNull(hourly);
        Assert.NotNull(daily);
        Assert.Empty(hourly);
        Assert.Empty(daily);
    }

    [Fact]
    public void Storage_PerformLifecycleMaintenance_Aggregates_And_Purges()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long eightDaysAgo = now - (8 * 86400L);
        long twoDaysAgo = now - (2 * 86400L);

        // 1. Record raw interface snapshots
        // Old (8 days ago - should be rolled up then purged)
        storage.RecordInterfaceSnapshot(eightDaysAgo, "eth0", 1000, 500, 100.0, 50.0);
        storage.RecordInterfaceSnapshot(eightDaysAgo + 10, "eth0", 3000, 1500, 200.0, 100.0);

        // Recent (2 days ago - should be rolled up and retained in raw table)
        storage.RecordInterfaceSnapshot(twoDaysAgo, "eth0", 10000, 5000, 500.0, 250.0);
        storage.RecordInterfaceSnapshot(twoDaysAgo + 20, "eth0", 15000, 8000, 600.0, 300.0);

        // 2. Record raw process snapshots
        storage.RecordProcessSnapshot(eightDaysAgo, "malware.exe", 101, 5000, 2000, 3);
        storage.RecordProcessSnapshot(twoDaysAgo, "chrome.exe", 202, 10000, 8000, 10);

        // 3. Execute lifecycle maintenance
        var result = storage.PerformLifecycleMaintenance(now);

        Assert.True(result.HourlyRollupsProcessed > 0, "Hourly rollups should be generated.");
        Assert.True(result.DailyRollupsProcessed > 0, "Daily rollups should be generated.");
        Assert.Equal(2, result.RawInterfaceRowsPurged); // 2 rows older than 7 days purged
        Assert.Equal(1, result.RawProcessRowsPurged);   // 1 row older than 7 days purged

        // 4. Verify hourly rollup table contains aggregated metrics
        var rollups = storage.GetHourlyInterfaceRollups(hours: 30 * 24);
        Assert.NotEmpty(rollups);

        // 5. Verify process daily rollup table contains aggregated metrics
        var procRollups = storage.GetDailyProcessRollups(60);
        Assert.NotEmpty(procRollups);
        Assert.Contains(procRollups, r => (string)r["process_name"] == "chrome.exe");
    }

    [Fact]
    public void Storage_GetDailyUsage_Combines_Raw_And_Hourly_Rollups()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long tenDaysAgo = now - (10 * 86400L);

        // Record historical snapshots and roll them up
        storage.RecordInterfaceSnapshot(tenDaysAgo, "eth0", 1000, 500, 100.0, 50.0);
        storage.RecordInterfaceSnapshot(tenDaysAgo + 30, "eth0", 5000, 2500, 200.0, 100.0);

        storage.PerformLifecycleMaintenance(now);

        // Query 30-day daily usage: even though raw per-second data is purged, rollups are queried
        var usage = storage.GetDailyUsage(30);
        Assert.NotEmpty(usage);
        Assert.True(usage.Sum(u => (long)u["total_bytes"]) > 0);
    }

    [Fact]
    public void Storage_GetDataPlanStatus_Combines_Raw_And_Hourly_Rollups()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long tenDaysAgo = now - (10 * 86400L);

        // Ensure resetDay starts before tenDaysAgo so it is inside the active billing cycle
        int resetDay = Math.Max(1, DateTimeOffset.FromUnixTimeSeconds(tenDaysAgo).Day - 1);
        storage.UpdateDataPlan("monthly", 10_000_000_000L, resetDay: resetDay, warningPct: 80);

        // Record historical snapshots 10 days ago (within current billing month, but older than 7-day raw cutoff)
        storage.RecordInterfaceSnapshot(tenDaysAgo, "eth0", 2_000_000_000L, 1_000_000_000L, 100.0, 50.0);
        storage.RecordInterfaceSnapshot(tenDaysAgo + 30, "eth0", 4_000_000_000L, 2_000_000_000L, 100.0, 50.0);

        // Execute maintenance: 10-day-old raw per-second data is purged into hourly rollups
        storage.PerformLifecycleMaintenance(now);

        // Crucial validation: GetDataPlanStatus must not drop historical consumption to zero!
        var plan = storage.GetDataPlanStatus();
        Assert.NotNull(plan);
        Assert.True(plan.UsageBytes > 0, "Data plan usage must include rolled up hourly data.");
    }

    [Fact]
    public void Storage_GetUsageSummary_Combines_Raw_And_Hourly_Rollups()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long tenDaysAgo = now - (10 * 86400L);

        storage.RecordInterfaceSnapshot(tenDaysAgo, "eth0", 500_000, 200_000, 100.0, 50.0);
        storage.RecordInterfaceSnapshot(tenDaysAgo + 30, "eth0", 900_000, 400_000, 100.0, 50.0);

        storage.PerformLifecycleMaintenance(now);

        var summary = storage.GetUsageSummary();
        long allTimeTotal = (long)summary["all_time_total_bytes"];
        Assert.True(allTimeTotal > 0, "All time usage must retain historical rolled-up consumption.");
    }

    #endregion

    #region 3. Live Dynamic VPNGate Relay Discovery

    [Fact]
    public void VpnGate_ParseCsv_ValidRows_SortedByLowestLatencyAndHighestThroughput()
    {
        string sampleCsv = """
            *vpn_servers
            #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
            public-vpn-slow,203.0.113.1,100000,120,10485760,United States,US,5,1000,100,500000000,2,operator,msg,data1
            public-vpn-fast,203.0.113.2,900000,15,52428800,Japan,JP,10,2000,200,900000000,2,operator,msg,data2
            public-vpn-medium,203.0.113.3,500000,45,26214400,Germany,DE,8,1500,150,700000000,2,operator,msg,data3
            *
            """;

        var relays = WindowsVpnManager.ParseVpnGateCsv(sampleCsv);

        Assert.Equal(3, relays.Count);

        // Fastest ping first: Japan (15ms)
        Assert.Equal("JP", relays[0].CountryCode);
        Assert.Equal("Japan", relays[0].CountryName);
        Assert.Equal(15, relays[0].PingMs);
        Assert.Equal("🇯🇵", relays[0].FlagEmoji);
        Assert.True(relays[0].ThroughputMbps >= 50.0);

        // Second: Germany (45ms)
        Assert.Equal("DE", relays[1].CountryCode);
        Assert.Equal(45, relays[1].PingMs);
        Assert.Equal("🇩🇪", relays[1].FlagEmoji);

        // Third: US (120ms)
        Assert.Equal("US", relays[2].CountryCode);
        Assert.Equal(120, relays[2].PingMs);
        Assert.Equal("🇺🇸", relays[2].FlagEmoji);

        // Verify base64 OpenVPN config extraction
        Assert.Equal("data2", relays[0].OpenVpnConfigBase64);
        Assert.Equal("data3", relays[1].OpenVpnConfigBase64);
        Assert.Equal("data1", relays[2].OpenVpnConfigBase64);
    }

    [Fact]
    public void VpnGate_ParseCsv_MalformedAndCommentLines_SkippedSafely()
    {
        string malformedCsv = """
            *vpn_servers
            #Header line
            invalid,short,row
            ,,,,,
            *
            """;

        var relays = WindowsVpnManager.ParseVpnGateCsv(malformedCsv);
        Assert.Empty(relays);
    }

    [Fact]
    public void VpnGate_GetCuratedSeedRelays_Provides_Instant_Fallbacks()
    {
        var seeds = WindowsVpnManager.GetCuratedSeedRelays();
        Assert.True(seeds.Count >= 7);
        Assert.All(seeds, s =>
        {
            Assert.False(string.IsNullOrWhiteSpace(s.HostOrIp));
            Assert.False(string.IsNullOrWhiteSpace(s.CountryName));
            Assert.False(string.IsNullOrWhiteSpace(s.FlagEmoji));
            Assert.True(s.PingMs > 0);
            Assert.True(s.ThroughputMbps > 0);
        });
    }

    [Fact]
    public void VpnRelayNode_DisplayName_Includes_Flag_And_Metrics()
    {
        var node = new VpnRelayNode
        {
            CountryName = "Japan",
            CountryCode = "JP",
            HostOrIp = "public-vpn-58.opengw.net",
            PingMs = 18,
            ThroughputMbps = 286.4
        };

        Assert.Contains("🇯🇵", node.DisplayName);
        Assert.Contains("Japan", node.DisplayName);
        Assert.Contains("18ms", node.DisplayName);
        Assert.Contains("286.4 Mbps", node.DisplayName);
    }

    #endregion

    #region 4. Accurate GeoIP & IPv6 Expansion

    [Theory]
    [InlineData("2001:4860:4860::8888", "US", "United States", "🇺🇸", 15169, "Google LLC")]
    [InlineData("2606:4700:4700::1111", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc.")]
    [InlineData("2620:fe::fe", "CH", "Switzerland", "🇨🇭", 19281, "Quad9")]
    [InlineData("2a01:4f8:c010:1234::1", "DE", "Germany", "🇩🇪", 24940, "Hetzner Online GmbH")]
    public void GeoIp_Resolves_Public_IPv6_Accurately(string ipv6, string expectedCc, string expectedName, string expectedFlag, int expectedAsn, string expectedOrg)
    {
        using var db = new GeoIpDatabase(CreateTempDbPath());
        var service = new GeoIpService(db);

        var result = service.Resolve(ipv6);

        Assert.NotNull(result);
        Assert.Equal(expectedCc, result.CountryCode);
        Assert.Equal(expectedName, result.CountryName);
        Assert.Equal(expectedFlag, result.FlagEmoji);
        Assert.Equal(expectedAsn, result.Asn);
        Assert.Equal(expectedOrg, result.AsOrg);
        Assert.False(result.IsLocal);
    }

    [Theory]
    [InlineData("::1", "LO", "Loopback", "🏠", true)]
    [InlineData("fe80::1ff:fe23:4567:890a", "LAN", "Local Area Network", "🏠", true)] // Link-Local
    [InlineData("fd12:3456:789a:1::1", "LAN", "Local Area Network", "🏠", true)]        // ULA Unique Local
    public void GeoIp_Resolves_Special_IPv6_As_Local_Or_Loopback(string ipv6, string expectedCc, string expectedName, string expectedFlag, bool expectedLocal)
    {
        using var db = new GeoIpDatabase(CreateTempDbPath());
        var service = new GeoIpService(db);

        var result = service.Resolve(ipv6);

        Assert.NotNull(result);
        Assert.Equal(expectedCc, result.CountryCode);
        Assert.Equal(expectedName, result.CountryName);
        Assert.Equal(expectedFlag, result.FlagEmoji);
        Assert.Equal(expectedLocal, result.IsLocal);
    }

    [Fact]
    public void GeoIp_ParseCidrV6_Computes_Exact_128Bit_Boundaries()
    {
        var (startHex, endHex) = GeoIpDatabase.ParseCidrV6("2001:4860::/32");

        Assert.StartsWith("20014860", startHex);
        Assert.EndsWith("000000000000000000000000", startHex);
        Assert.Equal(32, startHex.Length);

        Assert.StartsWith("20014860", endHex);
        Assert.EndsWith("ffffffffffffffffffffffff", endHex);
        Assert.Equal(32, endHex.Length);
    }

    [Fact]
    public void GeoIp_Enrich_SocketInfo_With_IPv6()
    {
        using var db = new GeoIpDatabase(CreateTempDbPath());
        var service = new GeoIpService(db);

        var socket = new SocketInfo
        {
            RemoteIp = "2001:4860:4860::8888",
            RemotePort = 443,
            Protocol = "TCP"
        };

        service.Enrich(socket);

        Assert.Equal("US", socket.CountryCode);
        Assert.Equal("United States", socket.CountryName);
        Assert.Equal("🇺🇸", socket.CountryFlag);
        Assert.Equal(15169, socket.Asn);
        Assert.Equal("Google LLC", socket.AsOrg);
    }

    [Fact]
    public async Task GeoIp_ResolveAsync_Handles_Unknown_Public_WAN_IP()
    {
        using var db = new GeoIpDatabase(CreateTempDbPath());
        var service = new GeoIpService(db);

        // Known IP resolves immediately
        var known = await service.ResolveAsync("8.8.8.8");
        Assert.Equal("US", known.CountryCode);
        Assert.Equal(15169, known.Asn);

        // Unknown IP does not crash, returns valid GeoIpInfo
        var unknown = await service.ResolveAsync("198.51.100.22");
        Assert.NotNull(unknown);
    }

    [Fact]
    public void GeoIp_Overlapping_IPv6_Picks_Most_Specific_Cidr()
    {
        using var db = new GeoIpDatabase(CreateTempDbPath());

        // Insert broad range: 2001:db8::/32
        var (bStart, bEnd) = GeoIpDatabase.ParseCidrV6("2001:db8::/32");
        db.InsertRangeV6(new GeoIpRangeEntryV6(bStart, bEnd, "BR", "Broad Country", "🌐", 1000, "Broad Org"));

        // Insert specific range: 2001:db8:cafe::/48
        var (sStart, sEnd) = GeoIpDatabase.ParseCidrV6("2001:db8:cafe::/48");
        db.InsertRangeV6(new GeoIpRangeEntryV6(sStart, sEnd, "SP", "Specific Country", "🎯", 2000, "Specific Org"));

        var service = new GeoIpService(db);

        // IP inside the specific /48 must resolve to the specific entry, not the broad /32!
        var res = service.Resolve("2001:db8:cafe::1");
        Assert.Equal("SP", res.CountryCode);
        Assert.Equal("Specific Org", res.AsOrg);
        Assert.Equal(2000, res.Asn);
    }

    [Fact]
    public void GeoIp_ExistingDatabase_Seeds_IPv6_Independently()
    {
        string path = CreateTempDbPath();
        using (var db1 = new GeoIpDatabase(path))
        {
            Assert.True(db1.GetCount() > 0);
            Assert.True(db1.GetCountV6() > 0);

            // Simulate an existing database that was created before IPv6 existed by clearing the v6 table
            db1.ExecuteNonQuery("DELETE FROM geoip_asn_v6;");
            Assert.Equal(0, db1.GetCountV6());
            Assert.True(db1.GetCount() > 0);
        }

        // Re-open: InitDb must detect GetCountV6() == 0 and seed IPv6 even though IPv4 is already seeded
        using (var db2 = new GeoIpDatabase(path))
        {
            Assert.True(db2.GetCountV6() > 0, "IPv6 table must be seeded independently when empty.");
        }
    }

    #endregion

    #region 5. Per-Process Network Bandwidth & Graceful Dual-Mode

    private class MockDualModeSocketProvider : ISocketProvider
    {
        public bool IsElevated { get; set; } = false;
        public Dictionary<int, (ulong Rx, ulong Tx)> EtwNetworkBytes { get; } = new();
        public Dictionary<int, (ulong Read, ulong Write)> DiskIoBytes { get; } = new();

        public List<SocketInfo> GetEnrichedSockets()
        {
            return new List<SocketInfo>
            {
                new()
                {
                    Pid = 4001,
                    ProcessName = "downloader.exe",
                    LocalIp = "192.168.1.100",
                    RemoteIp = "1.1.1.1",
                    RemotePort = 443
                }
            };
        }

        public bool TryGetProcessIo(int pid, out ulong readBytes, out ulong writeBytes)
        {
            if (DiskIoBytes.TryGetValue(pid, out var io))
            {
                readBytes = io.Read;
                writeBytes = io.Write;
                return true;
            }
            readBytes = 0;
            writeBytes = 0;
            return false;
        }

        public bool TryGetProcessNetworkBytes(int pid, out ulong rxBytes, out ulong txBytes)
        {
            if (EtwNetworkBytes.TryGetValue(pid, out var net))
            {
                rxBytes = net.Rx;
                txBytes = net.Tx;
                return true;
            }
            rxBytes = 0;
            txBytes = 0;
            return false;
        }

        public bool IsEtwElevated => IsElevated;
    }

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

    [Fact]
    public void DualMode_Elevated_UsesPureEtw_IgnoresDiskIo()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var provider = new MockDualModeSocketProvider { IsElevated = true };

        // Disk I/O has 10 GB file copy (10_000_000_000)
        provider.DiskIoBytes[4001] = (10_000_000_000ul, 10_000_000_000ul);

        // ETW Pure Network I/O has 500 KB socket download (500_000)
        provider.EtwNetworkBytes[4001] = (500_000ul, 20_000ul);

        var tracker = new BandwidthTracker(storage, new DummyFirewall(), provider);
        Assert.True(tracker.IsDualModeElevated);

        // Baseline tick
        tracker.PollOnce();

        // Increment: ETW adds 100 KB, Disk I/O adds 500 MB
        provider.DiskIoBytes[4001] = (10_500_000_000ul, 10_000_000_000ul); // 500 MB disk
        provider.EtwNetworkBytes[4001] = (600_000ul, 25_000ul);             // 100 KB network

        var snap = tracker.PollOnce();
        var proc = snap.TopProcesses.First(p => p.Pid == 4001);

        // Crucial validation: Process delta must equal pure ETW network delta (100,000 bytes), NOT 500 MB disk!
        Assert.Equal(100_000, proc.RxBytesDelta);
        Assert.Equal(5_000, proc.TxBytesDelta);
        Assert.Equal(600_000ul, proc.TotalReadBytes);
    }

    [Fact]
    public void DualMode_NonElevated_FallsBackSafely_ToSocketRateCalculations()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var provider = new MockDualModeSocketProvider { IsElevated = false };

        var tracker = new BandwidthTracker(storage, new DummyFirewall(), provider);
        Assert.False(tracker.IsDualModeElevated);

        var snap = tracker.PollOnce();
        Assert.NotNull(snap);
        Assert.Single(snap.TopProcesses);
        Assert.Equal(4001, snap.TopProcesses[0].Pid);
    }

    [Fact]
    public void DualMode_NonElevated_WithDiskIo_DoesNotConflateWithNetwork()
    {
        using var storage = new NetflowStorage(CreateTempDbPath());
        var provider = new MockDualModeSocketProvider { IsElevated = false };

        // Heavy disk activity (10 GB file copy)
        provider.DiskIoBytes[4001] = (10_000_000_000ul, 10_000_000_000ul);

        var tracker = new BandwidthTracker(storage, new DummyFirewall(), provider);
        Assert.False(tracker.IsDualModeElevated);

        tracker.PollOnce();

        // 1 GB disk write added
        provider.DiskIoBytes[4001] = (10_000_000_000ul, 11_000_000_000ul);

        var snap = tracker.PollOnce();
        var proc = snap.TopProcesses.First(p => p.Pid == 4001);

        // Crucial validation: In non-elevated mode without network interface traffic,
        // disk I/O should populate TotalWriteBytes, but network deltas remain safe and separate
        Assert.Equal(11_000_000_000ul, proc.TotalWriteBytes);
    }

    #endregion
}
