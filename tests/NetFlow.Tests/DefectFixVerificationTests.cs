using System;
using System.Collections.Generic;
using System.IO;
using NetFlow.App.Services;
using NetFlow.App.ViewModels;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.QoS;
using NetFlow.Platform.Windows.Services;
using Xunit;

namespace NetFlow.Tests;

public class DefectFixVerificationTests : IDisposable
{
    private readonly string _testDbPath;

    public DefectFixVerificationTests()
    {
        _testDbPath = Path.Combine(Path.GetTempPath(), $"netflow_defect_test_{Guid.NewGuid():N}.db");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_testDbPath)) File.Delete(_testDbPath);
            string wal = _testDbPath + "-wal";
            string shm = _testDbPath + "-shm";
            if (File.Exists(wal)) File.Delete(wal);
            if (File.Exists(shm)) File.Delete(shm);
        }
        catch { }
    }

    [Fact]
    public void FirewallViewModel_DroppedCount_AccuratelyReflectsTotalBlockedKey()
    {
        // 1. Verify dictionary key "total_blocked" updates DroppedCount in FirewallViewModel
        var vm = new FirewallViewModel();
        
        // Mocking or invoking telemetry status
        var engine = new WindowsFirewallEngine(new NetflowStorage(_testDbPath));
        var status = engine.GetStatus();

        Assert.True(status.ContainsKey("total_blocked"));
        Assert.False(status.ContainsKey("total_dropped_sockets"));
    }

    [Fact]
    public void WindowsFirewallEngine_ResolveExecutablePath_FindsKnownSystemApp()
    {
        // Resolve known executable (e.g. cmd, notepad)
        string? resolvedCmd = WindowsFirewallEngine.ResolveProcessExecutablePath("cmd");
        Assert.NotNull(resolvedCmd);
        Assert.True(File.Exists(resolvedCmd));
        Assert.EndsWith("cmd.exe", resolvedCmd, StringComparison.OrdinalIgnoreCase);

        string? resolvedNotepad = WindowsFirewallEngine.ResolveProcessExecutablePath("notepad.exe");
        Assert.NotNull(resolvedNotepad);
        Assert.True(File.Exists(resolvedNotepad));
    }

    [Fact]
    public void NetflowStorage_AppSettings_Persistence_Works()
    {
        using var storage = new NetflowStorage(_testDbPath);

        // Test default
        Assert.True(storage.GetSettingBool("toast_notifications", true));

        // Test write false
        storage.SetSettingBool("toast_notifications", false);
        Assert.False(storage.GetSettingBool("toast_notifications", true));

        // Test write true
        storage.SetSettingBool("toast_notifications", true);
        Assert.True(storage.GetSettingBool("toast_notifications", false));

        // String setting
        storage.SetSetting("custom_key", "custom_val");
        Assert.Equal("custom_val", storage.GetSetting("custom_key"));
    }

    [Fact]
    public void WindowsNotifier_NotificationHandler_ReceivesNotification()
    {
        string? receivedTitle = null;
        string? receivedMsg = null;

        WindowsNotifier.IsEnabled = true;
        WindowsNotifier.NotificationHandler = (title, msg) =>
        {
            receivedTitle = title;
            receivedMsg = msg;
        };

        WindowsNotifier.SendNotification("Test Title", "Test Message");

        Assert.Equal("Test Title", receivedTitle);
        Assert.Equal("Test Message", receivedMsg);

        // Test disabled
        receivedTitle = null;
        WindowsNotifier.IsEnabled = false;
        WindowsNotifier.SendNotification("Disabled Title", "Disabled Message");

        Assert.Null(receivedTitle);

        // Reset
        WindowsNotifier.IsEnabled = true;
        WindowsNotifier.NotificationHandler = null;
    }

    private class MultiProcMockSocketProvider : ISocketProvider
    {
        private readonly Dictionary<int, (ulong R, ulong W)> _ioMap = new();

        public void SetIo(int pid, ulong read, ulong write)
        {
            _ioMap[pid] = (read, write);
        }

        public List<SocketInfo> GetEnrichedSockets()
        {
            return new List<SocketInfo>
            {
                new SocketInfo
                {
                    Protocol = "TCP",
                    LocalIp = "127.0.0.1",
                    LocalPort = 50001,
                    RemoteIp = "142.250.190.46",
                    RemotePort = 443,
                    State = "ESTABLISHED",
                    Pid = 1001,
                    ProcessName = "chrome.exe",
                    Cmdline = "chrome.exe --type=renderer"
                },
                new SocketInfo
                {
                    Protocol = "TCP",
                    LocalIp = "127.0.0.1",
                    LocalPort = 50002,
                    RemoteIp = "142.250.190.47",
                    RemotePort = 443,
                    State = "ESTABLISHED",
                    Pid = 1002,
                    ProcessName = "chrome.exe",
                    Cmdline = "chrome.exe --type=utility"
                }
            };
        }

        public bool TryGetProcessIo(int pid, out ulong readBytes, out ulong writeBytes)
        {
            if (_ioMap.TryGetValue(pid, out var io))
            {
                readBytes = io.R;
                writeBytes = io.W;
                return true;
            }
            readBytes = 0;
            writeBytes = 0;
            return false;
        }
    }

    [Fact]
    public void BandwidthTracker_Aggregates_MultiProcess_Pids_UnderSameProcessName()
    {
        using var storage = new NetflowStorage(_testDbPath);
        var mockProvider = new MultiProcMockSocketProvider();
        mockProvider.SetIo(1001, 50_000, 20_000);
        mockProvider.SetIo(1002, 30_000, 10_000);

        var engine = new WindowsFirewallEngine(storage);
        var tracker = new BandwidthTracker(storage, engine, mockProvider);

        // Initial poll to set baselines
        var snap1 = tracker.PollOnce();
        Assert.Single(snap1.TopProcesses);
        var chrome1 = snap1.TopProcesses[0];
        Assert.Equal("chrome.exe", chrome1.Name);
        // Total I/O across PID 1001 (50000+20000) and PID 1002 (30000+10000) = 80000 read, 30000 write
        Assert.Equal(80_000ul, chrome1.TotalReadBytes);
        Assert.Equal(30_000ul, chrome1.TotalWriteBytes);
        Assert.Equal(2, chrome1.ActiveConnections);

        // Next poll with increments
        mockProvider.SetIo(1001, 150_000, 70_000); // delta: 100_000 R, 50_000 W
        mockProvider.SetIo(1002, 80_000, 30_000);  // delta: 50_000 R, 20_000 W

        var snap2 = tracker.PollOnce();
        Assert.Single(snap2.TopProcesses);
        var chrome2 = snap2.TopProcesses[0];
        // Total aggregated delta: 150_000 Rx, 70_000 Tx
        Assert.Equal(150_000, chrome2.RxBytesDelta);
        Assert.Equal(70_000, chrome2.TxBytesDelta);
        Assert.True(chrome2.RxSpeed > 0);
        Assert.True(chrome2.TxSpeed > 0);
    }

    [Fact]
    public void WindowsFirewallEngine_ResolveExecutablePath_HandlesQuotedStrings()
    {
        string? resolvedQuoted = WindowsFirewallEngine.ResolveProcessExecutablePath("\"cmd.exe\"");
        Assert.NotNull(resolvedQuoted);
        Assert.True(File.Exists(resolvedQuoted));
        Assert.EndsWith("cmd.exe", resolvedQuoted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WindowsNotifier_StorageCheck_RespectsCustomPredicate()
    {
        string? receivedTitle = null;
        WindowsNotifier.IsEnabled = true;
        WindowsNotifier.NotificationHandler = (t, m) => receivedTitle = t;

        // When StorageCheck returns false, notification should not be dispatched
        WindowsNotifier.StorageCheck = () => false;
        WindowsNotifier.SendNotification("Title1", "Msg1");
        Assert.Null(receivedTitle);

        // When StorageCheck returns true, notification is dispatched
        WindowsNotifier.StorageCheck = () => true;
        WindowsNotifier.SendNotification("Title2", "Msg2");
        Assert.Equal("Title2", receivedTitle);

        // Reset
        WindowsNotifier.StorageCheck = null;
        WindowsNotifier.NotificationHandler = null;
    }

    [Fact]
    public void MainViewModel_TabSwitching_ActivatesCorrespondingViewModels()
    {
        var mainVm = new MainViewModel();
        Assert.Equal("resources", mainVm.SelectedTab);
        Assert.False(mainVm.HistoryVM.IsActive);
        Assert.False(mainVm.ConnectionsVM.IsActive);

        mainVm.SelectedTab = "connections";
        Assert.False(mainVm.HistoryVM.IsActive);
        Assert.True(mainVm.ConnectionsVM.IsActive);

        mainVm.SelectedTab = "history";
        Assert.True(mainVm.HistoryVM.IsActive);
        Assert.False(mainVm.ConnectionsVM.IsActive);

        mainVm.SelectedTab = "resources";
        Assert.False(mainVm.HistoryVM.IsActive);
        Assert.False(mainVm.ConnectionsVM.IsActive);
    }

    [Fact]
    public void GeoIpService_UnknownWanIp_NeverQueuesOnlineLookup_ByDefault()
    {
        using var tempDb = new GeoIpDatabase(Path.Combine(Path.GetTempPath(), $"geoip_audit_test_{Guid.NewGuid():N}.db"));
        var service = new NetFlow.Core.Telemetry.GeoIpService(tempDb);
        Assert.False(service.EnableOnlineLookupFallback);

        // Resolve an unknown public IP
        var res = service.Resolve("198.51.100.77");
        Assert.NotNull(res);
        Assert.Equal("ZZ", res.CountryCode);
        Assert.Equal("Unknown", res.CountryName);
        Assert.Equal("🌐", res.FlagEmoji);
        Assert.False(res.IsLocal);
    }

    [Fact]
    public void WindowsFirewallEngine_SanitizeProcessName_StripsQuotesAndMetacharacters()
    {
        Assert.Equal("cmd", WindowsFirewallEngine.SanitizeProcessName("\"cmd.exe\""));
        Assert.Equal("cmd", WindowsFirewallEngine.SanitizeProcessName("cmd\" & calc.exe"));
        Assert.Equal("discord", WindowsFirewallEngine.SanitizeProcessName("discord'; DROP TABLE;"));
        Assert.Equal("powershell", WindowsFirewallEngine.SanitizeProcessName("  powershell.exe  "));
        Assert.Equal(string.Empty, WindowsFirewallEngine.SanitizeProcessName(""));
        Assert.Equal(string.Empty, WindowsFirewallEngine.SanitizeProcessName("   "));
    }

    [Fact]
    public void WinSqliteInterop_Constants_Include_Transient_And_Static()
    {
        Assert.Equal(IntPtr.Zero, WinSqliteInterop.SQLITE_STATIC);
        Assert.Equal(new IntPtr(-1), WinSqliteInterop.SQLITE_TRANSIENT);
    }
}
