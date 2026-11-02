using System.Diagnostics;
using System.Net;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Defense;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.Native;
using Xunit;

namespace NetFlow.Tests;

public class ActiveDefenseTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly NetflowStorage _storage;
    private readonly WindowsFirewallEngine _firewallEngine;
    private readonly ActiveDefenseManager _defenseManager;

    public ActiveDefenseTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"netflow_defense_test_{Guid.NewGuid():N}.db");
        _storage = new NetflowStorage(_tempDbPath);
        _firewallEngine = new WindowsFirewallEngine(_storage);
        _defenseManager = new ActiveDefenseManager(_firewallEngine);
    }

    public void Dispose()
    {
        _storage.Dispose();
        try
        {
            if (File.Exists(_tempDbPath))
            {
                File.Delete(_tempDbPath);
            }
        }
        catch { }
    }

    [Fact]
    public void Kernel32_TerminateProcess_Rejects_InvalidAndKernelPids()
    {
        // PID 0 (System Idle)
        var res0 = Kernel32.TerminateProcessById(0);
        Assert.False(res0.Success);
        Assert.Equal(87, res0.Win32Error);

        // Negative PID
        var resNeg = Kernel32.TerminateProcessById(-5);
        Assert.False(resNeg.Success);
        Assert.Equal(87, resNeg.Win32Error);

        // PID 4 (Windows Kernel)
        var resKernel = Kernel32.TerminateProcessById(4);
        Assert.False(resKernel.Success);
        Assert.Equal(5, resKernel.Win32Error);
    }

    [Fact]
    public void Kernel32_TerminateProcess_Handles_NonExistentPid_Gracefully()
    {
        // Extremely high non-existent PID
        var res = Kernel32.TerminateProcessById(99999999);
        Assert.False(res.Success);
        Assert.NotEqual(0, res.Win32Error);
        Assert.NotNull(res.Error);
    }

    [Fact]
    public void Kernel32_TerminateProcess_Genuinely_Terminates_OwnChildProcess()
    {
        // Launch a harmless child process that sleeps
        var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1 >nul")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        };

        using var child = Process.Start(psi);
        Assert.NotNull(child);
        Assert.False(child.HasExited);

        try
        {
            // A standard user has full rights to terminate their own child processes
            var killResult = _defenseManager.KillProcess(child.Id, exitCode: 42);
            Assert.True(killResult.Success, $"Expected kill to succeed, got error: {killResult.Error}");
            Assert.False(killResult.ElevationRequired);

            // Verify the process actually terminated
            bool exited = child.WaitForExit(3000);
            Assert.True(exited, "Process should have exited after TerminateProcess");
        }
        finally
        {
            if (!child.HasExited)
            {
                try { child.Kill(); } catch { }
            }
        }
    }

    [Fact]
    public void IpHlpApi_SeverSockets_InvalidParameters_ReturnsZeroSevered()
    {
        // Invalid IP string should fail validation gracefully
        var (count1, err1) = IpHlpApi.SeverSockets("invalid.ip.format", 80);
        Assert.Equal(0, count1);

        // Non-existent PID
        var (count2, err2) = IpHlpApi.SeverSockets(pid: -99);
        Assert.Equal(0, count2);

        // Documentation test network address (TEST-NET-3)
        var (count3, err3) = IpHlpApi.SeverSockets(remoteIp: "203.0.113.210", remotePort: 54321);
        Assert.Equal(0, count3);

        // Backwards compatibility wrappers
        bool severed = IpHlpApi.SeverTcpConnection("203.0.113.210", 54321);
        Assert.False(severed);

        int pidCount = IpHlpApi.SeverSocketsByPid(-999);
        Assert.Equal(0, pidCount);
    }

    [Fact]
    public void WindowsFirewallEngine_GetIpRuleName_FormatsCorrectly()
    {
        string ruleName = WindowsFirewallEngine.GetIpRuleName("198.51.100.50");
        Assert.Equal("NetFlow_Block_IP_198.51.100.50", ruleName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("999.999.999.999")]
    [InlineData("192.168.1.1; rm -rf")]
    public void WindowsFirewallEngine_BlockAndUnblock_Rejects_InvalidIpFormats(string invalidIp)
    {
        var blockRes = _firewallEngine.BlockIp(invalidIp);
        Assert.False(blockRes.Success);
        Assert.Contains("Invalid IP address format", blockRes.Error ?? "");
        Assert.False(blockRes.ElevationRequired);

        var unblockRes = _firewallEngine.UnblockIp(invalidIp);
        Assert.False(unblockRes.Success);
        Assert.Contains("Invalid IP address format", unblockRes.Error ?? "");
        Assert.False(unblockRes.ElevationRequired);
    }

    [Theory]
    [InlineData("The requested operation requires elevation (Run as administrator).", "", true)]
    [InlineData("", "Access is denied.", true)]
    [InlineData("Run as administrator to configure firewall", "", true)]
    [InlineData("Ok.", "", false)]
    [InlineData("0 rule(s) deleted.", "", false)]
    public void WindowsFirewallEngine_IsElevationRequiredError_DetectsAccurately(string stdout, string stderr, bool expected)
    {
        bool detected = WindowsFirewallEngine.IsElevationRequiredError(stdout, stderr);
        Assert.Equal(expected, detected);
    }

    [Fact]
    public void ActiveDefenseManager_GetStatus_ReturnsValidStructure()
    {
        var status = _defenseManager.GetStatus();
        Assert.NotNull(status);
        Assert.Equal(status.IsAdmin, !status.ElevationRequired);
    }

    [Fact]
    public void ActiveDefenseManager_KillProcess_GuardsAgainstKernelPids()
    {
        var res0 = _defenseManager.KillProcess(0);
        Assert.False(res0.Success);
        Assert.Contains("Invalid process ID", res0.Error);
        Assert.False(res0.ElevationRequired);

        var res4 = _defenseManager.KillProcess(4);
        Assert.False(res4.Success);
        Assert.Contains("Cannot terminate critical system kernel process", res4.Error);
        Assert.False(res4.ElevationRequired);
    }

    [Fact]
    public void ActiveDefenseManager_KillProcess_GuardsAgainstHostProcessId()
    {
        var res = _defenseManager.KillProcess(Environment.ProcessId);
        Assert.False(res.Success);
        Assert.Equal("Cannot terminate NetFlow host process.", res.Error);
        Assert.Equal(87, res.Win32Error);
        Assert.False(res.ElevationRequired);
    }

    [Fact]
    public void ActiveDefenseManager_SeverConnection_HandlesNonExistentEndpoints()
    {
        var res = _defenseManager.SeverConnection("198.51.100.99", 4433);
        Assert.NotNull(res);
        Assert.Equal(0, res.SeveredCount);
        // Should succeed with 0 severed or degrade gracefully without throwing
        if (!res.Success)
        {
            Assert.True(res.ElevationRequired || res.Win32Error.HasValue);
        }
    }

    [Fact]
    public void ActiveDefenseManager_BlockAndUnblockIp_HandlesElevationGracefully()
    {
        string testIp = "198.51.100.123";

        // Block IP attempt
        var blockRes = _defenseManager.BlockIp(testIp, "Unit Test Rule");
        Assert.NotNull(blockRes);
        Assert.Equal(testIp, blockRes.Ip);

        if (!blockRes.Success)
        {
            // When not running as Administrator, elevation must be clearly flagged
            Assert.True(blockRes.ElevationRequired, "Non-elevated firewall block must indicate elevation_required: true");
            Assert.NotNull(blockRes.Error);
        }
        else
        {
            Assert.Equal($"NetFlow_Block_IP_{testIp}", blockRes.RuleName);
        }

        // Unblock IP attempt
        var unblockRes = _defenseManager.UnblockIp(testIp);
        Assert.NotNull(unblockRes);
        Assert.Equal(testIp, unblockRes.Ip);

        if (!unblockRes.Success)
        {
            Assert.True(unblockRes.ElevationRequired, "Non-elevated firewall unblock must indicate elevation_required: true");
            Assert.NotNull(unblockRes.Error);
        }
    }
}
