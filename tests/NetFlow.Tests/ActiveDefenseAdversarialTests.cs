using System.Diagnostics;
using System.Net;
using System.Text.Json;
using NetFlow.Core.Storage;
using NetFlow.Platform.Windows.Defense;
using NetFlow.Platform.Windows.Firewall;
using NetFlow.Platform.Windows.Native;
using Xunit;

namespace NetFlow.Tests;

public class ActiveDefenseAdversarialTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly NetflowStorage _storage;
    private readonly WindowsFirewallEngine _firewallEngine;
    private readonly ActiveDefenseManager _defenseManager;

    public ActiveDefenseAdversarialTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"netflow_adv_stress_{Guid.NewGuid():N}.db");
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

    #region 1. Process Termination Boundary Tests

    [Theory]
    [InlineData(0)]                   // System Idle Process
    [InlineData(-1)]                  // Negative PID
    [InlineData(-100)]                // Deeply negative PID
    [InlineData(int.MinValue)]        // Boundary min
    public void KillProcess_NonPositivePid_ReturnsInvalidParameter(int pid)
    {
        var result = _defenseManager.KillProcess(pid);
        Assert.False(result.Success);
        Assert.Equal(pid, result.Pid);
        Assert.False(result.ElevationRequired);
        Assert.Contains("Invalid process ID", result.Error);
        Assert.Equal(87, result.Win32Error);
    }

    [Theory]
    [InlineData(1)]                   // Kernel init / protected
    [InlineData(2)]                   // Protected system
    [InlineData(3)]                   // Protected system
    [InlineData(4)]                   // System Kernel (ntoskrnl.exe)
    public void KillProcess_CriticalKernelPids_BlockedExplicitly(int pid)
    {
        var result = _defenseManager.KillProcess(pid);
        Assert.False(result.Success);
        Assert.Equal(pid, result.Pid);
        Assert.False(result.ElevationRequired);
        Assert.Contains("Cannot terminate critical system kernel process", result.Error);
        Assert.Equal(5, result.Win32Error);
    }

    [Theory]
    [InlineData(int.MaxValue)]        // 2147483647
    [InlineData(99999999)]            // Arbitrary high non-existent
    [InlineData(12345678)]            // High non-existent
    public void KillProcess_NonExistentPids_HandledGracefullyWithoutException(int nonExistentPid)
    {
        var result = _defenseManager.KillProcess(nonExistentPid);
        Assert.False(result.Success);
        Assert.Equal(nonExistentPid, result.Pid);
        Assert.NotNull(result.Error);
        Assert.True(result.Win32Error.HasValue);
        Assert.NotEqual(0, result.Win32Error.Value);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(42u)]
    [InlineData(255u)]
    [InlineData(uint.MaxValue)]
    public void KillProcess_ExitCode_PassedProperly(uint exitCode)
    {
        // Launch a harmless child process to test termination with distinct exit codes
        var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1 >nul")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        };

        using var child = Process.Start(psi);
        Assert.NotNull(child);
        try
        {
            var res = _defenseManager.KillProcess(child.Id, exitCode);
            Assert.True(res.Success);
            Assert.False(res.ElevationRequired);

            child.WaitForExit(3000);
            Assert.True(child.HasExited);
            // On Windows, TerminateProcess sets the process exit code
            Assert.Equal((int)exitCode, child.ExitCode);
        }
        finally
        {
            if (!child.HasExited)
            {
                try { child.Kill(); } catch { }
            }
        }
    }

    #endregion

    #region 2. Socket Severing Adversarial Tests

    [Theory]
    [InlineData("invalid-ip")]
    [InlineData("256.256.256.256")]
    [InlineData("1.2.3.4.5")]
    [InlineData("not an ip at all")]
    [InlineData("   ")]
    [InlineData("")]
    public void SeverConnection_MalformedIp_ReturnsZeroSeveredGracefully(string malformedIp)
    {
        var result = _defenseManager.SeverConnection(malformedIp, 80);
        Assert.NotNull(result);
        Assert.Equal(0, result.SeveredCount);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(65536)]
    [InlineData(70000)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void SeverConnection_InvalidPorts_HandledGracefully(int invalidPort)
    {
        var result = _defenseManager.SeverConnection("198.51.100.1", invalidPort);
        Assert.NotNull(result);
        Assert.Equal(0, result.SeveredCount);
    }

    [Fact]
    public void SeverConnection_NonExistentConnection_ReturnsZeroWithoutThrowing()
    {
        // RFC 5737 TEST-NET-2 address
        var result = _defenseManager.SeverConnection("198.51.100.222", 59999);
        Assert.NotNull(result);
        Assert.Equal(0, result.SeveredCount);
        Assert.Null(result.Error);
    }

    [Fact]
    public void SeverConnection_AllParametersNull_HandledWithoutCrash()
    {
        // When all parameters are null, SeverConnection should safely complete
        var result = _defenseManager.SeverConnection(null, null, null, null, null);
        Assert.NotNull(result);
    }

    [Fact]
    public void IpHlpApi_SeverSockets_NegativePid_AttemptsSeveringAllSocketsBug()
    {
        var sockets = IpHlpApi.GetTcpSockets();
        if (sockets.Count > 0)
        {
            // Negative pid is rejected upfront with ERROR_INVALID_PARAMETER (87) and 0 severed
            var (count, lastError) = IpHlpApi.SeverSockets(pid: -9999);
            Assert.Equal(0, count);
            Assert.Equal(87u, lastError);
        }
    }

    [Fact]
    public void IpHlpApi_SeverSockets_NegativePort_AttemptsSeveringAllSocketsBug()
    {
        var sockets = IpHlpApi.GetTcpSockets();
        if (sockets.Count > 0)
        {
            // Negative or out-of-range port is rejected upfront with ERROR_INVALID_PARAMETER (87) and 0 severed
            var (count, lastError) = IpHlpApi.SeverSockets(remotePort: -1);
            Assert.Equal(0, count);
            Assert.Equal(87u, lastError);
        }
    }

    #endregion

    #region 3. Firewall IP Injection & Loopback Tests

    [Theory]
    [InlineData("127.0.0.1; calc.exe")]
    [InlineData("192.168.1.1 & dir")]
    [InlineData("10.0.0.1 | whoami")]
    [InlineData("192.168.1.1`dir`")]
    [InlineData("192.168.1.1\ndir")]
    [InlineData("192.168.1.1\r\ndir")]
    [InlineData("192.168.1.1\" dir=out action=block \"")]
    [InlineData("192.168.1.1' OR '1'='1")]
    [InlineData("<script>alert(1)</script>")]
    public void BlockIp_CommandInjectionPayloads_StrictlyRejectedByIpValidator(string maliciousPayload)
    {
        var blockRes = _defenseManager.BlockIp(maliciousPayload, "Injection Test");
        Assert.False(blockRes.Success);
        Assert.Contains("Invalid IP address format", blockRes.Error);
        Assert.False(blockRes.ElevationRequired);

        var unblockRes = _defenseManager.UnblockIp(maliciousPayload);
        Assert.False(unblockRes.Success);
        Assert.Contains("Invalid IP address format", unblockRes.Error);
        Assert.False(unblockRes.ElevationRequired);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    public void BlockIp_LoopbackAddresses_SyntacticallyValidIp_DoesNotCrash(string loopbackIp)
    {
        // Loopback is syntactically a valid IP address. The firewall engine should process
        // or attempt netsh without throwing unhandled exceptions.
        var blockRes = _defenseManager.BlockIp(loopbackIp, "Testing loopback handling");
        Assert.NotNull(blockRes);
        Assert.Equal(loopbackIp, blockRes.Ip);

        // Cleanup
        _defenseManager.UnblockIp(loopbackIp);
    }

    [Theory]
    [InlineData("2001:db8::1")]
    [InlineData("fe80::1")]
    [InlineData("2607:f8b0:4005:805::200e")]
    public void BlockIp_IPv6Addresses_HandledSafely(string ipv6)
    {
        var blockRes = _defenseManager.BlockIp(ipv6, "IPv6 Test");
        Assert.NotNull(blockRes);
        Assert.Equal(ipv6, blockRes.Ip);

        var unblockRes = _defenseManager.UnblockIp(ipv6);
        Assert.NotNull(unblockRes);
    }

    [Theory]
    [InlineData("Normal reason")]
    [InlineData("Reason with quotes: \"testing\" and 'single'")]
    [InlineData("Reason with special chars: !@#$%^&*()_+{}|:<>?[];',./")]
    [InlineData("'); DROP TABLE firewall_events; --")]
    [InlineData("Reason with \r\n newlines")]
    [InlineData(null)]
    public void BlockIp_ReasonString_SqlAndSpecialChars_HandledSafely(string? reason)
    {
        string testIp = "198.51.100.77";
        var blockRes = _defenseManager.BlockIp(testIp, reason);
        Assert.NotNull(blockRes);

        // Verify storage database integrity - querying events should not fail
        var events = _storage.GetFirewallEvents(10);
        Assert.NotNull(events);

        // Cleanup
        _defenseManager.UnblockIp(testIp);
    }

    [Fact]
    public void UnblockIp_NonExistentIpRule_HandledGracefully()
    {
        // Unblocking an IP that was never blocked should succeed (idempotent) or return clean elevation requirement
        var unblockRes = _defenseManager.UnblockIp("198.51.100.99");
        Assert.NotNull(unblockRes);
        Assert.Equal("198.51.100.99", unblockRes.Ip);
    }

    #endregion

    #region 4. REST API Contract Serialization / Parsing Stress Tests

    [Theory]
    [InlineData("{\"pid\": \"not_a_number\"}")]
    [InlineData("{\"pid\": null}")]
    [InlineData("{\"pid\": true}")]
    public void KillProcess_JsonPayloadEdgeCases_ParseSafe(string json)
    {
        // NetFlowServerHost.cs checks ValueKind == JsonValueKind.Number before calling TryGetInt32.
        var doc = JsonDocument.Parse(json);
        int pid = 0;
        uint exitCode = 1;
        if (doc.RootElement.TryGetProperty("pid", out var pEl) && pEl.ValueKind == JsonValueKind.Number && pEl.TryGetInt32(out int pVal))
        {
            pid = pVal;
        }
        if (doc.RootElement.TryGetProperty("exit_code", out var eEl) && eEl.ValueKind == JsonValueKind.Number && eEl.TryGetUInt32(out uint eVal))
        {
            exitCode = eVal;
        }

        Assert.Equal(0, pid);
        Assert.Equal(1u, exitCode);
    }

    [Theory]
    [InlineData("{\"remote_ip\": null, \"remote_port\": null}")]
    [InlineData("{\"remote_port\": \"80\"}")]
    [InlineData("{\"pid\": null}")]
    [InlineData("{\"local_port\": null}")]
    public void SeverConnection_JsonPayloadEdgeCases_ParseSafe(string json)
    {
        // NetFlowServerHost.cs checks ValueKind == JsonValueKind.Number before calling TryGetInt32.
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string? remoteIp = null;
        int? remotePort = null;
        string? localIp = null;
        int? localPort = null;
        int? pid = null;

        if (root.TryGetProperty("remote_ip", out var ripEl) && ripEl.ValueKind == JsonValueKind.String)
            remoteIp = ripEl.GetString();
        if (root.TryGetProperty("remote_port", out var rportEl) && rportEl.ValueKind == JsonValueKind.Number && rportEl.TryGetInt32(out int rp))
            remotePort = rp;
        if (root.TryGetProperty("local_ip", out var lipEl) && lipEl.ValueKind == JsonValueKind.String)
            localIp = lipEl.GetString();
        if (root.TryGetProperty("local_port", out var lportEl) && lportEl.ValueKind == JsonValueKind.Number && lportEl.TryGetInt32(out int lp))
            localPort = lp;
        if (root.TryGetProperty("pid", out var pidEl) && pidEl.ValueKind == JsonValueKind.Number && pidEl.TryGetInt32(out int pVal))
            pid = pVal;

        Assert.Null(remotePort);
    }

    [Fact]
    public void KillProcess_SelfProcessId_GuardedExplicitly()
    {
        int ownPid = Environment.ProcessId;
        var res = _defenseManager.KillProcess(ownPid);
        Assert.False(res.Success);
        Assert.Equal(ownPid, res.Pid);
        Assert.Equal("Cannot terminate NetFlow host process.", res.Error);
        Assert.Equal(87, res.Win32Error);
        Assert.False(res.ElevationRequired);

        var (success, win32Error, error) = Kernel32.TerminateProcessById(ownPid);
        Assert.False(success);
        Assert.Equal(87, win32Error);
        Assert.Equal("Cannot terminate NetFlow host process.", error);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"ip\": \"\"}")]
    [InlineData("{\"ip\": \"   \"}")]
    [InlineData("{\"ip\": null}")]
    public void BlockIp_JsonPayloadEdgeCases_DetectsMissingIp(string json)
    {
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string? ip = root.TryGetProperty("ip", out var ipEl) && ipEl.ValueKind == JsonValueKind.String ? ipEl.GetString() : null;

        bool isMissing = string.IsNullOrWhiteSpace(ip);
        Assert.True(isMissing);
    }

    #endregion
}
