using NetFlow.Core.Models;
using NetFlow.Platform.Windows.QoS;
using NetFlow.Platform.Windows.Security;
using NetFlow.Platform.Windows.Tor;
using NetFlow.Platform.Windows.Vpn;

namespace NetFlow.Tests;

public class AdoptedFeaturesTests
{
    [Fact]
    public void SecurityScanner_Correctly_Identifies_Critical_Kernel_Process()
    {
        var scanner = new WindowsSecurityScanner();
        var assessment = scanner.AssessProcess(4, "System", "ntoskrnl.exe");

        Assert.Equal(RiskLevel.Safe, assessment.Level);
        Assert.True(assessment.IsCriticalOS);
        Assert.True(assessment.IsSigned);
        Assert.Contains("Microsoft Windows", assessment.Publisher);
    }

    [Fact]
    public void SecurityScanner_Flags_Masquerading_System_Process()
    {
        var scanner = new WindowsSecurityScanner();
        // A process claiming to be svchost.exe but running out of temp directory
        var assessment = scanner.AssessProcess(9999, "svchost.exe", @"C:\Users\AppData\Local\Temp\svchost.exe");

        Assert.Equal(RiskLevel.High, assessment.Level);
        Assert.Contains(assessment.Flags, f => f.Contains("Masquerading"));
    }

    [Fact]
    public void SecurityScanner_Flags_Suspicious_Port()
    {
        var scanner = new WindowsSecurityScanner();
        var sockets = new List<SocketInfo>
        {
            new() { RemoteIp = "185.190.140.2", RemotePort = 4444, State = "ESTABLISHED" }
        };

        var assessment = scanner.AssessProcess(12345, "miner.exe", @"C:\Games\miner.exe", sockets);

        Assert.Equal(RiskLevel.High, assessment.Level);
        Assert.Contains(assessment.Flags, f => f.Contains("Metasploit") || f.Contains("4444"));
    }

    [Fact]
    public void QosManager_Reads_Policies_Or_Returns_List()
    {
        var qos = new WindowsQosManager();
        var policies = qos.GetActivePolicies();

        Assert.NotNull(policies);
    }

    [Fact]
    public void VpnManager_Retrieves_Curated_Relays()
    {
        var vpn = new WindowsVpnManager();
        var relays = vpn.GetRelayNodes();

        Assert.NotEmpty(relays);
        Assert.Contains(relays, r => r.CountryCode == "JP");
        Assert.Contains(relays, r => r.Protocol == "SSTP");
    }

    [Fact]
    public void TorManager_Returns_Valid_Status()
    {
        var tor = new WindowsTorManager();
        var status = tor.GetStatus();

        Assert.NotNull(status);
        Assert.True(status.ActivePort is 9050 or 9150);
    }
}
