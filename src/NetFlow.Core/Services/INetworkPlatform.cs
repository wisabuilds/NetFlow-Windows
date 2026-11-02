using NetFlow.Core.Models;

namespace NetFlow.Core.Services;

public interface IFirewallEngine
{
    bool IsEnabled { get; }
    void LoadRules();
    bool ToggleFirewall(bool? enabled = null);
    string GetAppPolicy(string processName);
    bool IsAppBlocked(string processName);
    string SetAppPolicy(string processName, string policy);
    int ClearAllBlocks();
    Dictionary<string, object> GetStatus();
    List<Dictionary<string, object>> Enforce(List<SocketInfo> activeSockets, List<ProcessBandwidth> activeProcesses);
}

public interface ISocketProvider
{
    List<SocketInfo> GetEnrichedSockets();
    bool TryGetProcessIo(int pid, out ulong readBytes, out ulong writeBytes);
    bool TryGetProcessNetworkBytes(int pid, out ulong rxBytes, out ulong txBytes)
    {
        rxBytes = 0;
        txBytes = 0;
        return false;
    }
    bool IsEtwElevated => false;
}

public interface ISecurityScanner
{
    ThreatAssessment AssessProcess(int pid, string name, string path, List<SocketInfo>? sockets = null);
    (bool IsSigned, bool ChainVerified, string Publisher, string Status) CheckSignature(string exePath);
    List<ThreatAssessment> GetDetectedThreats(IEnumerable<ProcessBandwidth> processes);
}

public interface IQosManager
{
    List<QosPolicyInfo> GetActivePolicies();
    (bool Success, string Message) SetPolicy(string appExeName, int dscp, long throttleBytesPerSec = -1);
    (bool Success, string Message) RemovePolicy(string appExeName);
    (bool Success, string Message) ClearAllPolicies();
    (bool Success, string Message) SetProcessCpuPriority(int pid, string priorityLevel);
}

public interface IVpnManager
{
    VpnStatusInfo GetStatus();
    List<VpnRelayNode> GetRelayNodes();
    Task<(bool Success, string Message)> ConnectAsync(string hostOrIp, string protocol = "SSTP");
    (bool Success, string Message) Disconnect();
    Task<List<VpnRelayNode>> RefreshRelaysAsync(bool forceRefresh = false, CancellationToken ct = default)
    {
        return Task.FromResult(GetRelayNodes());
    }
}

public interface ITorManager
{
    TorStatusInfo GetStatus();
    (bool Success, string Message) EnableSystemProxy(int port = 9050);
    (bool Success, string Message) DisableSystemProxy();
}
