namespace NetFlow.Core.Models;

public record InterfaceStats(
    string Name,
    long RxBytes,
    long RxPackets,
    long RxErrors,
    long RxDrops,
    long TxBytes,
    long TxPackets,
    long TxErrors,
    long TxDrops
);

public record InterfaceSnapshot(
    string Name,
    double RxSpeed,
    double TxSpeed,
    long RxBytes,
    long TxBytes,
    long RxPackets,
    long TxPackets
);

public enum RiskLevel
{
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public class ThreatAssessment
{
    public RiskLevel Level { get; set; } = RiskLevel.Safe;
    public bool IsCriticalOS { get; set; }
    public bool IsSigned { get; set; }
    public bool ChainVerified { get; set; }
    public string Publisher { get; set; } = "Unknown";
    public string StatusMessage { get; set; } = "OK";
    public List<string> Flags { get; set; } = new();
}

public class ProcessBandwidth
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string Cmdline { get; set; } = "";
    public string? ExePath { get; set; }
    public int ActiveConnections { get; set; }
    public List<string> RemoteEndpoints { get; set; } = new();
    public List<GeoIpInfo> RemoteGeoIp { get; set; } = new();
    public long RxBytesDelta { get; set; }
    public long TxBytesDelta { get; set; }
    public double RxSpeed { get; set; }
    public double TxSpeed { get; set; }
    public ulong TotalReadBytes { get; set; }
    public ulong TotalWriteBytes { get; set; }
    public double TransferRateKbps { get; set; }
    public ThreatAssessment? Threat { get; set; }
}

public class RealtimeSnapshot
{
    public double Timestamp { get; set; }
    public double TotalRxSpeed { get; set; }
    public double TotalTxSpeed { get; set; }
    public long TotalRxBytes { get; set; }
    public long TotalTxBytes { get; set; }
    public double PeakRxSpeed { get; set; }
    public double PeakTxSpeed { get; set; }
    public Dictionary<string, InterfaceSnapshot> Interfaces { get; set; } = new();
    public List<ProcessBandwidth> TopProcesses { get; set; } = new();
    public int ActiveSocketCount { get; set; }
    public double? PingLatencyMs { get; set; }
    public int HighRiskCount { get; set; }
}

public class DataPlanStatus
{
    public string Period { get; set; } = "monthly";
    public long? LimitBytes { get; set; }
    public int ResetDay { get; set; } = 1;
    public int WarningPct { get; set; } = 80;
    public long UsageBytes { get; set; }
    public double PercentUsed { get; set; }
    public bool IsWarning { get; set; }
    public bool IsExceeded { get; set; }
    public double PeriodStart { get; set; }
    public double PeriodEnd { get; set; }
    public double RemainingDays { get; set; }
    public long? RemainingBytes { get; set; }

    public string UsedBytesHuman => FormatBytes(UsageBytes);
    public string LimitBytesHuman => LimitBytes.HasValue ? FormatBytes(LimitBytes.Value) : "Unlimited";

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }
}

public class BudgetForecast
{
    public bool Configured { get; set; }
    public long LimitBytes { get; set; }
    public long UsedBytes { get; set; }
    public long RemainingBytes { get; set; }
    public double DaysElapsed { get; set; }
    public double DaysRemaining { get; set; }
    public long AvgDailyBytes { get; set; }
    public long RecommendedDailyBudgetBytes { get; set; }
    public long ProjectedTotalBytes { get; set; }
    public double ProjectedPercentage { get; set; }
    public string BurnStatus { get; set; } = "unconfigured";
    public string EstimatedExhaustionDate { get; set; } = "Within Limit";
    public string Period { get; set; } = "monthly";
}

public record FirewallRule(string ProcessName, bool Blocked, string Policy, double UpdatedAt);

public record FirewallEvent(long Id, double Timestamp, string ProcessName, int? Pid, string RemoteEndpoint, string Action);

public enum DscpTier
{
    ExpeditedForwarding46 = 46, // Gaming / Real-time VoIP
    AssuredForwarding34 = 34,   // Streaming / Video
    BestEffort0 = 0,            // Normal
    Background8 = 8             // Low priority
}

public class QosPolicyInfo
{
    public string RuleName { get; set; } = "";
    public string ApplicationName { get; set; } = "";
    public int Dscp { get; set; } = 46;
    public long ThrottleBytesPerSec { get; set; } = -1;
    public string Protocol { get; set; } = "*";
    public string DscpDisplay => Dscp switch
    {
        46 => "EF 46 (Gaming/Real-Time)",
        34 => "AF41 (Streaming)",
        8 => "CS1 (Background)",
        _ => "Default 0 (Normal)"
    };
}

public class VpnRelayNode
{
    public string CountryName { get; set; } = "Unknown";
    public string CountryCode { get; set; } = "UN";
    public string HostOrIp { get; set; } = "";
    public int PingMs { get; set; } = 999;
    public double ThroughputMbps { get; set; }
    public string Protocol { get; set; } = "SSTP";
    public long Score { get; set; }
    public bool IsCurated { get; set; }
    public string? OpenVpnConfigBase64 { get; set; }
    public string FlagEmoji => GetFlagEmoji(CountryCode);
    public string DisplayName => $"{FlagEmoji} {CountryName} - {PingMs}ms ({ThroughputMbps:F1} Mbps)";
    public override string ToString() => DisplayName;

    public static string GetFlagEmoji(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || countryCode.Length != 2) return "🌐";
        char c1 = char.ToUpperInvariant(countryCode[0]);
        char c2 = char.ToUpperInvariant(countryCode[1]);
        if (c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z') return "🌐";
        int first = 0x1F1E6 + (c1 - 'A');
        int second = 0x1F1E6 + (c2 - 'A');
        return char.ConvertFromUtf32(first) + char.ConvertFromUtf32(second);
    }
}

public class VpnStatusInfo
{
    public string State { get; set; } = "Disconnected";
    public string? ActiveServer { get; set; }
    public string? Country { get; set; }
    public double? ConnectedSeconds { get; set; }
    public string? LastError { get; set; }
}

public class TorStatusInfo
{
    public bool IsTorListening { get; set; }
    public int ActivePort { get; set; } = 9050;
    public bool IsSystemProxyEnabled { get; set; }
}
