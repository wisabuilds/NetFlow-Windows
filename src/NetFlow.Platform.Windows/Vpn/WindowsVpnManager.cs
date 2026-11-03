using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Text;
using NetFlow.Core.Models;
using NetFlow.Core.Services;

namespace NetFlow.Platform.Windows.Vpn;

public class WindowsVpnManager : IVpnManager
{
    private const string ENTRY_NAME = "NetFlow_SSTP_VPN";
    private const string VPNGATE_API_URL = "https://www.vpngate.net/api/iphone/";
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };

    private readonly object _lock = new();
    private string _state = "Disconnected";
    private string? _activeServer;
    private string? _activeCountry;
    private DateTime? _connectedAt;
    private string? _lastError;
    private readonly string _pbkPath;
    private readonly string _cachePath;

    private List<VpnRelayNode> _cachedRelays = new();
    private DateTime _lastFetchTime = DateTime.MinValue;

    public WindowsVpnManager()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string netflowDir = Path.Combine(appData, "NetFlow");
        if (!Directory.Exists(netflowDir))
        {
            try { Directory.CreateDirectory(netflowDir); } catch { }
        }

        _pbkPath = Path.Combine(netflowDir, "rasphone.pbk");
        _cachePath = Path.Combine(netflowDir, "vpngate_cache.csv");

        // 1. Try loading cached relays from disk
        LoadFromDiskCache();

        // 2. If empty, seed with initial curated fallbacks
        if (_cachedRelays.Count == 0)
        {
            _cachedRelays = GetCuratedSeedRelays();
        }

        _lastFetchTime = DateTime.UtcNow;
    }

    public VpnStatusInfo GetStatus()
    {
        lock (_lock)
        {
            double? connectedSec = _connectedAt.HasValue
                ? (DateTime.UtcNow - _connectedAt.Value).TotalSeconds
                : null;

            return new VpnStatusInfo
            {
                State = _state,
                ActiveServer = _activeServer,
                Country = _activeCountry,
                ConnectedSeconds = connectedSec,
                LastError = _lastError
            };
        }
    }

    public List<VpnRelayNode> GetRelayNodes()
    {
        lock (_lock)
        {
            return new List<VpnRelayNode>(_cachedRelays);
        }
    }

    public async Task<List<VpnRelayNode>> RefreshRelaysAsync(bool forceRefresh = false, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (!forceRefresh && (DateTime.UtcNow - _lastFetchTime).TotalHours < 2 && _cachedRelays.Count > 0)
            {
                return new List<VpnRelayNode>(_cachedRelays);
            }
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, VPNGATE_API_URL);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetFlow/2.0");

            using var resp = await _httpClient.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                string csv = await resp.Content.ReadAsStringAsync(ct);
                var parsed = ParseVpnGateCsv(csv);
                if (parsed.Count > 0)
                {
                    lock (_lock)
                    {
                        _cachedRelays = parsed;
                        _lastFetchTime = DateTime.UtcNow;
                    }

                    try
                    {
                        File.WriteAllText(_cachePath, csv, Encoding.UTF8);
                    }
                    catch { }

                    return GetRelayNodes();
                }
            }
        }
        catch
        {
            // Fall back to existing cached relays or curated seed nodes if network query fails
        }

        return GetRelayNodes();
    }

    public static List<VpnRelayNode> ParseVpnGateCsv(string csvContent)
    {
        var list = new List<VpnRelayNode>();
        if (string.IsNullOrWhiteSpace(csvContent)) return list;

        using var reader = new StringReader(csvContent);
        string? line;

        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.StartsWith("*") || line.StartsWith("#") || string.IsNullOrEmpty(line))
            {
                continue;
            }

            // CSV Columns:
            // 0: HostName, 1: IP, 2: Score, 3: Ping, 4: Speed, 5: CountryLong, 6: CountryShort, 7: NumVpnSessions, 8: Uptime, ...
            var parts = line.Split(',');
            if (parts.Length < 7) continue;

            string host = parts[0].Trim();
            string ip = parts[1].Trim();
            string scoreStr = parts[2].Trim();
            string pingStr = parts[3].Trim();
            string speedStr = parts[4].Trim();
            string countryLong = parts[5].Trim();
            string countryShort = parts[6].Trim();

            if (string.IsNullOrWhiteSpace(host) && string.IsNullOrWhiteSpace(ip)) continue;

            long.TryParse(scoreStr, NumberStyles.Any, CultureInfo.InvariantCulture, out long score);
            int.TryParse(pingStr, NumberStyles.Any, CultureInfo.InvariantCulture, out int ping);
            long.TryParse(speedStr, NumberStyles.Any, CultureInfo.InvariantCulture, out long speedBytes);

            // Calculate Throughput in Mbps (Speed in bytes/sec * 8 / 1,000,000)
            double throughputMbps = Math.Round(speedBytes / (1024.0 * 1024.0), 1);
            if (ping <= 0) ping = 999;

            string targetHost = !string.IsNullOrEmpty(host) ? $"{host}.opengw.net" : ip;
            if (host.EndsWith(".opengw.net", StringComparison.OrdinalIgnoreCase))
            {
                targetHost = host;
            }

            string? openVpnBase64 = parts.Length > 14 ? parts[^1].Trim() : null;

            list.Add(new VpnRelayNode
            {
                CountryName = !string.IsNullOrEmpty(countryLong) ? countryLong : "Unknown",
                CountryCode = !string.IsNullOrEmpty(countryShort) ? countryShort.ToUpperInvariant() : "UN",
                HostOrIp = targetHost,
                PingMs = ping,
                ThroughputMbps = throughputMbps,
                Protocol = "SSTP",
                Score = score,
                IsCurated = false,
                OpenVpnConfigBase64 = openVpnBase64
            });
        }

        // Sort by lowest latency (PingMs ascending) and highest throughput (ThroughputMbps descending)
        return list
            .OrderBy(n => n.PingMs)
            .ThenByDescending(n => n.ThroughputMbps)
            .Take(40)
            .ToList();
    }

    private void LoadFromDiskCache()
    {
        try
        {
            if (File.Exists(_cachePath))
            {
                string csv = File.ReadAllText(_cachePath, Encoding.UTF8);
                var parsed = ParseVpnGateCsv(csv);
                if (parsed.Count > 0)
                {
                    _cachedRelays = parsed;
                    _lastFetchTime = File.GetLastWriteTimeUtc(_cachePath);
                }
            }
        }
        catch { }
    }

    public static List<VpnRelayNode> GetCuratedSeedRelays()
    {
        return new List<VpnRelayNode>
        {
            new() { CountryName = "Japan", CountryCode = "JP", HostOrIp = "public-vpn-58.opengw.net", PingMs = 18, ThroughputMbps = 286.4, Protocol = "SSTP", Score = 980000, IsCurated = true },
            new() { CountryName = "Japan", CountryCode = "JP", HostOrIp = "public-vpn-55.opengw.net", PingMs = 22, ThroughputMbps = 156.2, Protocol = "SSTP", Score = 970000, IsCurated = true },
            new() { CountryName = "Japan", CountryCode = "JP", HostOrIp = "public-vpn-161.opengw.net", PingMs = 25, ThroughputMbps = 131.6, Protocol = "SSTP", Score = 960000, IsCurated = true },
            new() { CountryName = "United States", CountryCode = "US", HostOrIp = "public-vpn-90.opengw.net", PingMs = 45, ThroughputMbps = 110.0, Protocol = "SSTP", Score = 920000, IsCurated = true },
            new() { CountryName = "United States", CountryCode = "US", HostOrIp = "public-vpn-112.opengw.net", PingMs = 52, ThroughputMbps = 95.5, Protocol = "SSTP", Score = 910000, IsCurated = true },
            new() { CountryName = "Germany", CountryCode = "DE", HostOrIp = "public-vpn-148.opengw.net", PingMs = 35, ThroughputMbps = 132.8, Protocol = "SSTP", Score = 950000, IsCurated = true },
            new() { CountryName = "Korea", CountryCode = "KR", HostOrIp = "public-vpn-43.opengw.net", PingMs = 28, ThroughputMbps = 116.2, Protocol = "SSTP", Score = 930000, IsCurated = true }
        };
    }

    public async Task<(bool Success, string Message)> ConnectAsync(string hostOrIp, string protocol = "SSTP")
    {
        if (string.IsNullOrWhiteSpace(hostOrIp))
        {
            return (false, "Invalid host or IP address.");
        }

        lock (_lock)
        {
            _state = "Connecting";
            _activeServer = hostOrIp;
            _lastError = null;
        }

        try
        {
            // 1. Generate / Write PBK entry
            var node = GetRelayNodes().FirstOrDefault(n => n.HostOrIp.Equals(hostOrIp, StringComparison.OrdinalIgnoreCase))
                ?? new VpnRelayNode { HostOrIp = hostOrIp, Protocol = protocol };

            lock (_lock)
            {
                _activeCountry = node.CountryName;
            }

            GeneratePhonebook(_pbkPath, node);

            // 2. Disconnect existing if any
            DisconnectInternal();

            // 3. Invoke rasdial
            var psi = new ProcessStartInfo
            {
                FileName = "rasdial.exe",
                Arguments = $"\"{ENTRY_NAME}\" vpn vpn /phonebook:\"{_pbkPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                throw new InvalidOperationException("Failed to start rasdial process.");
            }

            string stdout = await proc.StandardOutput.ReadToEndAsync();
            string stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0 || stdout.Contains("Successfully connected") || stdout.Contains("Command completed successfully"))
            {
                lock (_lock)
                {
                    _state = "Connected";
                    _connectedAt = DateTime.UtcNow;
                }
                return (true, $"Connected to {node.CountryName} ({node.HostOrIp}) via {node.Protocol}.");
            }
            else
            {
                string err = !string.IsNullOrWhiteSpace(stderr) ? stderr : stdout;
                lock (_lock)
                {
                    _state = "Failed";
                    _lastError = err.Trim();
                }
                return (false, $"VPN connection failed (Code {proc.ExitCode}): {err.Trim()}");
            }
        }
        catch (Exception ex)
        {
            lock (_lock)
            {
                _state = "Failed";
                _lastError = ex.Message;
            }
            return (false, $"Connection error: {ex.Message}");
        }
    }

    public (bool Success, string Message) Disconnect()
    {
        bool ok = DisconnectInternal();
        lock (_lock)
        {
            _state = "Disconnected";
            _activeServer = null;
            _activeCountry = null;
            _connectedAt = null;
        }
        return (ok, "VPN tunnel disconnected.");
    }

    private bool DisconnectInternal()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "rasdial.exe",
                Arguments = $"\"{ENTRY_NAME}\" /disconnect",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void GeneratePhonebook(string pbkPath, VpnRelayNode node)
    {
        string dir = Path.GetDirectoryName(pbkPath)!;
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        bool isL2tp = string.Equals(node.Protocol, "L2TP", StringComparison.OrdinalIgnoreCase);
        string port = isL2tp ? "VPN2-0" : "VPN1-0";
        string device = isL2tp ? "WAN Miniport (L2TP)" : "WAN Miniport (SSTP)";
        string vpnStrategy = isL2tp ? "2" : "5";

        var sb = new StringBuilder();
        sb.AppendLine($"[{ENTRY_NAME}]");
        sb.AppendLine("Encoding=1");
        sb.AppendLine("PBVersion=6");
        sb.AppendLine("Type=2");
        sb.AppendLine("AutoLogon=0");
        sb.AppendLine("UseRasCredentials=1");
        sb.AppendLine($"VpnStrategy={vpnStrategy}");
        sb.AppendLine("DataEncryption=8");
        sb.AppendLine("SwCompression=0");
        sb.AppendLine("NegotiateMultilinkAlways=0");
        sb.AppendLine("SkipDoubleDialDialog=1");
        sb.AppendLine($"PreferredPort={port}");
        sb.AppendLine($"PreferredDevice={device}");
        sb.AppendLine($"PhoneNumber={node.HostOrIp}");
        sb.AppendLine("PreviewUserPw=0");
        sb.AppendLine("ShowDialingProgress=0");
        sb.AppendLine("AuthenticateServer=0");

        File.WriteAllText(pbkPath, sb.ToString(), Encoding.Default);
    }
}
