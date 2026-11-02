using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using NetFlow.Core.Models;
using NetFlow.Core.Services;
using NetFlow.Core.Storage;

namespace NetFlow.Core.Telemetry;

public class GeoIpService
{
    private static readonly Lazy<GeoIpService> _lazyInstance = new(() => new GeoIpService());
    public static GeoIpService Instance => _lazyInstance.Value;

    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(5) };

    private readonly ConcurrentDictionary<string, GeoIpInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _inFlightLookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly GeoIpDatabase? _database;
    private readonly GeoIpRangeEntry[] _sortedRanges;
    private readonly GeoIpRangeEntryV6[] _sortedRangesV6;

    public GeoIpService(GeoIpDatabase? database = null)
    {
        _database = database;

        // 1. Load IPv4 ranges from database or fall back to curated dataset
        List<GeoIpRangeEntry> ranges;
        if (_database != null)
        {
            ranges = _database.GetAllRanges();
            if (ranges.Count == 0)
            {
                ranges = GeoIpDatabase.GetCuratedRanges().ToList();
            }
        }
        else
        {
            ranges = GeoIpDatabase.GetCuratedRanges().ToList();
        }

        _sortedRanges = ranges
            .OrderBy(r => r.StartIp)
            .ThenBy(r => r.EndIp - r.StartIp)
            .ToArray();

        // 2. Load IPv6 ranges from database or fall back to curated dataset
        List<GeoIpRangeEntryV6> rangesV6;
        if (_database != null)
        {
            rangesV6 = _database.GetAllRangesV6();
            if (rangesV6.Count == 0)
            {
                rangesV6 = GeoIpDatabase.GetCuratedRangesV6().ToList();
            }
        }
        else
        {
            rangesV6 = GeoIpDatabase.GetCuratedRangesV6().ToList();
        }

        _sortedRangesV6 = rangesV6
            .OrderBy(r => r.StartIp, StringComparer.Ordinal)
            .ThenBy(r => r.EndIp, StringComparer.Ordinal)
            .ToArray();
    }

    public int CacheCount => _cache.Count;
    public bool EnableOnlineLookupFallback { get; set; } = false;

    public void ClearCache()
    {
        _cache.Clear();
        _inFlightLookups.Clear();
    }

    public GeoIpInfo Resolve(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return new GeoIpInfo("XX", "Unknown", "🌐", null, null, isLocal: false, ip: ip);
        }

        ip = ip.Trim();

        // 1. Check in-memory fast cache
        if (_cache.TryGetValue(ip, out var cached))
        {
            return cached;
        }

        // 2. Validate IP parsing
        if (!IPAddress.TryParse(ip, out var parsedIp))
        {
            var fallback = new GeoIpInfo("XX", "Unknown", "🌐", null, null, isLocal: false, ip: ip);
            _cache[ip] = fallback;
            return fallback;
        }

        // 3. Fast check for Loopback / Localhost
        if (IPAddress.IsLoopback(parsedIp) || ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0")
        {
            var loopback = new GeoIpInfo("LO", "Loopback", "🏠", null, null, isLocal: true, ip: ip);
            _cache[ip] = loopback;
            return loopback;
        }

        // 4. Fast check for LAN / Private RFC1918 / Link-Local ranges / ULA
        if (DnsResolver.IsLanOrLocal(ip) || IsPrivateOrLan(parsedIp))
        {
            var lan = new GeoIpInfo("LAN", "Local Area Network", "🏠", null, null, isLocal: true, ip: ip);
            _cache[ip] = lan;
            return lan;
        }

        // 5. WAN IPv4 Resolution against interval index
        if (parsedIp.AddressFamily == AddressFamily.InterNetwork)
        {
            uint ipNum = GeoIpDatabase.IpToUInt32(ip);

            GeoIpRangeEntry? bestMatch = null;
            long bestWidth = long.MaxValue;

            for (int i = 0; i < _sortedRanges.Length; i++)
            {
                var r = _sortedRanges[i];
                if (r.StartIp <= ipNum && r.EndIp >= ipNum)
                {
                    long width = (long)r.EndIp - r.StartIp;
                    if (width < bestWidth)
                    {
                        bestWidth = width;
                        bestMatch = r;
                    }
                }
            }

            if (bestMatch != null)
            {
                var resolved = new GeoIpInfo(
                    bestMatch.CountryCode,
                    bestMatch.CountryName,
                    bestMatch.Flag,
                    bestMatch.Asn,
                    bestMatch.AsOrg,
                    isLocal: false,
                    ip: ip);

                _cache[ip] = resolved;
                return resolved;
            }

            if (_database != null)
            {
                var dbResult = _database.QueryRange(ipNum);
                if (dbResult != null)
                {
                    dbResult.Ip = ip;
                    _cache[ip] = dbResult;
                    return dbResult;
                }
            }
        }
        // 6. WAN IPv6 Resolution against 128-bit hex index
        else if (parsedIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            string hex = GeoIpDatabase.IpV6ToHex(parsedIp);

            GeoIpRangeEntryV6? bestMatchV6 = null;
            for (int i = 0; i < _sortedRangesV6.Length; i++)
            {
                var r = _sortedRangesV6[i];
                if (string.CompareOrdinal(hex, r.StartIp) >= 0 && string.CompareOrdinal(hex, r.EndIp) <= 0)
                {
                    if (bestMatchV6 == null ||
                        string.CompareOrdinal(r.StartIp, bestMatchV6.StartIp) > 0 ||
                        (string.CompareOrdinal(r.StartIp, bestMatchV6.StartIp) == 0 && string.CompareOrdinal(r.EndIp, bestMatchV6.EndIp) < 0))
                    {
                        bestMatchV6 = r;
                    }
                }
            }

            if (bestMatchV6 != null)
            {
                var resolvedV6 = new GeoIpInfo(
                    bestMatchV6.CountryCode,
                    bestMatchV6.CountryName,
                    bestMatchV6.Flag,
                    bestMatchV6.Asn,
                    bestMatchV6.AsOrg,
                    isLocal: false,
                    ip: ip);

                _cache[ip] = resolvedV6;
                return resolvedV6;
            }

            if (_database != null)
            {
                var dbResultV6 = _database.QueryRangeV6(parsedIp);
                if (dbResultV6 != null)
                {
                    dbResultV6.Ip = ip;
                    _cache[ip] = dbResultV6;
                    return dbResultV6;
                }
            }
        }

        // 7. Safe fallback for unrecognized public IPs with optional online resolution queue
        var unknownPublic = new GeoIpInfo("ZZ", "Unknown", "🌐", null, null, isLocal: false, ip: ip);
        _cache[ip] = unknownPublic;

        // Only queue online lookup if explicitly enabled (strictly offline by default)
        if (EnableOnlineLookupFallback)
        {
            QueueOnlineLookup(ip);
        }

        return unknownPublic;
    }

    public async Task<GeoIpInfo> ResolveAsync(string? ip, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return new GeoIpInfo("XX", "Unknown", "🌐", null, null, isLocal: false, ip: ip);
        }

        // Fast synchronous check
        var info = Resolve(ip);
        if (info.CountryCode is not "ZZ" || !EnableOnlineLookupFallback)
        {
            return info;
        }

        // Attempt online lookup for public WAN IP
        try
        {
            string url = $"https://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetFlow/2.0");

            using var resp = await _httpClient.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                string json = await resp.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("status", out var statusEl) && statusEl.GetString() == "success")
                {
                    string cc = root.TryGetProperty("countryCode", out var ccEl) ? ccEl.GetString() ?? "ZZ" : "ZZ";
                    string country = root.TryGetProperty("country", out var cEl) ? cEl.GetString() ?? "Unknown" : "Unknown";
                    string asString = root.TryGetProperty("as", out var asEl) ? asEl.GetString() ?? "" : "";
                    string org = root.TryGetProperty("org", out var oEl) ? oEl.GetString() ?? "" : "";

                    int? asn = null;
                    if (!string.IsNullOrEmpty(asString) && asString.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                    {
                        var spaceIdx = asString.IndexOf(' ');
                        string asnNum = spaceIdx > 2 ? asString.Substring(2, spaceIdx - 2) : asString.Substring(2);
                        if (int.TryParse(asnNum, out int parsedAsn))
                        {
                            asn = parsedAsn;
                        }
                    }

                    string flag = GeoIpDatabase.CountryCodeToFlag(cc);
                    var onlineResolved = new GeoIpInfo(cc, country, flag, asn, string.IsNullOrEmpty(org) ? asString : org, isLocal: false, ip: ip);
                    _cache[ip] = onlineResolved;
                    return onlineResolved;
                }
            }
        }
        catch { }

        return info;
    }

    private void QueueOnlineLookup(string ip)
    {
        if (_inFlightLookups.TryAdd(ip, 0))
        {
            Task.Run(async () =>
            {
                try
                {
                    await ResolveAsync(ip);
                }
                catch { }
                finally
                {
                    _inFlightLookups.TryRemove(ip, out _);
                }
            });
        }
    }

    public void Enrich(SocketInfo socket)
    {
        if (socket == null || string.IsNullOrWhiteSpace(socket.RemoteIp)) return;

        var geo = Resolve(socket.RemoteIp);
        socket.CountryCode = geo.CountryCode;
        socket.CountryName = geo.CountryName;
        socket.CountryFlag = geo.FlagEmoji;
        socket.Asn = geo.Asn;
        socket.AsOrg = geo.AsOrg;
    }

    public void EnrichList(IEnumerable<SocketInfo> sockets)
    {
        foreach (var s in sockets)
        {
            Enrich(s);
        }
    }

    private static bool IsPrivateOrLan(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (Link Local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 100.64.0.0/10 (Carrier-Grade NAT)
            if (bytes[0] == 100 && (bytes[1] & 0xC0) == 64) return true;
            // 255.255.255.255 (Broadcast)
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return true;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal)
                return true;
        }

        return false;
    }
}
