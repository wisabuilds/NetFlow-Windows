using System.Diagnostics;
using System.Text.Json;
using NetFlow.Core.Models;
using NetFlow.Core.Storage;
using NetFlow.Core.Telemetry;
using Xunit;

namespace NetFlow.Tests;

public class GeoIpTests : IDisposable
{
    private readonly string _testDbPath;
    private readonly GeoIpDatabase _db;
    private readonly GeoIpService _service;

    public GeoIpTests()
    {
        _testDbPath = Path.Combine(Path.GetTempPath(), $"netflow_geoip_test_{Guid.NewGuid():N}.db");
        _db = new GeoIpDatabase(_testDbPath);
        _service = new GeoIpService(_db);
    }

    public void Dispose()
    {
        _db.Dispose();
        try
        {
            if (File.Exists(_testDbPath)) File.Delete(_testDbPath);
        }
        catch { }
    }

    #region 1. Local and LAN Resolution

    [Theory]
    [InlineData("127.0.0.1", "LO", "Loopback", "🏠", true)]
    [InlineData("::1", "LO", "Loopback", "🏠", true)]
    [InlineData("0.0.0.0", "LO", "Loopback", "🏠", true)]
    public void Local_Loopback_ResolvesOfflineImmediately(string ip, string expectedCc, string expectedName, string expectedFlag, bool expectedLocal)
    {
        var result = _service.Resolve(ip);

        Assert.Equal(expectedCc, result.CountryCode);
        Assert.Equal(expectedName, result.CountryName);
        Assert.Equal(expectedFlag, result.FlagEmoji);
        Assert.Equal(expectedLocal, result.IsLocal);
        Assert.Null(result.Asn);
        Assert.Null(result.AsOrg);
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("10.254.254.1")]
    [InlineData("172.16.0.1")]
    [InlineData("172.24.5.10")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("192.168.100.50")]
    [InlineData("169.254.1.1")]
    [InlineData("169.254.10.20")]
    public void Private_LAN_Ranges_ResolveAsLocalWithHouseFlag(string lanIp)
    {
        var result = _service.Resolve(lanIp);

        Assert.Equal("LAN", result.CountryCode);
        Assert.Equal("Local Area Network", result.CountryName);
        Assert.Equal("🏠", result.FlagEmoji);
        Assert.True(result.IsLocal);
        Assert.Null(result.Asn);
        Assert.Null(result.AsOrg);
    }

    #endregion

    #region 2. Cloud and Autonomous System (ASN) Resolution

    [Theory]
    [InlineData("1.1.1.1", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc.")]
    [InlineData("1.0.0.1", "US", "United States", "🇺🇸", 13335, "Cloudflare, Inc.")]
    public void Cloudflare_Resolves_Accurately(string ip, string cc, string name, string flag, int asn, string org)
    {
        var result = _service.Resolve(ip);

        Assert.Equal(cc, result.CountryCode);
        Assert.Equal(name, result.CountryName);
        Assert.Equal(flag, result.FlagEmoji);
        Assert.Equal(asn, result.Asn);
        Assert.Equal(org, result.AsOrg);
        Assert.False(result.IsLocal);
    }

    [Theory]
    [InlineData("8.8.8.8", "US", "United States", "🇺🇸", 15169, "Google LLC")]
    [InlineData("8.8.4.4", "US", "United States", "🇺🇸", 15169, "Google LLC")]
    public void Google_Resolves_Accurately(string ip, string cc, string name, string flag, int asn, string org)
    {
        var result = _service.Resolve(ip);

        Assert.Equal(cc, result.CountryCode);
        Assert.Equal(name, result.CountryName);
        Assert.Equal(flag, result.FlagEmoji);
        Assert.Equal(asn, result.Asn);
        Assert.Equal(org, result.AsOrg);
        Assert.False(result.IsLocal);
    }

    [Fact]
    public void Microsoft_Resolves_Accurately()
    {
        var result = _service.Resolve("13.107.4.52");

        Assert.Equal("US", result.CountryCode);
        Assert.Equal("United States", result.CountryName);
        Assert.Equal("🇺🇸", result.FlagEmoji);
        Assert.Equal(8075, result.Asn);
        Assert.Equal("Microsoft Corporation", result.AsOrg);
        Assert.False(result.IsLocal);
    }

    [Fact]
    public void GlobalLayer_Bulletproof_ASN49453_Resolves_Accurately()
    {
        var result = _service.Resolve("185.190.140.2");

        Assert.Equal("NL", result.CountryCode);
        Assert.Equal("Netherlands", result.CountryName);
        Assert.Equal("🇳🇱", result.FlagEmoji);
        Assert.Equal(49453, result.Asn);
        Assert.Equal("Global Layer B.V.", result.AsOrg);
        Assert.False(result.IsLocal);
    }

    [Fact]
    public void Major_Hosting_Providers_Resolve_Correctly()
    {
        // Hetzner Germany
        var hetzner = _service.Resolve("78.46.10.20");
        Assert.Equal("DE", hetzner.CountryCode);
        Assert.Equal(24940, hetzner.Asn);
        Assert.Equal("Hetzner Online GmbH", hetzner.AsOrg);

        // OVH France
        var ovh = _service.Resolve("51.254.10.20");
        Assert.Equal("FR", ovh.CountryCode);
        Assert.Equal(16276, ovh.Asn);
        Assert.Equal("OVH SAS", ovh.AsOrg);

        // Quad9 Switzerland
        var quad9 = _service.Resolve("9.9.9.9");
        Assert.Equal("CH", quad9.CountryCode);
        Assert.Equal(19281, quad9.Asn);
        Assert.Equal("Quad9", quad9.AsOrg);
    }

    #endregion

    #region 3. Integer Range Mapping Math

    [Fact]
    public void IpToUInt32_Calculates_EndianIndependent_Integers()
    {
        Assert.Equal(0u, GeoIpDatabase.IpToUInt32("0.0.0.0"));
        Assert.Equal(0xFFFFFFFFu, GeoIpDatabase.IpToUInt32("255.255.255.255"));
        Assert.Equal(16843009u, GeoIpDatabase.IpToUInt32("1.1.1.1"));
        Assert.Equal(2130706433u, GeoIpDatabase.IpToUInt32("127.0.0.1"));
        Assert.Equal(0x08080808u, GeoIpDatabase.IpToUInt32("8.8.8.8"));
    }

    [Fact]
    public void UInt32ToIp_Roundtrips_Correctly()
    {
        string ip = "192.168.1.1";
        uint num = GeoIpDatabase.IpToUInt32(ip);
        string roundtrip = GeoIpDatabase.UInt32ToIp(num);
        Assert.Equal(ip, roundtrip);
    }

    [Fact]
    public void ParseCidr_Calculates_Exact_Start_And_End_Boundaries()
    {
        var (start24, end24) = GeoIpDatabase.ParseCidr("192.168.1.0/24");
        Assert.Equal(GeoIpDatabase.IpToUInt32("192.168.1.0"), start24);
        Assert.Equal(GeoIpDatabase.IpToUInt32("192.168.1.255"), end24);

        var (start16, end16) = GeoIpDatabase.ParseCidr("10.0.0.0/16");
        Assert.Equal(GeoIpDatabase.IpToUInt32("10.0.0.0"), start16);
        Assert.Equal(GeoIpDatabase.IpToUInt32("10.0.255.255"), end16);

        var (start32, end32) = GeoIpDatabase.ParseCidr("1.1.1.1/32");
        Assert.Equal(GeoIpDatabase.IpToUInt32("1.1.1.1"), start32);
        Assert.Equal(GeoIpDatabase.IpToUInt32("1.1.1.1"), end32);
    }

    [Fact]
    public void CountryCodeToFlag_Produces_Valid_Unicode_Emoji()
    {
        Assert.Equal("🇺🇸", GeoIpDatabase.CountryCodeToFlag("US"));
        Assert.Equal("🇩🇪", GeoIpDatabase.CountryCodeToFlag("DE"));
        Assert.Equal("🇬🇧", GeoIpDatabase.CountryCodeToFlag("GB"));
        Assert.Equal("🇫🇷", GeoIpDatabase.CountryCodeToFlag("FR"));
        Assert.Equal("🇳🇱", GeoIpDatabase.CountryCodeToFlag("NL"));
        Assert.Equal("🇯🇵", GeoIpDatabase.CountryCodeToFlag("JP"));
        Assert.Equal("🇨🇭", GeoIpDatabase.CountryCodeToFlag("CH"));
        Assert.Equal("🏠", GeoIpDatabase.CountryCodeToFlag("LO"));
        Assert.Equal("🏠", GeoIpDatabase.CountryCodeToFlag("LAN"));
        Assert.Equal("🌐", GeoIpDatabase.CountryCodeToFlag("ZZ"));
        Assert.Equal("🌐", GeoIpDatabase.CountryCodeToFlag(null));
        Assert.Equal("🌐", GeoIpDatabase.CountryCodeToFlag(""));
    }

    #endregion

    #region 4. In-Memory Cache Performance

    [Fact]
    public void Cache_Provides_ZeroLatency_RepeatedLookups()
    {
        string testIp = "1.1.1.1";
        // Warm cache
        _service.Resolve(testIp);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 10000; i++)
        {
            var res = _service.Resolve(testIp);
            Assert.Equal("US", res.CountryCode);
        }
        sw.Stop();

        // 10,000 in-memory lookups should complete in well under 50ms
        Assert.True(sw.ElapsedMilliseconds < 50, $"10,000 cache lookups took {sw.ElapsedMilliseconds}ms, expected < 50ms");
    }

    [Fact]
    public void Cache_Is_ThreadSafe_Under_Concurrent_Load()
    {
        _service.ClearCache();

        Parallel.For(0, 1000, i =>
        {
            string ip = (i % 2 == 0) ? "1.1.1.1" : "8.8.8.8";
            var res = _service.Resolve(ip);
            Assert.NotNull(res);
            Assert.Equal("US", res.CountryCode);
        });

        Assert.True(_service.CacheCount >= 2);
    }

    #endregion

    #region 5. Zero Network Dependency Validation

    [Fact]
    public void ZeroNetworkDependency_Resolves_Offline_Instantly()
    {
        var sw = Stopwatch.StartNew();
        var res1 = _service.Resolve("1.1.1.1");
        var res2 = _service.Resolve("8.8.8.8");
        var res3 = _service.Resolve("185.190.140.2");
        sw.Stop();

        // All 3 offline lookups without network calls must complete in < 20ms
        Assert.True(sw.ElapsedMilliseconds < 20, $"Offline resolution took {sw.ElapsedMilliseconds}ms, expected < 20ms");
        Assert.Equal(13335, res1.Asn);
        Assert.Equal(15169, res2.Asn);
        Assert.Equal(49453, res3.Asn);
    }

    #endregion

    #region 6. Fallback for Unrecognized / Malformed Inputs

    [Theory]
    [InlineData("198.51.100.99")] // TEST-NET-2 unassigned public IP
    [InlineData("192.0.2.1")]     // TEST-NET-1 unassigned public IP
    public void Unrecognized_PublicIP_ReturnsSafeFallback(string ip)
    {
        var result = _service.Resolve(ip);

        Assert.NotNull(result);
        Assert.Equal("ZZ", result.CountryCode);
        Assert.Equal("Unknown", result.CountryName);
        Assert.Equal("🌐", result.FlagEmoji);
        Assert.Null(result.Asn);
        Assert.False(result.IsLocal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("invalid_ip")]
    [InlineData("999.999.999.999")]
    public void Malformed_Or_Empty_Input_ReturnsSafeFallbackWithoutThrowing(string? malformed)
    {
        var result = _service.Resolve(malformed);

        Assert.NotNull(result);
        Assert.Equal("XX", result.CountryCode);
        Assert.Equal("Unknown", result.CountryName);
        Assert.Equal("🌐", result.FlagEmoji);
        Assert.False(result.IsLocal);
    }

    #endregion

    #region 7. SocketInfo and Telemetry Enrichment

    [Fact]
    public void Enrich_Populates_SocketInfo_Fields_Accurately()
    {
        var socket = new SocketInfo
        {
            Protocol = "TCP",
            LocalIp = "192.168.1.10",
            LocalPort = 54321,
            RemoteIp = "1.1.1.1",
            RemotePort = 443,
            State = "ESTABLISHED"
        };

        _service.Enrich(socket);

        Assert.Equal("US", socket.CountryCode);
        Assert.Equal("United States", socket.CountryName);
        Assert.Equal("🇺🇸", socket.CountryFlag);
        Assert.Equal("🇺🇸", socket.Flag);
        Assert.Equal(13335, socket.Asn);
        Assert.Equal("Cloudflare, Inc.", socket.AsOrg);
    }

    [Fact]
    public void GeoIpInfo_Serializes_To_Contract_Json()
    {
        var info = new GeoIpInfo("US", "United States", "🇺🇸", 13335, "Cloudflare, Inc.", false, "1.1.1.1");
        string json = JsonSerializer.Serialize(info);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("1.1.1.1", root.GetProperty("ip").GetString());
        Assert.Equal("US", root.GetProperty("country_code").GetString());
        Assert.Equal("United States", root.GetProperty("country_name").GetString());
        Assert.Equal("🇺🇸", root.GetProperty("flag").GetString());
        Assert.Equal(13335, root.GetProperty("asn").GetInt32());
        Assert.Equal("Cloudflare, Inc.", root.GetProperty("as_org").GetString());
        Assert.False(root.GetProperty("is_local").GetBoolean());
    }

    [Fact]
    public void Database_Persists_And_Queries_SQLite_Table()
    {
        int count = _db.GetCount();
        Assert.True(count > 50, $"Database should have > 50 seeded ranges, got {count}");

        uint ipNum = GeoIpDatabase.IpToUInt32("8.8.8.8");
        var result = _db.QueryRange(ipNum);

        Assert.NotNull(result);
        Assert.Equal("US", result.CountryCode);
        Assert.Equal(15169, result.Asn);
    }

    #endregion
}
