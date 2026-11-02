using System.Text.Json.Serialization;

namespace NetFlow.Core.Models;

public class GeoIpInfo
{
    [JsonPropertyName("ip")]
    public string? Ip { get; set; }

    [JsonPropertyName("country_code")]
    public string CountryCode { get; set; } = "XX";

    [JsonPropertyName("country_name")]
    public string CountryName { get; set; } = "Unknown";

    [JsonPropertyName("flag")]
    public string FlagEmoji { get; set; } = "🌐";

    [JsonPropertyName("flag_emoji")]
    public string Flag => FlagEmoji;

    [JsonPropertyName("country_flag")]
    public string CountryFlag => FlagEmoji;

    [JsonPropertyName("asn")]
    public int? Asn { get; set; }

    [JsonPropertyName("as_org")]
    public string? AsOrg { get; set; }

    [JsonPropertyName("is_local")]
    public bool IsLocal { get; set; }

    public GeoIpInfo()
    {
    }

    public GeoIpInfo(
        string countryCode,
        string countryName,
        string flagEmoji,
        int? asn = null,
        string? asOrg = null,
        bool isLocal = false,
        string? ip = null)
    {
        CountryCode = countryCode;
        CountryName = countryName;
        FlagEmoji = flagEmoji;
        Asn = asn;
        AsOrg = asOrg;
        IsLocal = isLocal;
        Ip = ip;
    }
}
