using System.Text.Json.Serialization;

namespace NetFlow.Core.Models;

public class SocketInfo
{
    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "TCP";

    [JsonPropertyName("local_ip")]
    public string LocalIp { get; set; } = "";

    [JsonPropertyName("local_port")]
    public int LocalPort { get; set; }

    [JsonPropertyName("local")]
    public string Local => $"{LocalIp}:{LocalPort}";

    [JsonPropertyName("remote_ip")]
    public string RemoteIp { get; set; } = "";

    [JsonPropertyName("remote_port")]
    public int RemotePort { get; set; }

    [JsonPropertyName("remote")]
    public string Remote => $"{RemoteIp}:{RemotePort}";

    [JsonPropertyName("remote_hostname")]
    public string? RemoteHostname => ResolvedHostname;

    [JsonPropertyName("state")]
    public string State { get; set; } = "";

    [JsonPropertyName("pid")]
    public int? Pid { get; set; }

    [JsonPropertyName("process_name")]
    public string? ProcessName { get; set; }

    [JsonPropertyName("cmdline")]
    public string? Cmdline { get; set; }

    [JsonPropertyName("resolved_hostname")]
    public string? ResolvedHostname { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("policy")]
    public string Policy { get; set; } = "allow";

    // Milestone 2 GeoIP & ASN Fields
    [JsonPropertyName("country_code")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("country_name")]
    public string? CountryName { get; set; }

    [JsonPropertyName("country_flag")]
    public string? CountryFlag { get; set; }

    [JsonPropertyName("flag")]
    public string? Flag => CountryFlag;

    [JsonPropertyName("asn")]
    public int? Asn { get; set; }

    [JsonPropertyName("as_org")]
    public string? AsOrg { get; set; }

    [JsonPropertyName("threat")]
    public ThreatAssessment? Threat { get; set; }
}
