using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace NetFlow.Core.Diagnostics;

public class NetworkDiagnostics
{
    private static readonly Dictionary<string, string> CommonOuiVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["b8:27:eb"] = "Raspberry Pi",
        ["dc:a6:32"] = "Raspberry Pi",
        ["e4:5f:01"] = "Raspberry Pi",
        ["f0:18:98"] = "Apple",
        ["a4:83:e7"] = "Apple",
        ["3c:22:fb"] = "Apple",
        ["ac:de:48"] = "Apple",
        ["bc:d0:74"] = "Google",
        ["54:60:09"] = "Google",
        ["f4:f5:e8"] = "Google",
        ["d4:6a:6a"] = "Samsung",
        ["8c:79:67"] = "Samsung",
        ["00:1a:2b"] = "Cisco",
        ["00:0c:29"] = "VMware",
        ["52:54:00"] = "QEMU/KVM",
        ["08:00:27"] = "VirtualBox",
        ["50:c7:bf"] = "TP-Link",
        ["ec:08:6b"] = "TP-Link",
        ["00:11:32"] = "Synology",
        ["b0:4e:26"] = "Intel",
    };

    public static string LookupMacVendor(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return "Unknown Vendor";
        var cleaned = mac.ToLowerInvariant().Replace("-", ":");
        var parts = cleaned.Split(':');
        if (parts.Length >= 3)
        {
            var prefix = $"{parts[0]}:{parts[1]}:{parts[2]}";
            if (CommonOuiVendors.TryGetValue(prefix, out var vendor))
            {
                return vendor;
            }
        }
        return "Unknown Vendor";
    }

    public static async Task<Dictionary<string, object>> MeasurePingAsync(string target = "1.1.1.1", int count = 3, int timeoutMs = 2000)
    {
        var latencies = new List<long>();
        using var pinger = new Ping();

        try
        {
            for (int i = 0; i < count; i++)
            {
                var reply = await pinger.SendPingAsync(target, timeoutMs);
                if (reply.Status == IPStatus.Success)
                {
                    latencies.Add(reply.RoundtripTime);
                }
                await Task.Delay(100);
            }

            if (latencies.Count > 0)
            {
                double avg = latencies.Average();
                return new Dictionary<string, object>
                {
                    ["success"] = true,
                    ["target"] = target,
                    ["latency_ms"] = Math.Round(avg, 2),
                    ["avg_ms"] = Math.Round(avg, 2),
                    ["min_ms"] = latencies.Min(),
                    ["max_ms"] = latencies.Max(),
                    ["packets_transmitted"] = count,
                    ["packets_received"] = latencies.Count,
                    ["packet_loss_pct"] = Math.Round((1.0 - (double)latencies.Count / count) * 100.0, 1)
                };
            }

            return new Dictionary<string, object>
            {
                ["success"] = false,
                ["target"] = target,
                ["error"] = "Host unreachable (100% packet loss)",
                ["packets_transmitted"] = count,
                ["packets_received"] = 0,
                ["packet_loss_pct"] = 100.0
            };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object>
            {
                ["success"] = false,
                ["target"] = target,
                ["error"] = ex.Message
            };
        }
    }

    public static async Task<Dictionary<string, object>> RunSpeedTestAsync(int testSizeMb = 5, int timeoutSec = 20)
    {
        int bytesToFetch = testSizeMb * 1024 * 1024;
        string url = $"https://speed.cloudflare.com/__down?bytes={bytesToFetch}";

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSec) };
        var sw = Stopwatch.StartNew();

        try
        {
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            using var stream = await response.Content.ReadAsStreamAsync();
            byte[] buffer = new byte[65536];
            long totalRead = 0;
            int read;

            while ((read = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                totalRead += read;
            }

            sw.Stop();
            double duration = Math.Max(0.05, sw.Elapsed.TotalSeconds);
            double speedBps = totalRead / duration;
            double speedMbps = Math.Round((speedBps * 8.0) / (1024 * 1024), 2);
            double speedMbytes = Math.Round(speedBps / (1024 * 1024), 2);

            return new Dictionary<string, object>
            {
                ["success"] = true,
                ["speed_mbps"] = speedMbps,
                ["speed_mbytes_sec"] = speedMbytes,
                ["bytes_transferred"] = totalRead,
                ["duration_seconds"] = Math.Round(duration, 2),
                ["target_size_mb"] = testSizeMb
            };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object>
            {
                ["success"] = false,
                ["error"] = ex.Message
            };
        }
    }

    public static List<Dictionary<string, object>> GetLocalSubnetDevices()
    {
        var devices = new List<Dictionary<string, object>>();

        try
        {
            // On Windows, parse 'arp -a'
            var psi = new ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                var regex = new Regex(@"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})");
                foreach (Match match in regex.Matches(output))
                {
                    string ip = match.Groups[1].Value;
                    string mac = match.Groups[2].Value.Replace("-", ":").ToLowerInvariant();

                    if (ip.EndsWith(".255") || mac == "ff:ff:ff:ff:ff:ff") continue;

                    string vendor = LookupMacVendor(mac);
                    devices.Add(new Dictionary<string, object>
                    {
                        ["ip"] = ip,
                        ["mac"] = mac,
                        ["vendor"] = vendor,
                        ["hostname"] = ip
                    });
                }
            }
        }
        catch
        {
            // Ignore error
        }

        return devices;
    }
}
